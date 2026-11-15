/**
 * 内存版 Redis 语义替身：实现 RedisSessionStore 依赖的命令子集，
 * 行为对齐真实 Redis 的关键语义（惰性 TTL、ZSET 按 score 排序、pipeline 原子批量返回）。
 *
 * 用途：单元/攻击测试离线运行；生产环境把 new Redis()（ioredis）传给 RedisSessionStore 即可，
 * 两边走的是同一个 RedisLike 接口。
 */
import type { RedisLike, RedisPipeline } from '../../src/stores/redis.js';

interface KeyState {
  type: 'hash' | 'zset';
  hash?: Map<string, string>;
  zset?: Map<string, number>;
  expiresAt: number | null;
}

export class FakeRedis implements RedisLike {
  private readonly keys = new Map<string, KeyState>();
  private now: () => number;
  private failNext: Error | null = null;

  constructor(opts: { now?: () => number } = {}) {
    this.now = opts.now ?? (() => Date.now());
  }

  /** 测试辅助：让下一条命令失败（模拟网络抖动） */
  injectFailure(err: Error): void {
    this.failNext = err;
  }

  private consumeFailure(): void {
    if (this.failNext) {
      const err = this.failNext;
      this.failNext = null;
      throw err;
    }
  }

  private live(key: string): KeyState | undefined {
    const state = this.keys.get(key);
    if (!state) return undefined;
    if (state.expiresAt !== null && state.expiresAt <= this.now()) {
      this.keys.delete(key);
      return undefined;
    }
    return state;
  }

  async hset(key: string, field: string, value: string): Promise<number> {
    this.consumeFailure();
    let state = this.live(key);
    if (!state) {
      state = { type: 'hash', hash: new Map(), expiresAt: null };
      this.keys.set(key, state);
    }
    const isNew = !state.hash!.has(field);
    state.hash!.set(field, value);
    return isNew ? 1 : 0;
  }

  async hgetall(key: string): Promise<Record<string, string>> {
    this.consumeFailure();
    const state = this.live(key);
    if (!state || state.type !== 'hash') return {};
    return Object.fromEntries(state.hash!);
  }

  async del(...delKeys: string[]): Promise<number> {
    this.consumeFailure();
    let n = 0;
    for (const k of delKeys) {
      if (this.live(k)) {
        this.keys.delete(k);
        n++;
      }
    }
    return n;
  }

  async expire(key: string, seconds: number): Promise<number> {
    this.consumeFailure();
    const state = this.live(key);
    if (!state) return 0;
    state.expiresAt = this.now() + Math.max(1, Math.ceil(seconds)) * 1000;
    return 1;
  }

  async zadd(key: string, score: number, member: string): Promise<number> {
    this.consumeFailure();
    let state = this.live(key);
    if (!state) {
      state = { type: 'zset', zset: new Map(), expiresAt: null };
      this.keys.set(key, state);
    }
    const isNew = !state.zset!.has(member);
    state.zset!.set(member, score);
    return isNew ? 1 : 0;
  }

  async zrange(key: string, start: number, stop: number): Promise<string[]> {
    this.consumeFailure();
    const state = this.live(key);
    if (!state || state.type !== 'zset') return [];
    const ordered = [...state.zset!.entries()]
      .sort((a, b) => (a[1] - b[1]) || a[0].localeCompare(b[0]))
      .map(([member]) => member);
    // Redis 支持负索引
    const len = ordered.length;
    const norm = (i: number) => (i < 0 ? Math.max(0, len + i) : Math.min(len - 1, i));
    const s = norm(start);
    const e = norm(stop);
    if (s > e) return [];
    return ordered.slice(s, e + 1);
  }

  async zrem(key: string, ...members: string[]): Promise<number> {
    this.consumeFailure();
    const state = this.live(key);
    if (!state || state.type !== 'zset') return 0;
    let n = 0;
    for (const m of members) {
      if (state.zset!.delete(m)) n++;
    }
    return n;
  }

  async ping(): Promise<string> {
    this.consumeFailure();
    return 'PONG';
  }

  async quit(): Promise<string> {
    this.keys.clear();
    return 'OK';
  }

  pipeline(): RedisPipeline {
    return new FakePipeline(this);
  }

  /** 测试辅助：当前存活键数量 */
  get keyCount(): number {
    let n = 0;
    for (const k of [...this.keys.keys()]) {
      if (this.live(k)) n++;
    }
    return n;
  }
}

type QueuedCmd =
  | { op: 'hset'; key: string; field: string; value: string }
  | { op: 'del'; keys: string[] }
  | { op: 'expire'; key: string; seconds: number }
  | { op: 'zadd'; key: string; score: number; member: string }
  | { op: 'zrem'; key: string; members: string[] };

class FakePipeline implements RedisPipeline {
  private readonly cmds: QueuedCmd[] = [];
  constructor(private readonly redis: FakeRedis) {}

  hset(key: string, field: string, value: string): this {
    this.cmds.push({ op: 'hset', key, field, value });
    return this;
  }
  del(...keys: string[]): this {
    this.cmds.push({ op: 'del', keys });
    return this;
  }
  expire(key: string, seconds: number): this {
    this.cmds.push({ op: 'expire', key, seconds });
    return this;
  }
  zadd(key: string, score: number, member: string): this {
    this.cmds.push({ op: 'zadd', key, score, member });
    return this;
  }
  zrem(key: string, ...members: string[]): this {
    this.cmds.push({ op: 'zrem', key, members });
    return this;
  }

  async exec(): Promise<Array<[Error | null, unknown]>> {
    // 与真实 pipeline 一致：顺序执行、逐条回报，单条失败不阻断后续
    const out: Array<[Error | null, unknown]> = [];
    for (const cmd of this.cmds) {
      try {
        switch (cmd.op) {
          case 'hset':
            out.push([null, await this.redis.hset(cmd.key, cmd.field, cmd.value)]);
            break;
          case 'del':
            out.push([null, await this.redis.del(...cmd.keys)]);
            break;
          case 'expire':
            out.push([null, await this.redis.expire(cmd.key, cmd.seconds)]);
            break;
          case 'zadd':
            out.push([null, await this.redis.zadd(cmd.key, cmd.score, cmd.member)]);
            break;
          case 'zrem':
            out.push([null, await this.redis.zrem(cmd.key, ...cmd.members)]);
            break;
        }
      } catch (err) {
        out.push([err as Error, null]);
      }
    }
    return out;
  }
}
