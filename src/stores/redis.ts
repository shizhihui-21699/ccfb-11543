/**
 * Redis 协议会话存储。
 *
 * 键布局：
 *   session:<id>            -> 哈希表（SessionRecord 的 JSON 字段 + 内部 expiresAt）
 *   user_sessions:<userId>  -> ZSET，member=sessionId，score=createdAt（天然按创建时间排序）
 *
 * 为什么 ZSET 的 score 用 createdAt：并发上限淘汰“最早创建的会话”时直接 ZRANGE 0 取第一个，
 * 踢人用 ZRANGE 拿全量成员后 pipeline 批量 DEL，语义和内存版完全对齐。
 *
 * 客户端只要求满足 RedisLike 这一小撮命令 —— ioredis 原生满足；
 * 测试里的 FakeRedis 实现同样的 RESP 语义，因此本文件不 import 任何具体客户端，
 * 换 node-redis 等其它库时只需写一层薄适配。
 */
import type { SessionRecord, SessionStore } from '../types.js';

/** 本存储实际用到的 Redis 命令子集（ioredis 的签名风格） */
export interface RedisLike {
  hset(key: string, field: string, value: string): Promise<number>;
  hgetall(key: string): Promise<Record<string, string>>;
  del(...keys: string[]): Promise<number>;
  expire(key: string, seconds: number): Promise<number>;
  zadd(key: string, score: number, member: string): Promise<number>;
  zrange(key: string, start: number, stop: number): Promise<string[]>;
  zrem(key: string, ...members: string[]): Promise<number>;
  /** pipeline：各命令入队后一次性 exec，返回与入队顺序一致的结果 */
  pipeline(): RedisPipeline;
  ping(): Promise<string>;
  quit?(): Promise<string>;
}

export interface RedisPipeline {
  hset(key: string, field: string, value: string): this;
  del(...keys: string[]): this;
  expire(key: string, seconds: number): this;
  zadd(key: string, score: number, member: string): this;
  zrem(key: string, ...members: string[]): this;
  exec(): Promise<Array<[Error | null, unknown]>>;
}

export interface RedisStoreOptions {
  client: RedisLike;
  /** 键前缀，多服务共库时做命名空间隔离 */
  keyPrefix?: string;
}

const SESSION_PREFIX = 'session:';
const INDEX_PREFIX = 'user_sessions:';

export class RedisSessionStore implements SessionStore {
  private readonly client: RedisLike;
  private readonly prefix: string;

  constructor(opts: RedisStoreOptions) {
    this.client = opts.client;
    this.prefix = opts.keyPrefix ?? 'sessmw:';
  }

  private sessionKey(id: string): string {
    return `${this.prefix}${SESSION_PREFIX}${id}`;
  }

  private indexKey(userId: string): string {
    return `${this.prefix}${INDEX_PREFIX}${userId}`;
  }

  async put(record: SessionRecord, ttlSeconds: number): Promise<void> {
    const pipe = this.client.pipeline();
    const sk = this.sessionKey(record.id);
    // 整条 record 序列化进一个 hash field，避免字段级类型漂移；读取处统一 JSON.parse
    pipe.hset(sk, 'record', JSON.stringify(record));
    pipe.expire(sk, Math.max(1, Math.ceil(ttlSeconds)));
    if (record.userId !== null) {
      pipe.zadd(this.indexKey(record.userId), record.createdAt, record.id);
    }
    await pipe.exec();
  }

  async get(id: string): Promise<SessionRecord | null> {
    const rows = await this.client.hgetall(this.sessionKey(id));
    const raw = rows.record;
    if (!raw) return null;
    return JSON.parse(raw) as SessionRecord;
  }

  async destroy(id: string): Promise<void> {
    // 先读 record 拿 userId 才能清理索引；会话不存在则无事发生
    const record = await this.get(id);
    const pipe = this.client.pipeline();
    pipe.del(this.sessionKey(id));
    if (record?.userId !== null && record?.userId !== undefined) {
      pipe.zrem(this.indexKey(record.userId), id);
    }
    await pipe.exec();
  }

  async touch(id: string, lastSeenAt: number, ttlSeconds: number): Promise<void> {
    const record = await this.get(id);
    if (!record) return;
    record.lastSeenAt = lastSeenAt;
    const pipe = this.client.pipeline();
    pipe.hset(this.sessionKey(id), 'record', JSON.stringify(record));
    pipe.expire(this.sessionKey(id), Math.max(1, Math.ceil(ttlSeconds)));
    await pipe.exec();
  }

  async listUserSessions(userId: string): Promise<SessionRecord[]> {
    const ids = await this.client.zrange(this.indexKey(userId), 0, -1);
    if (ids.length === 0) return [];
    // 单账号会话数受 maxSessionsPerUser 约束（默认 5），并发逐个 get 成本可忽略
    const records = await Promise.all(ids.map((id) => this.get(id)));
    const live = records.filter((r): r is SessionRecord => r !== null);
    // 清理 ZSET 里已被 TTL 淘汰的脏成员
    const stale = ids.filter((id) => !live.some((r) => r.id === id));
    if (stale.length > 0) {
      await this.client.zrem(this.indexKey(userId), ...stale);
    }
    live.sort((a, b) => a.createdAt - b.createdAt);
    return live;
  }

  async kickUser(userId: string, exceptId?: string): Promise<string[]> {
    const ids = await this.client.zrange(this.indexKey(userId), 0, -1);
    const targets = ids.filter((id) => id !== exceptId);
    if (targets.length === 0) return [];
    const pipe = this.client.pipeline();
    for (const id of targets) pipe.del(this.sessionKey(id));
    pipe.zrem(this.indexKey(userId), ...targets);
    await pipe.exec();
    return targets;
  }

  async ping(): Promise<void> {
    await this.client.ping();
  }

  async close(): Promise<void> {
    await this.client.quit?.();
  }
}
