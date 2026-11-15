/**
 * 进程内会话存储 —— 单实例部署、测试与演示用。
 *
 * - 主键：sessionId -> { record, expiresAt }
 * - 索引：userId -> Set<sessionId>，集合里允许残留已过期成员，读取时惰性过滤
 * - TTL：get 时惰性淘汰 + 可选的 unref 周期清扫器（不阻止 Node 进程退出）
 */
import type { SessionRecord, SessionStore } from '../types.js';

interface Entry {
  record: SessionRecord;
  expiresAt: number;
}

export interface MemoryStoreOptions {
  /** 清扫周期（毫秒），默认 60s；设 0 关闭清扫器（仍有惰性淘汰） */
  sweepIntervalMs?: number;
  /** 注入时钟（测试用） */
  now?: () => number;
}

export class MemorySessionStore implements SessionStore {
  private readonly sessions = new Map<string, Entry>();
  private readonly userIndex = new Map<string, Set<string>>();
  private readonly now: () => number;
  private readonly timer: NodeJS.Timeout | null = null;

  constructor(opts: MemoryStoreOptions = {}) {
    this.now = opts.now ?? (() => Date.now());
    const interval = opts.sweepIntervalMs ?? 60_000;
    if (interval > 0) {
      this.timer = setInterval(() => this.sweep(), interval);
      // 不阻止事件循环退出
      this.timer.unref?.();
    }
  }

  async put(record: SessionRecord, ttlSeconds: number): Promise<void> {
    const ttlMs = Math.max(0, ttlSeconds) * 1000;
    this.sessions.set(record.id, { record, expiresAt: this.now() + ttlMs });
    if (record.userId !== null) {
      let set = this.userIndex.get(record.userId);
      if (!set) {
        set = new Set();
        this.userIndex.set(record.userId, set);
      }
      set.add(record.id);
    }
  }

  async get(id: string): Promise<SessionRecord | null> {
    const entry = this.sessions.get(id);
    if (!entry) return null;
    if (entry.expiresAt <= this.now()) {
      await this.destroy(id);
      return null;
    }
    return entry.record;
  }

  async destroy(id: string): Promise<void> {
    const entry = this.sessions.get(id);
    this.sessions.delete(id);
    if (entry?.record.userId !== null && entry?.record.userId !== undefined) {
      const set = this.userIndex.get(entry.record.userId);
      if (set) {
        set.delete(id);
        if (set.size === 0) this.userIndex.delete(entry.record.userId);
      }
    }
  }

  async touch(id: string, lastSeenAt: number, ttlSeconds: number): Promise<void> {
    const entry = this.sessions.get(id);
    if (!entry) return;
    // 以新对象替换，杜绝外部继续持有旧引用时的别名突变
    entry.record = { ...entry.record, lastSeenAt };
    entry.expiresAt = lastSeenAt + Math.max(0, ttlSeconds) * 1000;
  }

  async listUserSessions(userId: string): Promise<SessionRecord[]> {
    const set = this.userIndex.get(userId);
    if (!set) return [];
    const now = this.now();
    const live: SessionRecord[] = [];
    for (const id of [...set]) {
      const entry = this.sessions.get(id);
      if (!entry || entry.expiresAt <= now) {
        // 惰性清理脏索引成员
        set.delete(id);
        if (entry) this.sessions.delete(id);
        continue;
      }
      live.push(entry.record);
    }
    if (set.size === 0) this.userIndex.delete(userId);
    live.sort((a, b) => a.createdAt - b.createdAt);
    return live;
  }

  async kickUser(userId: string, exceptId?: string): Promise<string[]> {
    const set = this.userIndex.get(userId);
    if (!set) return [];
    const destroyed: string[] = [];
    for (const id of [...set]) {
      if (id === exceptId) continue;
      this.sessions.delete(id);
      set.delete(id);
      destroyed.push(id);
    }
    if (set.size === 0) this.userIndex.delete(userId);
    return destroyed;
  }

  async ping(): Promise<void> {
    // 内存存储永远健康
  }

  async close(): Promise<void> {
    if (this.timer) clearInterval(this.timer);
    this.sessions.clear();
    this.userIndex.clear();
  }

  /** 当前存活会话数（测试/演示可观测性） */
  get size(): number {
    return this.sessions.size;
  }

  private sweep(): void {
    const now = this.now();
    for (const [id, entry] of this.sessions) {
      if (expiresBefore(entry.expiresAt, now)) {
        void this.destroy(id);
      }
    }
  }
}

function expiresBefore(expiresAt: number, now: number): boolean {
  return expiresAt <= now;
}
