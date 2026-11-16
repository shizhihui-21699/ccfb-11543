import type { Clock, SessionRecord, SessionStore } from "../core/types.js";

interface Entry {
  record: SessionRecord;
  /**
   * 垃圾回收时刻（毫秒），仅给后台 sweep 用。
   * 注意：get/listByUser 不读它 —— 会话是否超时由引擎看
   * lastAccessAt / authenticatedAt 权威判定，存储层不抢答。
   */
  expiresAt: number;
}

/**
 * 进程内会话存储。
 *
 * - Map<会话ID, 记录> + Map<用户ID, Set<会话ID>> 双索引；
 * - 空闲/绝对超时的判定权归引擎：存储层 get 不做惰性删除，
 *   否则引擎无法区分"会话超时"与"会话从不存在"，拿不到 idle/absolute 细分原因；
 * - expiresAt 仅作为后台 sweep 兜底回收无人访问的僵尸记录（真实时钟下
 *   引擎正常处理流量时本就会清掉过期会话，sweep 只负责漏网之鱼）。
 *
 * 适用于单实例部署与测试；多实例请用 RedisStore。
 */
export class MemoryStore implements SessionStore {
  readonly name = "memory";

  private readonly sessions = new Map<string, Entry>();
  private readonly userIndex = new Map<string, Set<string>>();
  private readonly sweepTimer: NodeJS.Timeout | null = null;

  constructor(
    private readonly clock: Clock = { now: () => Date.now() },
    sweepIntervalMs = 60_000,
  ) {
    if (sweepIntervalMs > 0) {
      // unref：测试与 CLI 进程退出时不被定时器挂住
      this.sweepTimer = setInterval(() => this.sweep(), sweepIntervalMs).unref();
    }
  }

  /** 读取不过期；超时由引擎统一判定 */
  async get(id: string): Promise<SessionRecord | null> {
    return this.sessions.get(id)?.record ?? null;
  }

  async save(record: SessionRecord, idleTimeoutMs: number, maxSessions = 0): Promise<void> {
    const existing = this.sessions.get(record.id);
    // 用户归属可能在 login 时从 null 变成具体 userId，需要维护索引迁移
    if (existing?.record.userId && existing.record.userId !== record.userId) {
      this.indexRemove(existing.record.userId, record.id);
    }
    this.sessions.set(record.id, {
      record,
      expiresAt: this.clock.now() + idleTimeoutMs,
    });
    if (record.userId) {
      this.indexAdd(record.userId, record.id);
      if (maxSessions > 0) await this.enforceLimit(record.userId, maxSessions);
    }
  }

  async touch(id: string, lastAccessAt: number, idleTimeoutMs: number): Promise<void> {
    const entry = this.sessions.get(id);
    if (!entry) return;
    entry.record.lastAccessAt = lastAccessAt;
    entry.expiresAt = lastAccessAt + idleTimeoutMs;
  }

  async destroy(id: string): Promise<void> {
    const entry = this.sessions.get(id);
    if (!entry) return;
    this.sessions.delete(id);
    if (entry.record.userId) this.indexRemove(entry.record.userId, id);
  }

  /** 列出用户会话；不做超时过滤——引擎拿到记录后自行判定 */
  async listByUser(userId: string): Promise<SessionRecord[]> {
    const ids = this.userIndex.get(userId);
    if (!ids) return [];
    const out: SessionRecord[] = [];
    for (const id of [...ids]) {
      const entry = this.sessions.get(id);
      if (!entry) {
        // 索引残留（理论上 destroy 都会同步清，防御性处理）
        ids.delete(id);
        continue;
      }
      out.push(entry.record);
    }
    return out;
  }

  async destroyByUser(userId: string): Promise<number> {
    const ids = this.userIndex.get(userId);
    if (!ids) return 0;
    const count = ids.size;
    for (const id of [...ids]) this.sessions.delete(id);
    this.userIndex.delete(userId);
    return count;
  }

  async close(): Promise<void> {
    if (this.sweepTimer) clearInterval(this.sweepTimer);
    this.sessions.clear();
    this.userIndex.clear();
  }

  /**
   * 并发上限：淘汰该用户最老的会话。
   * 判定"老"用 createdAt（会话首次建立时间），与空闲活动无关，
   * 避免一个活跃旧会话因为 lastAccessAt 新而永远挤不掉。
   */
  private async enforceLimit(userId: string, max: number): Promise<void> {
    const ids = this.userIndex.get(userId);
    if (!ids) return;
    const live: Array<{ id: string; createdAt: number }> = [];
    for (const id of [...ids]) {
      const entry = this.sessions.get(id);
      if (!entry) {
        ids.delete(id);
        continue;
      }
      live.push({ id, createdAt: entry.record.createdAt });
    }
    const overflow = live.length - max;
    if (overflow <= 0) return;
    live.sort((a, b) => a.createdAt - b.createdAt);
    for (let i = 0; i < overflow; i++) await this.destroy(live[i]!.id);
  }

  /** 纯垃圾回收：只删超过 GC 宽限期的僵尸，不参与安全判定 */
  private sweep(): void {
    const now = this.clock.now();
    for (const [id, entry] of this.sessions) {
      if (entry.expiresAt <= now) {
        this.sessions.delete(id);
        if (entry.record.userId) this.indexRemove(entry.record.userId, id);
      }
    }
  }

  private indexAdd(userId: string, id: string): void {
    let set = this.userIndex.get(userId);
    if (!set) {
      set = new Set();
      this.userIndex.set(userId, set);
    }
    set.add(id);
  }

  private indexRemove(userId: string, id: string): void {
    const set = this.userIndex.get(userId);
    if (!set) return;
    set.delete(id);
    if (set.size === 0) this.userIndex.delete(userId);
  }
}
