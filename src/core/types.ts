/**
 * 会话记录与存储抽象。
 *
 * 设计要点：
 * - SessionRecord 是存储层唯一的数据模型，所有安全策略（超时、并发上限、踢下线）
 *   由引擎在记录上计算，存储层只负责持久化与按用户索引。
 * - SessionStore 不感知 cookie / CSRF / HTTP，方便单测与替换实现。
 */

/** 一条服务端会话记录（永远不要整个下发给浏览器） */
export interface SessionRecord {
  /** 随机会话 ID（高熵，加密随机生成） */
  id: string;
  /** 归属账号 ID（未登录会话为匿名，可空） */
  userId: string | null;
  /** 业务数据 */
  data: Record<string, unknown>;
  /** 创建时间（毫秒） */
  createdAt: number;
  /** 最近一次访问时间（毫秒），用于空闲超时 */
  lastAccessAt: number;
  /** 登录/轮转时间（毫秒），用于绝对超时；未登录时为 null */
  authenticatedAt: number | null;
  /** 同步令牌模式下的 CSRF token（双提交模式不在这里存） */
  csrfToken: string | null;
}

/**
 * 可插拔会话存储接口。
 *
 * 超时职责划分（关键约定）：
 * - "会话是否已超时"的判定权完全在引擎：引擎读取记录的 lastAccessAt（空闲）
 *   与 authenticatedAt（绝对）自行判定，存储层 get/listByUser 不得因为"到点了"
 *   就过滤或删除记录 —— 否则引擎无法区分"超时失效"与"会话从不存在"；
 * - 存储层 TTL 只做垃圾回收兜底：建议设为 idleTimeoutMs 的 2 倍，
 *   保证引擎判活的会话一定还能读到，同时无人访问的僵尸记录最终会被回收；
 * - 绝对超时不依赖任何存储 TTL。
 *
 * 并发语义：单进程内存实现天然同步；Redis 实现要求引擎在"登录轮转 + 超限淘汰"
 * 这类复合操作上通过 Lua 脚本保证原子性（见 RedisStore 内部实现）。
 */
export interface SessionStore {
  /** 存储实现名称，便于日志与测试断言 */
  readonly name: string;

  /** 按 ID 取会话；仅当记录被 destroy/GC 回收时返回 null，不做超时判定 */
  get(id: string): Promise<SessionRecord | null>;

  /**
   * 全量更新会话并刷新 GC TTL（建议 2 * idleTimeoutMs）。
   * maxSessions > 0 时（仅登录轮转传），保证该用户存活会话数不超过上限，
   * 超出部分淘汰最老的会话；为 0 时不做限制。
   */
  save(record: SessionRecord, idleTimeoutMs: number, maxSessions?: number): Promise<void>;

  /** 只刷新访问时间与 GC TTL，不改变其它字段 */
  touch(id: string, lastAccessAt: number, idleTimeoutMs: number): Promise<void>;

  /** 删除单条会话；同时负责清理 userId 反向索引 */
  destroy(id: string): Promise<void>;

  /** 列出某账号当前全部会话（不过滤超时，引擎自行判定），用于并发上限与踢下线 */
  listByUser(userId: string): Promise<SessionRecord[]>;

  /** 删除某账号的全部会话（一键踢下线），返回被删数量 */
  destroyByUser(userId: string): Promise<number>;

  /** 释放存储资源（关闭定时器、连接等），进程退出时调用 */
  close?(): Promise<void>;
}

/** 可注入的时钟，测试用；默认 Date.now */
export interface Clock {
  now(): number;
}
