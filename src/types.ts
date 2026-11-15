/**
 * 会话安全中间件 —— 领域模型与存储抽象
 *
 * 设计原则：
 * 1. 存储层只负责 KV 持久化 + 用户→会话的索引维护，所有安全策略（轮换、过期、并发上限、踢人）
 *    都在 engine 层实现，换存储不会改变安全语义。
 * 2. 引擎不持有任何计时器，空闲/绝对超时全部惰性求值（基于 createdAt / lastSeenAt 与当前时间比对），
 *    这样内存版与 Redis 版行为完全一致，也方便用假时钟做单元测试。
 */

/** 挂在请求上下文上的会话对象（存储层的完整记录 + 引擎运行期状态） */
export interface SessionRecord {
  /** 会话 ID，同时也是存储主键；轮换登录后会变成新值 */
  id: string;
  /** 登录主体（用户 ID）。未登录的匿名会话为 null */
  userId: string | null;
  /** 创建时间（epoch ms），绝对超时从这里起算，整个会话生命周期内不变 */
  createdAt: number;
  /** 最近一次被请求“触碰”的时间（epoch ms），空闲超时从这里起算 */
  lastSeenAt: number;
  /**
   * 同步令牌模式（synchronizer）下的 CSRF token，随会话创建/轮换一次性生成。
   * 双提交模式下该字段为空（token 只活在签名 cookie 里）。
   */
  csrfToken: string | null;
  /** 应用自定义数据（登录态之外的业务字段） */
  data: Record<string, unknown>;
}

/**
 * 可插拔会话存储。
 *
 * 语义约定：
 * - key 一律是会话 ID（由引擎生成的高熵随机串），value 是完整 SessionRecord。
 * - 引擎自己计算过期时间并写入 record，存储只负责按 ttlSeconds 做 TTL 淘汰；
 *   语义级的“空闲/绝对超时”判定永远在引擎里做，存储不参与。
 * - 用户索引是一个“可能包含过期成员”的集合：存储不负责清理脏成员，
 *   引擎读回后会用 record 的时间戳自行过滤。这样存储接口可以极简。
 */
export interface SessionStore {
  /** 写入/覆盖一个会话，并设置整键 TTL（秒）。ttl 应取空闲与绝对剩余时间的较小值 */
  put(record: SessionRecord, ttlSeconds: number): Promise<void>;

  /** 按会话 ID 读取；不存在或已被 TTL 淘汰时返回 null */
  get(id: string): Promise<SessionRecord | null>;

  /** 删除单个会话（登出 / 踢人 / 轮换时清理旧 ID）。不存在时静默成功 */
  destroy(id: string): Promise<void>;

  /**
   * 刷新 lastSeenAt 并续期 TTL，不改动其它字段。
   * 单独成方法是为了让 Redis 版能用一次原子调用完成，避免 get→put 的竞态。
   */
  touch(id: string, lastSeenAt: number, ttlSeconds: number): Promise<void>;

  /** 列出某用户当前（可能含已过期成员）的全部会话，按创建时间升序 */
  listUserSessions(userId: string): Promise<SessionRecord[]>;

  /**
   * 踢某账号下线：销毁其全部会话。
   * exceptId 给定时保留该会话（用于“登录挤掉旧会话、保留当前新会话”的并发上限场景）。
   * 返回被销毁的会话 ID 列表。
   */
  kickUser(userId: string, exceptId?: string): Promise<string[]>;

  /** 存储自检（健康检查 / 演示用） */
  ping?(): Promise<void>;

  /** 释放底层连接（进程退出钩子用） */
  close?(): Promise<void>;
}

/** CSRF 防护模式 */
export type CsrfMode =
  | 'synchronizer'
  | 'double-submit'
  | 'off';

export type SameSite = 'lax' | 'strict' | 'none';

export interface SessionEngineOptions {
  /** 会话存储，必填 */
  store: SessionStore;
  /** 会话 cookie 名；启用 __Host 前缀时会自动强制 __Host- 前缀 */
  cookieName?: string;
  /**
   * 是否使用 __Host- 前缀（默认 true）。
   * __Host- cookie 强制 Secure、不能带 Domain、路径必须是 /，浏览器层面阻止子域注入覆盖。
   * 本地 http 调试时可显式关掉，关掉后 cookie 名去掉前缀且不写 Secure。
   */
  hostPrefix?: boolean;
  /** SameSite 策略，默认 lax（可挡跨站 POST 的 CSRF，同时允许顶层 GET 导航带 cookie） */
  sameSite?: SameSite;
  /** 空闲超时（毫秒）：两次请求间隔超过该值会话失效。默认 30 分钟 */
  idleTimeoutMs?: number;
  /** 绝对超时（毫秒）：会话自创建起的最长寿命，无论期间是否活跃。默认 12 小时 */
  absoluteTimeoutMs?: number;
  /** 同一账号允许的并发会话上限；超出时最早创建的会话被挤掉。默认 5 */
  maxSessionsPerUser?: number;
  /** CSRF 模式，默认 synchronizer（同步令牌） */
  csrfMode?: CsrfMode;
  /** 双提交模式下存放 CSRF token 的 cookie 名 */
  csrfCookieName?: string;
  /**
   * 双提交 cookie 的 HMAC 签名密钥。
   * 双提交 token 不进服务端存储，靠 HMAC 防止攻击者自行铸造 token；必须提供足够长的随机密钥。
   * synchronizer 模式下可省略。
   */
  csrfSecret?: string;
  /** 自定义时钟（单元测试注入），默认 Date.now */
  now?: () => number;
  /** 自定义会话 ID 字节数（默认 32 字节 → 43 字符 base64url） */
  idBytes?: number;
}

/** 引擎在请求级暴露给业务代码的句柄 */
export interface SessionHandle {
  /** 当前会话记录（可能是匿名会话，userId 为 null） */
  readonly record: SessionRecord;
  /** 当前请求有效的 CSRF token（synchronizer 返回服务端存的；double-submit 返回 cookie 里的值） */
  readonly csrfToken: string | null;
  /** 是否已登录 */
  isAuthenticated(): boolean;
  /**
   * 登录：销毁旧会话 ID、生成全新 ID 与全新 CSRF token 后再绑定 userId —— 防会话固定。
   * 同时执行并发上限淘汰。返回新的会话 ID。
   */
  login(userId: string, data?: Record<string, unknown>): Promise<string>;
  /** 登出：销毁当前会话并下发清除 cookie */
  logout(): Promise<void>;
  /** 更新业务数据并落盘（不触碰 lastSeenAt 之外的安全字段） */
  setData(patch: Record<string, unknown>): Promise<void>;
  /** 踢同一账号的所有其它会话下线，当前会话保留 */
  kickOthers(): Promise<string[]>;
}

/** CSRF 校验失败的原因，便于日志与演示 */
export type CsrfFailureReason =
  | 'no-token'
  | 'token-mismatch'
  | 'bad-signature';
