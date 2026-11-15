/**
 * SessionEngine —— 框架无关的会话安全核心。
 *
 * 职责（全部安全语义集中在本文件，适配器只做协议翻译）：
 * 1. 读 cookie → 惰性校验空闲/绝对超时 → 必要时新建匿名会话
 * 2. 登录轮换（regenerate）：旧 ID 彻底销毁，新 ID + 新 CSRF token，防会话固定
 * 3. CSRF：synchronizer（服务端存 token，恒定时间比对）/ double-submit（HMAC 签名 cookie，恒定时间比对）
 * 4. 并发会话上限：登录后按 createdAt 淘汰最旧会话
 * 5. 踢人：store.kickUser
 * 6. 每个请求结束统一 touch + 计算剩余 TTL + 下发 cookie
 */
import {
  randomId,
  randomCsrfToken,
  safeEqual,
  signToken,
  verifySignedToken,
} from './crypto.js';
import {
  effectiveCookieName,
  parseCookieHeader,
  serializeSetCookie,
} from './cookie.js';
import type {
  CsrfFailureReason,
  CsrfMode,
  SameSite,
  SessionEngineOptions,
  SessionHandle,
  SessionRecord,
  SessionStore,
} from './types.js';

/** 适配器需要实现的最小请求/响应抽象，Express 与 Hono 各自翻译 */
export interface FrameworkRequest {
  cookieHeader(): string | undefined;
  /** CSRF token 的带外来源：header 优先，其次请求体字段 */
  header(name: string): string | undefined;
  bodyField?(name: string): unknown;
  method(): string;
}

export interface FrameworkResponse {
  /** 追加一条 Set-Cookie（适配器负责映射到各自框架的多值响应头 API） */
  appendSetCookie(cookie: string): void;
}

/** 引擎处理一次请求后的结果，供适配器决定后续流程 */
export interface ProcessResult {
  handle: SessionHandle;
  /** 本次请求是否被判定为 CSRF 攻击（仅状态变更方法可能为 true） */
  csrfFailed: boolean;
  csrfFailureReason: CsrfFailureReason | null;
  /** 本次请求是否因超时而失效（旧会话已被销毁，handle 是新匿名会话） */
  timedOut: 'idle' | 'absolute' | null;
}

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS', 'TRACE']);
const CSRF_HEADER = 'x-csrf-token';
const CSRF_BODY_FIELD = '_csrf';

interface HandleState {
  record: SessionRecord;
  loggedOut: boolean;
}

export class SessionEngine {
  readonly store: SessionStore;
  readonly cookieName: string;
  readonly csrfCookieName: string;
  readonly hostPrefix: boolean;
  readonly sameSite: SameSite;
  readonly idleTimeoutMs: number;
  readonly absoluteTimeoutMs: number;
  readonly maxSessionsPerUser: number;
  readonly csrfMode: CsrfMode;
  private readonly csrfSecret: string | null;
  private readonly now: () => number;
  private readonly idBytes: number;
  /** handle -> 运行期内部状态（可变 record 引用 + logout 标记），不暴露给业务代码 */
  private readonly handleState = new WeakMap<SessionHandle, HandleState>();

  constructor(opts: SessionEngineOptions) {
    this.store = opts.store;
    this.hostPrefix = opts.hostPrefix ?? true;
    this.sameSite = opts.sameSite ?? 'lax';
    this.idleTimeoutMs = opts.idleTimeoutMs ?? 30 * 60_000;
    this.absoluteTimeoutMs = opts.absoluteTimeoutMs ?? 12 * 60 * 60_000;
    this.maxSessionsPerUser = opts.maxSessionsPerUser ?? 5;
    this.csrfMode = opts.csrfMode ?? 'synchronizer';
    this.now = opts.now ?? (() => Date.now());
    this.idBytes = opts.idBytes ?? 32;
    this.cookieName = effectiveCookieName(opts.cookieName ?? 'sid', this.hostPrefix);
    this.csrfCookieName = effectiveCookieName(
      opts.csrfCookieName ?? 'csrf_token',
      this.hostPrefix,
    );
    if (this.csrfMode === 'double-submit' && !opts.csrfSecret) {
      throw new Error(
        'double-submit CSRF 模式必须提供 csrfSecret（至少 32 字节随机串的 base64）',
      );
    }
    this.csrfSecret = opts.csrfSecret ?? null;
    if (this.absoluteTimeoutMs < this.idleTimeoutMs) {
      // 绝对超时短于空闲超时是合法的（每次请求都按绝对寿命强制重登），不报错，
      // TTL 计算处自然取最小值。
    }
  }

  /**
   * 当前时间下，record 的存储 TTL（秒）。
   * 存储层 TTL 按绝对寿命 + 宽限期设置 —— 空闲/绝对过期都是引擎的语义职责
   * （需要区分 idle/absolute 归因并主动销毁），不能让存储在引擎判定前把键删掉。
   * 宽限期保证死线后第一个请求仍能读到 record，由引擎归因后销毁；
   * 若死线后再无请求，宽限期结束存储也会兜底清理，不会泄漏。
   */
  storageTtlSeconds(record: SessionRecord, now = this.now()): number {
    const absoluteDeadline = record.createdAt + this.absoluteTimeoutMs;
    const graceMs = 60_000;
    return Math.max(1, Math.ceil((absoluteDeadline + graceMs - now) / 1000));
  }

  /**
   * 距下一次语义过期还有多久（秒），取空闲与绝对死线的较小值；
   * 供下发给浏览器的 cookie Max-Age 使用，让浏览器侧也按最短寿命清理。
   */
  remainingTtlSeconds(record: SessionRecord, now = this.now()): number {
    const idleDeadline = record.lastSeenAt + this.idleTimeoutMs;
    const absoluteDeadline = record.createdAt + this.absoluteTimeoutMs;
    const deadline = Math.min(idleDeadline, absoluteDeadline);
    return Math.max(0, Math.ceil((deadline - now) / 1000));
  }

  /** 判定 record 处于哪种过期（先到先得，同一时刻两者都过期报 absolute） */
  private expirationKind(
    record: SessionRecord,
    now: number,
  ): 'idle' | 'absolute' | null {
    const absoluteDeadline = record.createdAt + this.absoluteTimeoutMs;
    if (now >= absoluteDeadline) return 'absolute';
    const idleDeadline = record.lastSeenAt + this.idleTimeoutMs;
    if (now >= idleDeadline) return 'idle';
    return null;
  }

  private newRecord(userId: string | null): SessionRecord {
    const now = this.now();
    return {
      id: randomId(this.idBytes),
      userId,
      createdAt: now,
      lastSeenAt: now,
      csrfToken: this.csrfMode === 'synchronizer' ? randomCsrfToken() : null,
      data: {},
    };
  }

  /**
   * 处理请求的主入口。适配器在业务 handler 之前调用一次。
   * 结束时适配器必须调用 finalize()，以保证 touch / Set-Cookie 一定发生。
   */
  async process(req: FrameworkRequest): Promise<ProcessResult> {
    const cookies = parseCookieHeader(req.cookieHeader());
    const sid = cookies[this.cookieName];
    let record: SessionRecord | null = null;
    let timedOut: ProcessResult['timedOut'] = null;

    if (sid) {
      const stored = await this.store.get(sid);
      if (stored) {
        const kind = this.expirationKind(stored, this.now());
        if (kind) {
          // 过期会话立即销毁，避免旧 ID 继续可被探测
          await this.store.destroy(stored.id);
          timedOut = kind;
        } else {
          record = stored;
        }
      }
    }

    if (!record) {
      record = this.newRecord(null);
      await this.store.put(record, this.storageTtlSeconds(record));
    }

    const handle = this.createHandle(record);
    const csrf = this.shouldCheckCsrf(req.method())
      ? this.checkCsrf(req, record, cookies)
      : { ok: true, reason: null as CsrfFailureReason | null };
    return {
      handle,
      csrfFailed: !csrf.ok,
      csrfFailureReason: csrf.ok ? null : csrf.reason,
      timedOut,
    };
  }

  /**
   * 请求收尾：续期 lastSeenAt、写回存储、下发会话 cookie（及双提交 CSRF cookie）。
   * 必须传 process() 返回的同一个 handle，引擎据此定位内部 holder 并替换 record 副本。
   */
  async finalize(
    res: FrameworkResponse,
    handle: SessionHandle,
    options: { clear?: boolean } = {},
  ): Promise<void> {
    const record = handle.record;
    if (options.clear) {
      res.appendSetCookie(this.clearCookie(this.cookieName));
      if (this.csrfMode === 'double-submit') {
        res.appendSetCookie(this.clearCookie(this.csrfCookieName));
      }
      return;
    }
    const now = this.now();
    // 创建副本再更新：内存存储持有的是同一对象引用，原地改写会让引擎与存储
    // 共享可变状态（Redis 版经 JSON 序列化天然无别名，内存版必须显式隔离）
    let touched: SessionRecord = { ...record, lastSeenAt: now };
    this.replaceHandleRecord(handle, touched);
    await this.store.touch(touched.id, now, this.storageTtlSeconds(touched, now));
    // cookie 的 Max-Age 仍取语义最短寿命，浏览器侧按空闲/绝对先到者清理
    const ttl = this.remainingTtlSeconds(touched, now);
    res.appendSetCookie(
      serializeSetCookie({
        name: this.cookieName,
        value: record.id,
        hostPrefix: this.hostPrefix,
        httpOnly: true,
        secure: this.hostPrefix,
        sameSite: this.sameSite,
        maxAgeSeconds: ttl,
      }),
    );
    if (this.csrfMode === 'double-submit') {
      // 双提交 cookie 不设 HttpOnly：前端 JS 需要读取后放到 header 里回传；
      // 靠 HMAC 签名保证攻击者无法铸造，靠 __Host 前缀保证无法被子域注入。
      let token = this.doubleSubmitTokenFromRecord(touched);
      if (!token) {
        token = this.mintDoubleSubmitToken();
        // 回写并落盘，保证后续请求的 getter、cookie、校验三处拿到同一个 token
        const withToken: SessionRecord = {
          ...touched,
          data: { ...touched.data, __csrfDoubleSubmit: token },
        };
        this.replaceHandleRecord(handle, withToken);
        await this.store.put(withToken, this.storageTtlSeconds(withToken, now));
        touched = withToken;
      }
      res.appendSetCookie(
        serializeSetCookie({
          name: this.csrfCookieName,
          value: token,
          hostPrefix: this.hostPrefix,
          httpOnly: false,
          secure: this.hostPrefix,
          sameSite: this.sameSite,
          maxAgeSeconds: ttl,
        }),
      );
    }
  }

  private shouldCheckCsrf(method: string): boolean {
    if (this.csrfMode === 'off') return false;
    return !SAFE_METHODS.has(method.toUpperCase());
  }

  private checkCsrf(
    req: FrameworkRequest,
    record: SessionRecord,
    cookies: Record<string, string>,
  ): { ok: boolean; reason: CsrfFailureReason | null } {
    const presented = this.readPresentedToken(req);
    if (!presented) return { ok: false, reason: 'no-token' };
    if (this.csrfMode === 'synchronizer') {
      const expected = record.csrfToken;
      if (!expected || !safeEqual(presented, expected)) {
        return { ok: false, reason: 'token-mismatch' };
      }
      return { ok: true, reason: null };
    }
    // double-submit：cookie 与 header/body 必须一致，且两者都必须通过 HMAC 验签
    const cookieToken = cookies[this.csrfCookieName];
    if (!cookieToken || cookieToken !== presented) {
      return { ok: false, reason: 'token-mismatch' };
    }
    if (
      !this.csrfSecret ||
      !verifySignedToken(this.csrfSecret, cookieToken) ||
      !verifySignedToken(this.csrfSecret, presented)
    ) {
      return { ok: false, reason: 'bad-signature' };
    }
    return { ok: true, reason: null };
  }

  private readPresentedToken(req: FrameworkRequest): string | null {
    const headerVal = req.header(CSRF_HEADER);
    if (typeof headerVal === 'string' && headerVal.length > 0) return headerVal;
    const bodyVal = req.bodyField?.(CSRF_BODY_FIELD);
    return typeof bodyVal === 'string' && bodyVal.length > 0 ? bodyVal : null;
  }

  private mintDoubleSubmitToken(): string {
    return signToken(this.csrfSecret ?? '', randomCsrfToken(16));
  }

  private doubleSubmitTokenFromRecord(record: SessionRecord): string | null {
    // 双提交 token 不入存储；这里仅复用 record.data 里适配器缓存的当次值
    const cached = record.data.__csrfDoubleSubmit;
    return typeof cached === 'string' ? cached : null;
  }

  private createHandle(initial: SessionRecord): SessionHandle {
    // holder 同时承载可变 record 引用与运行期标记，引擎通过 WeakMap 在 finalize 时替换 record
    const holder: HandleState = { record: initial, loggedOut: false };
    const self = this;

    const handle: SessionHandle = {
      get record() {
        return holder.record;
      },
      get csrfToken() {
        const current = holder.record;
        if (self.csrfMode === 'synchronizer') return current.csrfToken;
        let cached = self.doubleSubmitTokenFromRecord(current);
        if (!cached) {
          cached = self.mintDoubleSubmitToken();
          // 经副本写回，保持“record 一旦进入引擎就不原地突变”的不变式
          const next = {
            ...current,
            data: { ...current.data, __csrfDoubleSubmit: cached },
          };
          holder.record = next;
          void self.store.put(next, self.storageTtlSeconds(next));
        }
        return cached;
      },
      isAuthenticated() {
        return holder.record.userId !== null;
      },
      async login(userId: string, data = {}) {
        if (!userId) throw new Error('login 需要非空 userId');
        // 1) 销毁登录前的会话（无论匿名还是已登录），旧 session ID 立即失效
        const oldId = holder.record.id;
        // 2) 全新 record：新 ID、新 createdAt、新 CSRF token —— 防会话固定
        const fresh = self.newRecord(userId);
        fresh.data = { ...data };
        await self.store.put(fresh, self.storageTtlSeconds(fresh));
        if (oldId !== fresh.id) await self.store.destroy(oldId);
        holder.record = fresh;
        holder.loggedOut = false;
        // 3) 并发上限：列出该用户全部存活会话，超出部分从最旧开始踢
        await self.enforceConcurrencyLimit(holder.record);
        return holder.record.id;
      },
      async logout() {
        await self.store.destroy(holder.record.id);
        // 替换成匿名 record，适配器 finalize 时下发清除 cookie
        holder.record = self.newRecord(null);
        holder.loggedOut = true;
      },
      async setData(patch) {
        const current = holder.record;
        const next = { ...current, data: { ...current.data, ...patch } };
        holder.record = next;
        await self.store.put(next, self.storageTtlSeconds(next));
      },
      async kickOthers() {
        if (holder.record.userId === null) return [];
        return self.store.kickUser(holder.record.userId, holder.record.id);
      },
    };
    this.handleState.set(handle, holder);
    return handle;
  }

  /** finalize 续期后，把 handle 指向新的 record 副本（断开与存储对象的别名） */
  private replaceHandleRecord(
    handle: SessionHandle,
    next: SessionRecord,
  ): void {
    const holder = this.handleState.get(handle);
    if (holder) holder.record = next;
  }

  /** 适配器查询本次请求是否调用过 logout（决定 finalize 走清除分支） */
  isLoggedOut(handle: SessionHandle): boolean {
    return this.handleState.get(handle)?.loggedOut ?? false;
  }

  private async enforceConcurrencyLimit(record: SessionRecord): Promise<void> {
    if (record.userId === null) return;
    const all = await this.store.listUserSessions(record.userId);
    const excess = all.length - this.maxSessionsPerUser;
    if (excess <= 0) return;
    // all 已按 createdAt 升序；最旧的 excess 个会话被挤掉
    const victims = all.slice(0, excess).filter((r) => r.id !== record.id);
    for (const victim of victims) {
      await this.store.destroy(victim.id);
    }
  }

  /** 一键踢整个账号下线（管理员操作入口，不依赖具体请求句柄） */
  async kickUser(userId: string): Promise<string[]> {
    return this.store.kickUser(userId);
  }

  private clearCookie(name: string): string {
    return serializeSetCookie({
      name,
      value: '',
      hostPrefix: this.hostPrefix,
      httpOnly: true,
      secure: this.hostPrefix,
      sameSite: this.sameSite,
      maxAgeSeconds: 0,
    });
  }
}
