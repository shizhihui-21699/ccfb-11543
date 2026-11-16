import type { WebContext } from "../http/context.js";
import type { ResolvedConfig } from "./config.js";
import { generateCsrfToken, generateSessionId, timingSafeEqual } from "./random.js";
import type { SessionRecord } from "./types.js";

export class SessionError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly code: string,
  ) {
    super(message);
  }
}

/**
 * 每个请求一个 Guard，挂在 ctx.guard / req.sessionGuard 上。
 * 路由处理器通过它操作当前会话。
 *
 * 两种 CSRF 模式共用同一个服务端持有字段 record.csrfToken：
 * - sync-token：token 只在服务端，通过响应头交给前端；
 * - double-submit：token 同样由服务端生成并持有，另外镜像一份到可读 cookie，
 *   前端读 cookie 回传，校验时比对"服务端持有值 == cookie == 回传值"。
 * 这样 token 随会话稳定存在，不会每个请求漂移。
 */
export class SessionGuard {
  /** 当前会话记录；引擎保证非空（无效请求会在到达路由前被拒） */
  record: SessionRecord;
  /** 本请求是否需要把更新后的记录写回存储 */
  private dirty = false;
  /** logout 后为 true，finalize 不再 touch 已删除的记录 */
  private destroyed = false;
  private sessionCookieAction: "keep" | "issue" | "rotate" | "clear" = "keep";
  private newSessionId: string | null = null;
  private doubleSubmitCookieAction: "keep" | "issue" | "clear" = "keep";
  /**
   * sync-token 模式下 login 轮转了 token，而适配器在 process 阶段就已经把
   * 旧 token 写进响应头 —— 置位后适配器在 finalize 阶段必须重写响应头。
   */
  private csrfHeaderStale = false;

  constructor(
    private readonly ctx: WebContext,
    private readonly config: ResolvedConfig,
    record: SessionRecord,
  ) {
    this.record = record;
  }

  get userId(): string | null {
    return this.record.userId;
  }

  get data(): Record<string, unknown> {
    return this.record.data;
  }

  get sessionId(): string {
    return this.record.id;
  }

  isAuthenticated(): boolean {
    return this.record.userId !== null;
  }

  get<T = unknown>(key: string): T | undefined {
    return this.record.data[key] as T | undefined;
  }

  set(key: string, value: unknown): void {
    this.record.data[key] = value;
    this.dirty = true;
  }

  /** 取当前 CSRF token；不存在则生成并标记落库 */
  csrfToken(): string {
    if (!this.record.csrfToken) {
      this.record.csrfToken = generateCsrfToken();
      this.dirty = true;
      // 双提交模式下新 token 需要镜像到 cookie
      if (this.config.csrf === "double-submit") {
        this.doubleSubmitCookieAction = "issue";
        this.ctx.cookies[this.config.csrfCookieName] = this.record.csrfToken;
      }
    }
    return this.record.csrfToken;
  }

  /**
   * 登录：防会话固定的核心。
   * 1) 旧 id 销毁；2) 全新随机会话 id；3) 清空旧会话数据；
   * 4) 重新计时绝对超时；5) 重新签发 CSRF token；6) 原子写入并执行并发上限淘汰。
   */
  async login(userId: string, data: Record<string, unknown> = {}): Promise<void> {
    const now = this.config.clock.now();
    const oldId = this.record.id;
    await this.config.store.destroy(oldId);

    const id = generateSessionId();
    const csrfToken =
      this.config.csrf === "off" ? null : generateCsrfToken();
    this.record = {
      id,
      userId,
      data: { ...data },
      createdAt: now,
      lastAccessAt: now,
      authenticatedAt: now,
      csrfToken,
    };
    this.newSessionId = id;
    this.sessionCookieAction = "rotate";
    this.dirty = true;
    if (this.config.csrf === "sync-token") this.csrfHeaderStale = true;
    if (this.config.csrf === "double-submit") {
      this.doubleSubmitCookieAction = "issue";
      if (csrfToken) this.ctx.cookies[this.config.csrfCookieName] = csrfToken;
    }
    // 原子：写入 + 用户索引 + 超限淘汰
    await this.config.store.save(
      this.record,
      this.config.idleTimeoutMs,
      this.config.maxSessionsPerUser,
    );
    this.dirty = false;
  }

  /** 登出：销毁服务端记录并清除 cookie */
  async logout(): Promise<void> {
    await this.config.store.destroy(this.record.id);
    this.destroyed = true;
    this.sessionCookieAction = "clear";
    if (this.config.csrf === "double-submit") this.doubleSubmitCookieAction = "clear";
  }

  wasDestroyed(): boolean {
    return this.destroyed;
  }

  /** 适配器在 finalize 后查询：sync-token 响应头是否需要重写为新 token */
  consumeCsrfHeaderRefresh(): { stale: true; token: string } | { stale: false } {
    if (!this.csrfHeaderStale) return { stale: false };
    this.csrfHeaderStale = false;
    return { stale: true, token: this.record.csrfToken ?? this.csrfToken() };
  }

  /** 踢掉该账号的全部其它会话（一键踢下线），返回被踢数量（不含当前会话） */
  async kickOtherSessions(): Promise<number> {
    if (!this.record.userId) return 0;
    const total = await this.config.store.destroyByUser(this.record.userId);
    // destroyByUser 会把当前会话也删掉，需要把自己写回去
    await this.config.store.save(this.record, this.config.idleTimeoutMs);
    return Math.max(0, total - 1);
  }

  /** 引擎在响应阶段调用：落库 + 下发 cookie */
  async commit(): Promise<void> {
    if (this.sessionCookieAction === "clear") {
      this.ctx.setCookie(this.config.cookieName, "", this.clearedCookieAttrs());
      if (this.doubleSubmitCookieAction === "clear") {
        this.ctx.setCookie(this.config.csrfCookieName, "", this.clearedCookieAttrs());
      }
      return;
    }
    if (this.dirty) {
      this.record.lastAccessAt = this.config.clock.now();
      await this.config.store.save(this.record, this.config.idleTimeoutMs);
      this.dirty = false;
    }
    if (this.sessionCookieAction === "issue" || this.sessionCookieAction === "rotate") {
      this.ctx.setCookie(
        this.config.cookieName,
        this.newSessionId ?? this.record.id,
        this.sessionCookieAttrs(),
      );
    }
    if (
      this.config.csrf === "double-submit" &&
      (this.doubleSubmitCookieAction === "issue" || this.doubleSubmitCookieAction === "keep")
    ) {
      // 每个响应都确保 cookie 与服务端持有值一致（首次签发或登录轮转后重发）
      const token = this.record.csrfToken ?? this.csrfToken();
      this.ctx.setCookie(this.config.csrfCookieName, token, this.csrfCookieAttrs());
    }
  }

  /** 引擎调用：CSRF 校验 */
  verifyCsrf(): void {
    if (this.config.csrf === "off") return;
    if (this.config.csrfSafeMethods.includes(this.ctx.method)) return;
    if (this.config.csrfExemptPrefixes.some((p) => this.ctx.path.startsWith(p))) return;

    const supplied = this.readSuppliedToken();
    const serverToken = this.record.csrfToken;

    if (this.config.csrf === "sync-token") {
      if (!serverToken || !supplied || !timingSafeEqual(serverToken, supplied)) {
        throw new SessionError("CSRF token 校验失败", 403, "CSRF_INVALID");
      }
      return;
    }

    // double-submit：服务端持有值、cookie、回传值三者必须一致且非空
    const cookieToken = this.ctx.cookies[this.config.csrfCookieName];
    if (
      !serverToken ||
      !cookieToken ||
      !supplied ||
      !timingSafeEqual(serverToken, cookieToken) ||
      !timingSafeEqual(serverToken, supplied)
    ) {
      throw new SessionError("双提交 CSRF 校验失败", 403, "CSRF_INVALID");
    }
  }

  /** 双提交模式下，引擎确保每个响应都带与服务端一致的 CSRF cookie */
  ensureDoubleSubmitCookieIssued(): void {
    if (this.config.csrf !== "double-submit") return;
    // 触发 token 生成（若尚未生成），commit 会负责把它写进 cookie
    this.csrfToken();
  }

  private readSuppliedToken(): string | undefined {
    const header = this.ctx.header(this.config.csrfHeaderName);
    if (header) return header;
    const query = this.ctx.query("csrf_token");
    if (query) return query;
    const body = this.ctx.bodyField("csrf_token");
    return typeof body === "string" ? body : undefined;
  }

  private sessionCookieAttrs() {
    return {
      path: "/",
      secure: !this.config.allowInsecureLocal,
      httpOnly: true,
      sameSite: "Strict" as const,
    };
  }

  private csrfCookieAttrs() {
    return {
      path: "/",
      secure: !this.config.allowInsecureLocal,
      // 刻意不开 HttpOnly：前端要读出来回传，这正是双提交模式的定义
      httpOnly: false,
      sameSite: "Strict" as const,
    };
  }

  private clearedCookieAttrs() {
    return {
      path: "/",
      maxAge: 0,
      secure: !this.config.allowInsecureLocal,
      httpOnly: true,
      sameSite: "Strict" as const,
    };
  }

  // ---- 引擎内部使用 ----

  /** 标记为新建匿名会话，响应时下发 cookie */
  markNew(): void {
    this.sessionCookieAction = "issue";
    this.newSessionId = this.record.id;
  }
}
