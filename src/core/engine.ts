import type { WebContext } from "../http/context.js";
import { resolveConfig, type ResolvedConfig, type SessionConfig } from "./config.js";
import { SessionGuard, SessionError } from "./guard.js";
import { generateSessionId } from "./random.js";

/**
 * 会话安全引擎。无框架依赖：适配器负责把请求翻译成 WebContext，
 * 引擎负责全部安全判定，返回一个挂好守卫的 ctx。
 *
 * 每个请求的处理顺序：
 *   1. 读 cookie 中的会话 id，查存储；
 *   2. 无效/缺失 -> 新建匿名会话（登录前也有服务端会话，CSRF token 有地方落）；
 *   3. 绝对超时判定（authenticatedAt + absoluteTimeoutMs，不可续期）；
 *   4. 空闲超时判定（lastAccessAt + idleTimeoutMs）；
 *   5. 不安全方法做 CSRF 校验；
 *   6. 路由执行（通过 guard.login/logout/... 操作会话）；
 *   7. commit：刷空闲 TTL、落库、下发/轮转/清除 cookie。
 */
export class SessionEngine {
  readonly config: ResolvedConfig;

  constructor(config: SessionConfig) {
    this.config = resolveConfig(config);
    this.assertCookieNameSafety();
  }

  /**
   * 处理一个请求。成功返回带 guard 的 ctx；失败抛 SessionError，
   * 由适配器翻译成对应状态码的响应。
   */
  async process(ctx: WebContext): Promise<WebContext> {
    const now = this.config.clock.now();
    let record = await this.loadSession(ctx);

    if (record) {
      const timeoutReason = this.checkTimeouts(record, now);
      if (timeoutReason) {
        await this.config.store.destroy(record.id);
        // 旧 cookie 必须清掉，再建一个全新匿名会话
        record = null;
        ctx.sessionExpired = timeoutReason;
      }
    }

    let guard: SessionGuard;
    if (!record) {
      guard = await this.createAnonymous(ctx, now);
      guard.markNew();
    } else {
      guard = new SessionGuard(ctx, this.config, record);
    }

    // CSRF 在路由之前；登录接口本身应放进 csrfExemptPrefixes
    guard.verifyCsrf();
    guard.ensureDoubleSubmitCookieIssued();

    ctx.guard = guard;
    return ctx;
  }

  /** 路由结束后调用；未发生登录/登出时仅 touch 刷空闲 TTL */
  async finalize(ctx: WebContext): Promise<void> {
    const guard = this.requireGuard(ctx);
    await guard.commit();

    // commit 内部只在 dirty 时 save；纯读请求在这里 touch 续空闲 TTL。
    // 绝对超时不随 touch 延长 —— 这正是两种超时分开算的意义。
    if (guard.wasDestroyed()) return;
    const now = this.config.clock.now();
    await this.config.store.touch(guard.sessionId, now, this.config.idleTimeoutMs);
  }

  /** 适配器在捕获 SessionError 时调用，尽量清掉过期 cookie */
  async handleFailure(ctx: WebContext, error: unknown): Promise<void> {
    if (error instanceof SessionError && error.code === "CSRF_INVALID") return;
    // 超时等场景：清除浏览器侧旧 cookie
    if (ctx.cookies[this.config.cookieName]) {
      ctx.setCookie(this.config.cookieName, "", {
        path: "/",
        maxAge: 0,
        secure: !this.config.allowInsecureLocal,
        httpOnly: true,
        sameSite: "Strict",
      });
    }
  }

  /** 管理面：列出某账号全部有效会话 */
  listSessions(userId: string) {
    return this.config.store.listByUser(userId);
  }

  /** 管理面：一键踢下线某账号全部会话 */
  kickUser(userId: string): Promise<number> {
    return this.config.store.destroyByUser(userId);
  }

  private async loadSession(ctx: WebContext) {
    const sid = ctx.cookies[this.config.cookieName];
    if (!sid) return null;
    // 不接受攻击者塞进来的异常格式：必须是我们自己签发的 base64url 32 字节形态
    if (!this.looksLikeOurSessionId(sid)) return null;
    const record = await this.config.store.get(sid);
    return record;
  }

  private checkTimeouts(
    record: { authenticatedAt: number | null; lastAccessAt: number },
    now: number,
  ): "idle" | "absolute" | null {
    if (
      record.authenticatedAt !== null &&
      now - record.authenticatedAt >= this.config.absoluteTimeoutMs
    ) {
      return "absolute";
    }
    if (now - record.lastAccessAt >= this.config.idleTimeoutMs) {
      return "idle";
    }
    return null;
  }

  private async createAnonymous(ctx: WebContext, now: number): Promise<SessionGuard> {
    const record = {
      id: generateSessionId(),
      userId: null,
      data: {},
      createdAt: now,
      lastAccessAt: now,
      authenticatedAt: null,
      csrfToken: null,
    };
    await this.config.store.save(record, this.config.idleTimeoutMs);
    const guard = new SessionGuard(ctx, this.config, record);
    if (this.config.csrf === "sync-token") {
      // 预生成 token，首个 GET 响应即可通过响应头交给前端
      guard.csrfToken();
    }
    return guard;
  }

  private requireGuard(ctx: WebContext): SessionGuard {
    if (!(ctx.guard instanceof SessionGuard)) {
      throw new Error("会话守卫未初始化（适配器未正确调用 engine.process）");
    }
    return ctx.guard;
  }

  private looksLikeOurSessionId(sid: string): boolean {
    // base64url，32 字节随机数编码后固定 43 字符
    return /^[A-Za-z0-9_-]{43}$/.test(sid);
  }

  private assertCookieNameSafety(): void {    const name = this.config.cookieName;
    if (this.config.allowInsecureLocal) return;
    if (!name.startsWith("__Host-")) {
      throw new Error(
        `生产环境会话 cookie 必须使用 __Host- 前缀（当前: ${name}）；` +
          "本地 http 开发请显式设置 allowInsecureLocal: true",
      );
    }
    if (name.includes("__Host-") && name.indexOf("__Host-") !== 0) {
      throw new Error("__Host- 前缀必须位于 cookie 名起始处");
    }
  }
}
