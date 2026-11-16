import type { Context, MiddlewareHandler, Next } from "hono";
import { parseCookies, type CookieAttrs, type WebContext } from "../http/context.js";
import { SessionEngine } from "../core/engine.js";
import { SessionError, SessionGuard } from "../core/guard.js";

/** Hono 变量类型增强：c.get("sessionGuard") 取守卫 */
export type SessionHonoVariables = {
  sessionGuard: SessionGuard;
  sessionExpired?: "idle" | "absolute";
};

class HonoContext implements WebContext {
  readonly method: string;
  readonly path: string;
  cookies: Record<string, string>;
  guard?: unknown;
  sessionExpired?: "idle" | "absolute";
  private bodyCache: Record<string, unknown> | null = null;

  constructor(private readonly c: Context) {
    this.method = c.req.method.toUpperCase();
    this.path = new URL(c.req.url).pathname;
    this.cookies = parseCookies(c.req.header("Cookie"));
  }

  header(name: string): string | undefined {
    return this.c.req.header(name);
  }

  /** 自序列化 Set-Cookie，行为与 Express 适配器完全一致 */
  setCookie(name: string, value: string, attrs: CookieAttrs): void {
    let out = `${name}=${encodeURIComponent(value)}`;
    if (attrs.maxAge !== undefined) out += `; Max-Age=${Math.floor(attrs.maxAge)}`;
    if (attrs.domain) out += `; Domain=${attrs.domain}`;
    out += `; Path=${attrs.path ?? "/"}`;
    if (attrs.secure) out += "; Secure";
    if (attrs.httpOnly !== false) out += "; HttpOnly";
    if (attrs.sameSite) out += `; SameSite=${attrs.sameSite}`;
    this.c.header("Set-Cookie", out, { append: true });
  }

  query(name: string): string | undefined {
    return this.c.req.query(name);
  }

  bodyField(name: string): unknown {
    return this.bodyCache?.[name];
  }

  async parseJsonBody(): Promise<void> {
    if (!this.c.req.header("content-type")?.includes("application/json")) return;
    try {
      this.bodyCache = await this.c.req.json<Record<string, unknown>>();
    } catch {
      // 非法 JSON 当作无 body；路由自身会处理解析错误
    }
  }
}

/**
 * Hono 中间件工厂。
 *
 * 用法：
 *   app.use("*", honoSession(engine));
 *   const guard = c.get("sessionGuard");
 *
 * 落库时机：await next() 之后、Hono 提交响应之前 await finalize，
 * 写顺序与请求顺序一致。
 */
export function honoSession(engine: SessionEngine): MiddlewareHandler {
  return async (c: Context, next: Next) => {
    const ctx = new HonoContext(c);
    await ctx.parseJsonBody();
    try {
      await engine.process(ctx);
      const guard = ctx.guard as SessionGuard;
      c.set("sessionGuard", guard);
      if (ctx.sessionExpired) c.set("sessionExpired", ctx.sessionExpired);

      if (engine.config.csrf === "sync-token") {
        c.header(engine.config.csrfHeaderName, guard.csrfToken());
      }

      await next();
      await engine.finalize(ctx);
      // login 轮转 CSRF token 后，重写响应头（Hono 对已 finalize 的响应仍允许改 header）
      const refresh = guard.consumeCsrfHeaderRefresh();
      if (refresh.stale) c.header(engine.config.csrfHeaderName, refresh.token);
    } catch (err) {
      if (err instanceof SessionError) {
        await engine.handleFailure(ctx, err);
        return c.json(
          {
            error: err.code,
            message: err.message,
            ...(ctx.sessionExpired ? { reason: ctx.sessionExpired } : {}),
          },
          err.status as 403,
        );
      }
      throw err;
    }
  };
}
