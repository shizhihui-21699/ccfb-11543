import type { NextFunction, Request, Response } from "express";
import { parseCookies, serializeCookie, type CookieAttrs, type WebContext } from "../http/context.js";
import { SessionEngine } from "../core/engine.js";
import { SessionError, SessionGuard } from "../core/guard.js";

declare module "express-serve-static-core" {
  interface Request {
    sessionGuard?: SessionGuard;
    sessionExpired?: "idle" | "absolute";
  }
}

/** Express 适配：把 req/res 翻译成引擎认识的 WebContext */
class ExpressContext implements WebContext {
  readonly method: string;
  readonly path: string;
  cookies: Record<string, string>;
  guard?: unknown;
  sessionExpired?: "idle" | "absolute";

  constructor(
    private readonly req: Request,
    private readonly res: Response,
  ) {
    this.method = req.method.toUpperCase();
    this.path = req.path;
    this.cookies = parseCookies(req.headers.cookie);
  }

  header(name: string): string | undefined {
    return this.req.header(name);
  }

  setCookie(name: string, value: string, attrs: CookieAttrs): void {
    this.res.append("Set-Cookie", serializeCookie(name, value, attrs));
  }

  query(name: string): string | undefined {
    const v = this.req.query[name];
    return typeof v === "string" ? v : undefined;
  }

  bodyField(name: string): unknown {
    return this.req.body?.[name];
  }
}

/**
 * Express 中间件工厂。
 *
 * 用法：
 *   app.use(expressSession(engine));
 *   app.post("/login", async (req, res) => {
 *     await req.sessionGuard!.login(uid);
 *     res.json({ ok: true });
 *   });
 *
 * 落库时机：包装 res.end —— 路由处理完成后、响应字节真正发出前 await finalize，
 * 保证同一会话连续请求的写顺序与其到达顺序一致，不出现 touch/login 互相覆盖。
 */
export function expressSession(engine: SessionEngine) {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    const ctx = new ExpressContext(req, res);
    try {
      await engine.process(ctx);
      const guard = ctx.guard as SessionGuard;
      req.sessionGuard = guard;
      req.sessionExpired = ctx.sessionExpired;

      if (engine.config.csrf === "sync-token") {
        res.setHeader(engine.config.csrfHeaderName, guard.csrfToken());
      }

      const originalEnd = res.end;
      res.end = function (this: Response, ...args: never[]): Response {
        // 恢复原始 end 防止重入；finalize 完成后再真正结束响应
        res.end = originalEnd;
        void engine
          .finalize(ctx)
          .then(() => {
            // login 可能轮转了 CSRF token：process 阶段写的响应头已过期，这里重写
            const refresh = guard.consumeCsrfHeaderRefresh();
            if (refresh.stale) res.setHeader(engine.config.csrfHeaderName, refresh.token);
          })
          .catch((err) => console.error("会话 finalize 失败:", err))
          .finally(() => {
            (originalEnd as (...a: unknown[]) => Response).apply(res, args);
          });
        return res;
      } as Response["end"];

      next();
    } catch (err) {
      if (err instanceof SessionError) {
        await engine.handleFailure(ctx, err);
        res.status(err.status).json({
          error: err.code,
          message: err.message,
          ...(ctx.sessionExpired ? { reason: ctx.sessionExpired } : {}),
        });
        return;
      }
      next(err);
    }
  };
}
