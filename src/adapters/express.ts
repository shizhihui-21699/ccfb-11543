/**
 * Express 适配器：把 IncomingMessage/ServerResponse 翻译成引擎的中性接口。
 *
 * 用法：
 *   app.use(sessionMiddleware(engine));
 *   app.post('/login', async (req, res) => {
 *     await req.session.login('u1');
 *     res.json({ csrfToken: req.session.csrfToken });
 *   });
 *
 * 收尾时机：必须在响应头刷新到 socket 之前完成 finalize（Set-Cookie 才随响应发出）。
 * Express 的 finish 事件发生在响应发送之后，太晚；因此包装 res.end / res.writeHead，
 * 在第一次真正发送前 await 一次 finalize，并用标志保证幂等。
 */
import type { NextFunction, Request, Response } from 'express';
import { SessionEngine } from '../engine.js';
import type { FrameworkRequest, FrameworkResponse } from '../engine.js';

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      session: import('../types.js').SessionHandle;
      sessionTimedOut: 'idle' | 'absolute' | null;
    }
  }
}

function toFrameworkRequest(req: Request): FrameworkRequest {
  return {
    cookieHeader: () => req.headers.cookie,
    header: (name) => {
      const v = req.headers[name.toLowerCase()];
      return Array.isArray(v) ? v[0] : v;
    },
    bodyField: (name) =>
      req.body && typeof req.body === 'object' ? req.body[name] : undefined,
    method: () => req.method,
  };
}

function toFrameworkResponse(res: Response): FrameworkResponse {
  return {
    appendSetCookie: (cookie) => {
      const existing = res.getHeader('set-cookie');
      const list = Array.isArray(existing)
        ? [...existing]
        : existing !== undefined
          ? [String(existing)]
          : [];
      list.push(cookie);
      res.setHeader('set-cookie', list);
    },
  };
}

export function sessionMiddleware(engine: SessionEngine) {
  return (req: Request, res: Response, next: NextFunction): void => {
    void (async () => {
      try {
        const result = await engine.process(toFrameworkRequest(req));
        req.session = result.handle;
        req.sessionTimedOut = result.timedOut;

        if (result.csrfFailed) {
          await engine.finalize(toFrameworkResponse(res), result.handle);
          if (!res.headersSent) {
            res.status(403).json({
              error: 'csrf_rejected',
              reason: result.csrfFailureReason,
            });
          }
          return;
        }

        let finalizePromise: Promise<void> | null = null;
        const ensureFinalized = (): Promise<void> => {
          if (!finalizePromise) {
            finalizePromise = engine
              .isLoggedOut(result.handle)
              ? engine.finalize(toFrameworkResponse(res), result.handle, {
                  clear: true,
                })
              : engine.finalize(toFrameworkResponse(res), result.handle);
            finalizePromise.catch((err) => {
              req.app?.emit?.('session-finalize-error', err);
            });
          }
          return finalizePromise;
        };

        // 包装 res.end：所有正常响应路径（res.json/send/end）最终都经过它。
        // 在原始 end 执行前 await finalize，确保 Set-Cookie 已在 header 上。
        const originalEnd = res.end.bind(res) as Response['end'];
        res.end = ((...args: unknown[]) => {
          // res.end 可能被同步调用；统一转成异步链，finalize 完成后再真正结束
          ensureFinalized().finally(() => {
            // @ts-expect-error 透传原始可变参数
            originalEnd(...args);
          });
        }) as Response['end'];

        // 连接提前中断（客户端断开）也要保证 touch 至少执行一次
        res.once('close', () => {
          if (!res.writableEnded) void ensureFinalized();
        });

        next();
      } catch (err) {
        next(err as Error);
      }
    })();
  };
}
