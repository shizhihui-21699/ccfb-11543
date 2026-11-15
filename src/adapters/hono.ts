/**
 * Hono 适配器（Node 服务端场景；同一套引擎也可用于 Hono 的其它 runtime）。
 *
 * 用法：
 *   const app = new Hono();
 *   app.use('*', sessionMiddleware(engine));
 *   app.post('/login', async (c) => {
 *     const session = c.get('session');
 *     await session.login('u1');
 *     return c.json({ csrfToken: session.csrfToken });
 *   });
 */
import type { Context, Next } from 'hono';
import { SessionEngine } from '../engine.js';
import type { FrameworkRequest, FrameworkResponse } from '../engine.js';

export const SESSION_HANDLE_KEY = 'session' as const;
export const SESSION_TIMEOUT_KEY = 'sessionTimedOut' as const;

function toFrameworkRequest(c: Context): FrameworkRequest {
  return {
    cookieHeader: () => c.req.header('cookie'),
    header: (name) => c.req.header(name) ?? undefined,
    bodyField: (name) => {
      // Hono 的 body 是异步解析的；中间件里不提前消费 body，
      // 仅当业务已经 parse 过（挂在 env 上的缓存）才读取。
      const cached = (c.req as unknown as { __parsedBody?: Record<string, unknown> })
        .__parsedBody;
      return cached?.[name];
    },
    method: () => c.req.method,
  };
}

function toFrameworkResponse(c: Context): FrameworkResponse {
  return {
    appendSetCookie: (cookie) => c.header('set-cookie', cookie, { append: true }),
  };
}

export function sessionMiddleware(engine: SessionEngine) {
  return async (c: Context, next: Next): Promise<Response | void> => {
    const result = await engine.process(toFrameworkRequest(c));
    c.set(SESSION_HANDLE_KEY, result.handle);
    c.set(SESSION_TIMEOUT_KEY, result.timedOut);

    if (result.csrfFailed) {
      await engine.finalize(toFrameworkResponse(c), result.handle);
      return c.json(
        { error: 'csrf_rejected', reason: result.csrfFailureReason },
        403,
      );
    }

    try {
      await next();
    } finally {
      if (engine.isLoggedOut(result.handle)) {
        await engine.finalize(toFrameworkResponse(c), result.handle, {
          clear: true,
        });
      } else {
        await engine.finalize(toFrameworkResponse(c), result.handle);
      }
    }
  };
}

/**
 * 业务路由读取表单字段做 CSRF 双提交校验时的辅助：
 * Hono 下推荐用 header 传 token（c.req.header('x-csrf-token')），
 * 需要 body 字段时用本函数解析并缓存，避免重复消费 body 流。
 */
export async function parseJsonBodyOnce(
  c: Context,
): Promise<Record<string, unknown>> {
  const req = c.req as unknown as {
    __parsedBody?: Record<string, unknown>;
  };
  if (!req.__parsedBody) {
    req.__parsedBody = ((await c.req.json().catch(() => ({}))) ?? {}) as Record<
      string,
      unknown
    >;
  }
  return req.__parsedBody;
}
