/**
 * 加固站 B：Hono + 双提交 CSRF + 内存存储。
 *
 * 与加固站 A 的差异仅在 CSRF 模式：
 *  - double-submit：服务端不存 token，下发一个可读 cookie（无 HttpOnly），
 *    前端请求时把同样的值放进 x-csrf-token 头，中间件常量时间比较两处是否一致。
 *    攻击者受同源策略限制读不到 cookie，自然无法构造匹配的头。
 *  - 会话 cookie 仍是 __Host + SameSite=Strict + HttpOnly。
 */
import { Hono } from "hono";
import { serve } from "@hono/node-server";
import {
  MemoryStore,
  SessionEngine,
  honoSession,
  type SessionHonoVariables,
} from "../../src/index.js";

const app = new Hono<{ Variables: SessionHonoVariables }>();

const engine = new SessionEngine({
  store: new MemoryStore(),
  csrf: "double-submit",
  idleTimeoutMs: 15 * 60 * 1000,
  absoluteTimeoutMs: 2 * 60 * 60 * 1000,
  maxSessionsPerUser: 3,
  allowInsecureLocal: true,
  csrfExemptPrefixes: ["/login"],
});

app.use("*", honoSession(engine));

app.get("/", (c) => c.json({ app: "secure-hono", csrf: "double-submit" }));

app.post("/login", async (c) => {
  const body = (await c.req.json().catch(() => ({}))) as {
    username?: string;
    password?: string;
  };
  if (!body.username || body.password !== "pw") {
    return c.json({ error: "bad credentials" }, 401);
  }
  const guard = c.get("sessionGuard");
  await guard.login(body.username, { loginCount: 1 });
  return c.json({ ok: true, userId: body.username });
});

app.get("/me", (c) => {
  const guard = c.get("sessionGuard");
  return c.json({
    authenticated: guard.isAuthenticated(),
    userId: guard.userId,
    data: guard.data,
    csrfCookie: c.req.header("Cookie")?.match(/__Host-csrf\.token=([^;]+)/)?.[1] ?? null,
  });
});

app.post("/transfer", async (c) => {
  const guard = c.get("sessionGuard");
  if (!guard.isAuthenticated()) return c.json({ error: "unauthenticated" }, 401);
  const body = (await c.req.json().catch(() => ({}))) as { to?: string; amount?: number };
  guard.set("lastTransfer", { to: body.to, amount: body.amount });
  return c.json({ ok: true, transferred: { to: body.to, amount: body.amount } });
});

app.get("/sessions", async (c) => {
  const guard = c.get("sessionGuard");
  if (!guard.userId) return c.json({ error: "unauthenticated" }, 401);
  const all = await engine.listSessions(guard.userId);
  return c.json({
    count: all.length,
    sessions: all.map((s) => ({
      id: s.id.slice(0, 12) + "…",
      createdAt: s.createdAt,
      lastAccessAt: s.lastAccessAt,
      current: s.id === guard.sessionId,
    })),
  });
});

app.post("/kick", async (c) => {
  const guard = c.get("sessionGuard");
  if (!guard.userId) return c.json({ error: "unauthenticated" }, 401);
  const kicked = await guard.kickOtherSessions();
  return c.json({ ok: true, kicked });
});

app.post("/logout", async (c) => {
  const guard = c.get("sessionGuard");
  await guard.logout();
  return c.json({ ok: true });
});

const PORT = Number(process.env.PORT ?? 4103);
const server = serve({ fetch: app.fetch, port: PORT }, (info) => {
  console.log(`[secure-hono] 加固站（double-submit）监听 http://127.0.0.1:${info.port}`);
});

export { app, server, engine };
