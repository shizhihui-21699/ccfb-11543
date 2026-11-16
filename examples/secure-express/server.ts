/**
 * 加固站 A：Express + 同步令牌 CSRF + 内存存储。
 *
 * 安全配置一览：
 *  - __Host- 前缀 cookie（本地 http 开发显式 allowInsecureLocal 才放宽）
 *  - SameSite=Strict + HttpOnly
 *  - 登录即轮转会话 ID，旧 ID 立即销毁（防会话固定）
 *  - CSRF sync-token：token 存服务端，响应头 x-csrf-token 下发，
 *    不安全方法必须回传，常量时间比较
 *  - 空闲 15 分钟 / 绝对 2 小时，分别计时
 *  - 同账号最多 3 个并发会话，超出挤掉最老的
 */
import express from "express";
import {
  MemoryStore,
  SessionEngine,
  expressSession,
} from "../../src/index.js";

const app = express();
app.use(express.json());

const engine = new SessionEngine({
  store: new MemoryStore(),
  csrf: "sync-token",
  idleTimeoutMs: 15 * 60 * 1000,
  absoluteTimeoutMs: 2 * 60 * 60 * 1000,
  maxSessionsPerUser: 3,
  // 仅本地 http 演示用；生产（https）删除此项，引擎会强制 __Host 校验
  allowInsecureLocal: true,
  csrfExemptPrefixes: ["/login"],
});

app.use(expressSession(engine));

app.get("/", (_req, res) => {
  res.json({ app: "secure-express", csrf: "sync-token" });
});

app.post("/login", async (req, res, next) => {
  try {
    const { username, password } = req.body as { username?: string; password?: string };
    if (!username || password !== "pw") {
      res.status(401).json({ error: "bad credentials" });
      return;
    }
    // 关键：login 内部销毁旧会话、签发全新 ID、重置绝对超时
    await req.sessionGuard!.login(username, { loginCount: 1 });
    res.json({ ok: true, userId: username });
  } catch (err) {
    next(err);
  }
});

app.get("/me", (req, res) => {
  const guard = req.sessionGuard!;
  res.json({
    authenticated: guard.isAuthenticated(),
    userId: guard.userId,
    data: guard.data,
    // 同步令牌也显式暴露一个查询入口，方便脚本演示
    csrfToken: guard.csrfToken(),
  });
});

app.post("/transfer", async (req, res, next) => {
  try {
    const guard = req.sessionGuard!;
    if (!guard.isAuthenticated()) {
      res.status(401).json({ error: "unauthenticated" });
      return;
    }
    const { to, amount } = req.body as { to?: string; amount?: number };
    guard.set("lastTransfer", { to, amount });
    res.json({ ok: true, transferred: { to, amount } });
  } catch (err) {
    next(err);
  }
});

app.get("/sessions", async (req, res, next) => {
  try {
    const guard = req.sessionGuard!;
    if (!guard.userId) {
      res.status(401).json({ error: "unauthenticated" });
      return;
    }
    const all = await engine.listSessions(guard.userId);
    res.json({
      count: all.length,
      sessions: all.map((s) => ({
        id: s.id.slice(0, 12) + "…",
        createdAt: s.createdAt,
        lastAccessAt: s.lastAccessAt,
        current: s.id === guard.sessionId,
      })),
    });
  } catch (err) {
    next(err);
  }
});

app.post("/kick", async (req, res, next) => {
  try {
    const guard = req.sessionGuard!;
    if (!guard.userId) {
      res.status(401).json({ error: "unauthenticated" });
      return;
    }
    const kicked = await guard.kickOtherSessions();
    res.json({ ok: true, kicked });
  } catch (err) {
    next(err);
  }
});

app.post("/logout", async (req, res, next) => {
  try {
    await req.sessionGuard!.logout();
    res.json({ ok: true });
  } catch (err) {
    next(err);
  }
});

const PORT = Number(process.env.PORT ?? 4102);
const server = app.listen(PORT, () => {
  console.log(`[secure-express] 加固站（sync-token）监听 http://127.0.0.1:${PORT}`);
});

export { app, server, engine };
