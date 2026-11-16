/**
 * 加固站 C：Express + sync-token + Redis 存储。
 *
 * 与加固站 A 的唯一差别是存储后端 —— 证明 SessionStore 抽象可插拔，
 * 引擎与适配器代码一行不改即可从内存切到 Redis（多实例部署形态）。
 *
 * 需要本机 redis-server；端口可用 REDIS_PORT 覆盖。
 */
import express from "express";
import {
  RedisStore,
  SessionEngine,
  expressSession,
} from "../../src/index.js";

const app = express();
app.use(express.json());

const store = new RedisStore({
  clientOptions: {
    host: process.env.REDIS_HOST ?? "127.0.0.1",
    port: Number(process.env.REDIS_PORT ?? 6379),
  },
});
await store.connect();

const engine = new SessionEngine({
  store,
  csrf: "sync-token",
  idleTimeoutMs: 15 * 60 * 1000,
  absoluteTimeoutMs: 2 * 60 * 60 * 1000,
  maxSessionsPerUser: 3,
  allowInsecureLocal: true,
  csrfExemptPrefixes: ["/login"],
});

app.use(expressSession(engine));

app.get("/", (_req, res) => res.json({ app: "secure-express-redis", store: store.name }));

app.post("/login", async (req, res, next) => {
  try {
    const { username, password } = req.body as { username?: string; password?: string };
    if (!username || password !== "pw") {
      res.status(401).json({ error: "bad credentials" });
      return;
    }
    await req.sessionGuard!.login(username);
    res.json({ ok: true, userId: username });
  } catch (err) {
    next(err);
  }
});

app.get("/me", (req, res) => {
  const guard = req.sessionGuard!;
  res.json({ authenticated: guard.isAuthenticated(), userId: guard.userId });
});

app.post("/transfer", async (req, res, next) => {
  try {
    const guard = req.sessionGuard!;
    if (!guard.isAuthenticated()) {
      res.status(401).json({ error: "unauthenticated" });
      return;
    }
    guard.set("lastTransfer", req.body);
    res.json({ ok: true });
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

const PORT = Number(process.env.PORT ?? 4104);
const server = app.listen(PORT, () => {
  console.log(`[secure-express-redis] Redis 加固站监听 http://127.0.0.1:${PORT}`);
});

export { app, server, engine, store };
