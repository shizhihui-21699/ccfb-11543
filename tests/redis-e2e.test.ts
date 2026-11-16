import assert from "node:assert/strict";
import type { Server } from "node:http";
import { after, describe, it } from "node:test";
import express from "express";
import {
  RedisStore,
  SessionEngine,
  expressSession,
} from "../src/index.js";
import { startRedis, type RedisFixture } from "./redis-fixture.js";

/**
 * 引擎 + Express 适配器 + 真实 Redis 存储的端到端测试，
 * 覆盖存储可插拔性、轮转、CSRF、并发上限在 Redis 上的真实表现。
 */
describe("Redis 后端端到端（真实 redis-server + HTTP）", () => {
  let fixture: RedisFixture | null = null;
  let store: RedisStore;
  let server: Server;
  let base: string;
  let rawClient: import("../src/stores/redis-client.js").RedisClient;

  const jar = (res: Response) =>
    (res.headers.getSetCookie?.() ?? []).map((c) => c.split(";")[0]!).join("; ");

  after(async () => {
    await new Promise<void>((res) => server?.close(() => res()));
    await store?.close();
    await rawClient?.close();
    await fixture?.stop();
  });

  it("完整链路：登录轮转 + CSRF + 并发上限 + Redis 键验证", async (t) => {
    fixture = await startRedis();
    if (!fixture) {
      t.skip("本机无 redis-server");
      return;
    }

    store = new RedisStore({ clientOptions: { port: fixture.port } });
    await store.connect();
    const { RedisClient } = await import("../src/stores/redis-client.js");
    rawClient = new RedisClient({ port: fixture.port });
    await rawClient.connect();

    const app = express();
    app.use(express.json());
    const engine = new SessionEngine({
      store,
      csrf: "sync-token",
      idleTimeoutMs: 60_000,
      absoluteTimeoutMs: 120_000,
      maxSessionsPerUser: 2,
      allowInsecureLocal: true,
      csrfExemptPrefixes: ["/login"],
    });
    app.use(expressSession(engine));
    app.post("/login", async (req, res) => {
      await req.sessionGuard!.login(req.body.username);
      res.json({ ok: true });
    });
    app.post("/transfer", (req, res) => {
      if (!req.sessionGuard!.isAuthenticated()) return res.status(401).json({});
      res.json({ ok: true });
    });

    server = app.listen(0);
    await new Promise((r) => server.once("listening", r));
    base = `http://127.0.0.1:${(server.address() as { port: number }).port}`;

    // 匿名会话
    const warm = await fetch(base);
    const warmCookie = jar(warm);
    const anonToken = warm.headers.get("x-csrf-token")!;
    assert.ok(anonToken.length > 10);

    // Redis 里确实有会话键与用户集合尚未建立（匿名）
    const warmSid = warmCookie.split("=")[1]!;
    assert.equal(await rawClient.send(["EXISTS", `sg:session:${warmSid}`]), 1);

    // 无 token 被 CSRF 拦截
    const blocked = await fetch(`${base}/transfer`, {
      method: "POST",
      headers: { "content-type": "application/json", cookie: warmCookie },
      body: "{}",
    });
    assert.equal(blocked.status, 403);

    // 登录轮转
    const login = await fetch(`${base}/login`, {
      method: "POST",
      headers: { "content-type": "application/json", cookie: warmCookie },
      body: JSON.stringify({ username: "redis-user" }),
    });
    assert.equal(login.status, 200);
    const authCookie = jar(login);
    const newSid = authCookie.split("=")[1]!;
    assert.notEqual(newSid, warmSid);
    // 旧键已从 Redis 删除
    assert.equal(await rawClient.send(["EXISTS", `sg:session:${warmSid}`]), 0);
    // 用户集合已建立
    assert.equal(await rawClient.send(["EXISTS", "sg:user:redis-user"]), 1);

    // 用新 token 操作成功
    const token = login.headers.get("x-csrf-token")!;
    const ok = await fetch(`${base}/transfer`, {
      method: "POST",
      headers: { "content-type": "application/json", cookie: authCookie, "x-csrf-token": token },
      body: "{}",
    });
    assert.equal(ok.status, 200);

    // 并发上限 = 2：上面已有 1 个登录会话，再登录 2 次（共 3 个），
    // 最老的 newSid 应被 Lua 脚本原子淘汰，只剩后两个
    const sids: string[] = [newSid];
    for (let i = 0; i < 2; i++) {
      const w = await fetch(base);
      const l = await fetch(`${base}/login`, {
        method: "POST",
        headers: { "content-type": "application/json", cookie: jar(w) },
        body: JSON.stringify({ username: "redis-user" }),
      });
      assert.equal(l.status, 200);
      sids.push(jar(l).split("=")[1]!);
    }
    const members = (await rawClient.send(["SMEMBERS", "sg:user:redis-user"])) as string[];
    assert.equal(members.length, 2, "Redis 用户集合应只剩 2 个会话");
    assert.equal(members.includes(sids[0]!), false, "最老会话应已被 Lua 脚本淘汰");
    assert.equal(members.includes(sids[1]!), true);
    assert.equal(members.includes(sids[2]!), true);
    // 被淘汰会话的 session 键也应被 DEL
    assert.equal(await rawClient.send(["EXISTS", `sg:session:${sids[0]}`]), 0);
  });
});
