import assert from "node:assert/strict";
import { after, describe, it } from "node:test";
import express from "express";
import { Hono } from "hono";
import { serve } from "@hono/node-server";
import {
  MemoryStore,
  SessionEngine,
  expressSession,
  honoSession,
  type SessionHonoVariables,
} from "../src/index.js";

/**
 * 同一套安全断言同时跑 Express(sync-token) 与 Hono(double-submit)，
 * 证明两个适配器行为一致、两种 CSRF 模式都成立。
 */

interface Rig {
  base: string;
  csrfMode: "sync-token" | "double-submit";
  stop: () => Promise<void>;
  csrfFromResponse: (res: Response) => string;
}

/**
 * 模拟真实浏览器的 cookie 罐：自动吸收每个响应的 Set-Cookie，
 * 后续请求自动带 Cookie 头。会话 cookie 与 CSRF cookie 都会被保留。
 */
class BrowserJar {
  private values = new Map<string, string>();

  absorb(res: Response): void {
    for (const c of res.headers.getSetCookie?.() ?? []) {
      const pair = c.split(";")[0]!;
      const eq = pair.indexOf("=");
      const name = pair.slice(0, eq);
      const value = pair.slice(eq + 1);
      if (value === "") this.values.delete(name);
      else this.values.set(name, value);
    }
  }

  cookieHeader(): string {
    return [...this.values.entries()].map(([k, v]) => `${k}=${v}`).join("; ");
  }

  get(name: string): string | undefined {
    return this.values.get(name);
  }
}

function parseSetCookies(res: Response): Record<string, string> {
  const out: Record<string, string> = {};
  for (const c of res.headers.getSetCookie?.() ?? []) {
    const [pair] = c.split(";");
    const eq = pair!.indexOf("=");
    out[pair!.slice(0, eq)] = pair!.slice(eq + 1);
  }
  return out;
}

async function startExpress(): Promise<Rig> {
  const app = express();
  app.use(express.json());
  const engine = new SessionEngine({
    store: new MemoryStore(),
    csrf: "sync-token",
    idleTimeoutMs: 60_000,
    absoluteTimeoutMs: 120_000,
    maxSessionsPerUser: 2,
    allowInsecureLocal: true,
    csrfExemptPrefixes: ["/login"],
  });
  app.use(expressSession(engine));
  app.post("/login", async (req, res) => {
    const { username } = req.body as { username: string };
    await req.sessionGuard!.login(username);
    res.json({ ok: true });
  });
  app.post("/transfer", (req, res) => {
    if (!req.sessionGuard!.isAuthenticated()) return res.status(401).json({});
    req.sessionGuard!.set("moved", req.body);
    res.json({ ok: true });
  });
  app.post("/kick", async (_req, res) => {
    res.json({ kicked: await _req.sessionGuard!.kickOtherSessions() });
  });
  app.post("/logout", async (req, res) => {
    await req.sessionGuard!.logout();
    res.json({ ok: true });
  });
  const server = app.listen(0);
  await new Promise((r) => server.once("listening", r));
  const port = (server.address() as { port: number }).port;
  return {
    base: `http://127.0.0.1:${port}`,
    csrfMode: "sync-token",
    stop: () =>
      new Promise<void>((res) => server.close(() => res())),
    csrfFromResponse: (res) => res.headers.get("x-csrf-token") ?? "",
  };
}

async function startHono(): Promise<Rig> {
  const app = new Hono<{ Variables: SessionHonoVariables }>();
  const engine = new SessionEngine({
    store: new MemoryStore(),
    csrf: "double-submit",
    idleTimeoutMs: 60_000,
    absoluteTimeoutMs: 120_000,
    maxSessionsPerUser: 2,
    allowInsecureLocal: true,
    csrfExemptPrefixes: ["/login"],
  });
  app.use("*", honoSession(engine));
  app.post("/login", async (c) => {
    const body = await c.req.json();
    await c.get("sessionGuard").login(body.username);
    return c.json({ ok: true });
  });
  app.post("/transfer", async (c) => {
    const guard = c.get("sessionGuard");
    if (!guard.isAuthenticated()) return c.json({}, 401);
    guard.set("moved", await c.req.json());
    return c.json({ ok: true });
  });
  app.post("/kick", async (c) => c.json({ kicked: await c.get("sessionGuard").kickOtherSessions() }));
  app.post("/logout", async (c) => {
    await c.get("sessionGuard").logout();
    return c.json({ ok: true });
  });
  const server = serve({ fetch: app.fetch, port: 0 });
  const port = (server.address() as { port: number }).port;
  await new Promise((r) => server.once("listening", r));
  return {
    base: `http://127.0.0.1:${port}`,
    csrfMode: "double-submit",
    stop: () =>
      new Promise<void>((res) => server.close(() => res())),
    csrfFromResponse: (res) => parseSetCookies(res)["__Host-csrf.token"] ?? "",
  };
}

// describe/it 注册发生在模块加载的同步阶段，因此 rig 必须在顶层 await 阶段
// （注册之前）就启动好；不能放进 before 钩子——那时 for...of 已经跑完了。
const rigs: Array<{ name: string; rig: Rig }> = [
  { name: "Express+sync-token", rig: await startExpress() },
  { name: "Hono+double-submit", rig: await startHono() },
];

after(async () => {
  for (const { rig } of rigs) await rig.stop();
});

for (const { name, rig } of rigs) {
  describe(`适配器集成：${name}`, () => {
    it("首个请求下发会话 cookie，属性含 SameSite=Strict/HttpOnly/Path=/", async () => {
      const get = await fetch(rig.base);
      const setCookie = get.headers.getSetCookie?.().find((c) => c.includes("session.sid")) ?? "";
      assert.match(setCookie, /SameSite=Strict/);
      assert.match(setCookie, /HttpOnly/);
      assert.match(setCookie, /Path=\//);
      assert.match(setCookie, /__Host-session\.sid/);
    });

    it("完整登录-带 CSRF 操作-登出链路", async () => {
      const jar = new BrowserJar();

      // 1. 建匿名会话拿 CSRF
      const warm = await fetch(rig.base);
      jar.absorb(warm);
      const anonToken = rig.csrfFromResponse(warm);
      assert.ok(anonToken.length > 10);
      const beforeSid = jar.get("__Host-session.sid");

      // 2. 匿名会话无 token 打状态变更：CSRF 层先拦 403
      const noToken = await fetch(`${rig.base}/transfer`, {
        method: "POST",
        headers: { "content-type": "application/json", cookie: jar.cookieHeader() },
        body: JSON.stringify({ to: "x", amount: 1 }),
      });
      assert.equal(noToken.status, 403);

      // 3. 登录（豁免前缀），会话 ID 轮转
      const login = await fetch(`${rig.base}/login`, {
        method: "POST",
        headers: { "content-type": "application/json", cookie: jar.cookieHeader() },
        body: JSON.stringify({ username: "alice" }),
      });
      assert.equal(login.status, 200);
      jar.absorb(login);
      const afterSid = jar.get("__Host-session.sid");
      assert.ok(afterSid);
      assert.notEqual(afterSid, beforeSid, "登录必须轮转会话 ID");

      // 登录后两种模式都能从"下一个响应"拿到与当前会话匹配的 token
      const probe = await fetch(rig.base, { headers: { cookie: jar.cookieHeader() } });
      jar.absorb(probe);
      const token = rig.csrfFromResponse(probe);
      assert.ok(token.length > 10);

      // 4. 带正确 token 的操作通过
      const ok = await fetch(`${rig.base}/transfer`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          cookie: jar.cookieHeader(),
          "x-csrf-token": token,
        },
        body: JSON.stringify({ to: "bob", amount: 100 }),
      });
      assert.equal(ok.status, 200, await ok.text());

      // 5. 错误 token 仍被拒（已认证会话，纯 CSRF 403）
      const bad = await fetch(`${rig.base}/transfer`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          cookie: jar.cookieHeader(),
          "x-csrf-token": token.slice(0, -3) + "abc",
        },
        body: "{}",
      });
      assert.equal(bad.status, 403);

      // 6. 登出：服务端记录销毁，cookie 被清
      const logout = await fetch(`${rig.base}/logout`, {
        method: "POST",
        headers: { cookie: jar.cookieHeader(), "x-csrf-token": token },
      });
      assert.equal(logout.status, 200);
      jar.absorb(logout);
      assert.equal(jar.get("__Host-session.sid"), undefined, "登出应清除会话 cookie");
    });

    it("并发会话上限：第三个登录挤掉第一个", async () => {
      const jars: BrowserJar[] = [];
      for (let i = 0; i < 3; i++) {
        const jar = new BrowserJar();
        const warm = await fetch(rig.base);
        jar.absorb(warm);
        const login = await fetch(`${rig.base}/login`, {
          method: "POST",
          headers: { "content-type": "application/json", cookie: jar.cookieHeader() },
          body: JSON.stringify({ username: "multi" }),
        });
        assert.equal(login.status, 200);
        jar.absorb(login);
        jars.push(jar);
      }

      // 被挤掉的旧会话：GET 时引擎建立匿名新会话并下发新 cookie，
      // jar 吸收后带它自己的有效 CSRF 打 transfer —— CSRF 过、认证不过 -> 401
      const victimJar = jars[0]!;
      const victimWarm = await fetch(rig.base, { headers: { cookie: victimJar.cookieHeader() } });
      victimJar.absorb(victimWarm);
      const victimToken = rig.csrfFromResponse(victimWarm);
      const victim = await fetch(`${rig.base}/transfer`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          cookie: victimJar.cookieHeader(),
          "x-csrf-token": victimToken,
        },
        body: "{}",
      });
      assert.equal(victim.status, 401, "最老会话应已被挤下线");

      // 最新会话仍然有效
      const aliveJar = jars[2]!;
      const warm3 = await fetch(rig.base, { headers: { cookie: aliveJar.cookieHeader() } });
      aliveJar.absorb(warm3);
      const t3 = rig.csrfFromResponse(warm3);
      const alive = await fetch(`${rig.base}/transfer`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          cookie: aliveJar.cookieHeader(),
          "x-csrf-token": t3,
        },
        body: "{}",
      });
      assert.equal(alive.status, 200);
    });

    it("一键踢下线：当前会话保留，其它同账号会话失效", async () => {
      const jarA = new BrowserJar();
      const warmA = await fetch(rig.base);
      jarA.absorb(warmA);
      const loginA = await fetch(`${rig.base}/login`, {
        method: "POST",
        headers: { "content-type": "application/json", cookie: jarA.cookieHeader() },
        body: JSON.stringify({ username: "kickme" }),
      });
      jarA.absorb(loginA);

      const jarB = new BrowserJar();
      const warmB = await fetch(rig.base);
      jarB.absorb(warmB);
      const loginB = await fetch(`${rig.base}/login`, {
        method: "POST",
        headers: { "content-type": "application/json", cookie: jarB.cookieHeader() },
        body: JSON.stringify({ username: "kickme" }),
      });
      jarB.absorb(loginB);

      // B 取当前 token 后执行踢下线
      const probeB = await fetch(rig.base, { headers: { cookie: jarB.cookieHeader() } });
      jarB.absorb(probeB);
      const tokenB = rig.csrfFromResponse(probeB);
      const kick = await fetch(`${rig.base}/kick`, {
        method: "POST",
        headers: { cookie: jarB.cookieHeader(), "x-csrf-token": tokenB },
      });
      const kickBody = (await kick.clone().json()) as { kicked: number };
      assert.equal(kick.status, 200, JSON.stringify(kickBody));
      jarB.absorb(kick);
      assert.equal(kickBody.kicked, 1);

      // A 已失效：吸收 A 的匿名新会话后，CSRF 过、认证不过 -> 401
      const probeA = await fetch(rig.base, { headers: { cookie: jarA.cookieHeader() } });
      jarA.absorb(probeA);
      const tokenA = rig.csrfFromResponse(probeA);
      const aCheck = await fetch(`${rig.base}/transfer`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          cookie: jarA.cookieHeader(),
          "x-csrf-token": tokenA,
        },
        body: "{}",
      });
      assert.equal(aCheck.status, 401);

      // B 仍存活（踢下线会重发 CSRF cookie，jar 已吸收；token 本身不变）
      const bCheck = await fetch(`${rig.base}/transfer`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          cookie: jarB.cookieHeader(),
          "x-csrf-token": tokenB,
        },
        body: "{}",
      });
      assert.equal(bCheck.status, 200);
    });
  });
}
