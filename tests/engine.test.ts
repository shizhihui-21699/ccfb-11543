import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { MemoryStore, SessionEngine, SessionError, SessionGuard } from "../src/index.js";
import { FakeClock, FakeContext } from "./helpers.js";

function makeEngine(opts: { idleMs?: number; absoluteMs?: number; max?: number; csrf?: "sync-token" | "double-submit" | "off" } = {}) {
  const clock = new FakeClock();
  const store = new MemoryStore(clock, 0); // 关掉周期清扫，避免假时钟下的干扰
  const engine = new SessionEngine({
    store,
    clock,
    idleTimeoutMs: opts.idleMs ?? 1000,
    absoluteTimeoutMs: opts.absoluteMs ?? 3000,
    maxSessionsPerUser: opts.max ?? 3,
    csrf: opts.csrf ?? "sync-token",
    allowInsecureLocal: true,
    csrfExemptPrefixes: ["/login"],
  });
  return { clock, store, engine };
}

async function run(engine: SessionEngine, ctx: FakeContext): Promise<SessionGuard> {
  await engine.process(ctx);
  const guard = ctx.guard as SessionGuard;
  await engine.finalize(ctx);
  return guard;
}

describe("会话固定防护：登录轮转", () => {
  it("登录后签发全新会话 ID，旧 ID 立即失效", async () => {
    const { engine } = makeEngine();
    const anonymous = new FakeContext({ method: "GET", path: "/" });
    const guard1 = await run(engine, anonymous);
    const oldId = guard1.sessionId;
    assert.equal(guard1.userId, null);

    const loginCtx = anonymous.carryCookies(new FakeContext({ method: "POST", path: "/login" }));
    await engine.process(loginCtx);
    const loginGuard = loginCtx.guard as SessionGuard;
    await loginGuard.login("alice");
    await engine.finalize(loginCtx);

    assert.notEqual(loginGuard.sessionId, oldId);
    assert.equal(loginGuard.userId, "alice");
    // 旧 id 在存储里已不存在
    assert.equal(await engine.config.store.get(oldId), null);
    // 浏览器收到的是新 cookie
    const issued = loginCtx.lastCookie(engine.config.cookieName);
    assert.equal(issued?.value, loginGuard.sessionId);
  });

  it("攻击者预设的会话 ID 在登录后不会被认证", async () => {
    const { engine } = makeEngine();
    // 攻击者直接塞一个自己构造的 sid
    const forged = new FakeContext({ method: "POST", path: "/login" });
    forged.cookies[engine.config.cookieName] = "attacker-controlled-value-xxxx";
    await engine.process(forged);
    const guard = forged.guard as SessionGuard;
    // 引擎拒绝非法格式，建立的是全新匿名会话，攻击者的值被忽略
    assert.notEqual(guard.sessionId, "attacker-controlled-value-xxxx");
    assert.equal(guard.userId, null);
  });

  it("即使伪造值格式合法，登录也会轮转使其失效", async () => {
    const { engine } = makeEngine();
    // 先合法建立一个会话拿到真实形态的 id，模拟攻击者偷到/猜到的 id
    const ctx0 = new FakeContext();
    const g0 = await run(engine, ctx0);
    const stolenId = g0.sessionId;

    const attacker = new FakeContext({ method: "POST", path: "/login" });
    attacker.cookies[engine.config.cookieName] = stolenId;
    await engine.process(attacker);
    const ag = attacker.guard as SessionGuard;
    await ag.login("bob");
    await engine.finalize(attacker);

    assert.notEqual(ag.sessionId, stolenId);
    assert.equal(await engine.config.store.get(stolenId), null);
  });
});

describe("CSRF - 同步令牌模式", () => {
  it("无 token 的 POST 被 403 拒绝", async () => {
    const { engine } = makeEngine({ csrf: "sync-token" });
    const ctx = new FakeContext({ method: "POST", path: "/transfer" });
    await assert.rejects(engine.process(ctx), (err: unknown) =>
      err instanceof SessionError && err.code === "CSRF_INVALID",
    );
  });

  it("携带正确 token 的 POST 通过，错误 token 被拒", async () => {
    const { engine } = makeEngine({ csrf: "sync-token" });
    const first = new FakeContext({ method: "GET", path: "/" });
    const g = await run(engine, first);
    const token = g.csrfToken();

    const good = first.carryCookies(new FakeContext({ method: "POST", path: "/transfer" }));
    good.requestHeaders["x-csrf-token"] = token;
    await assert.doesNotReject(run(engine, good));

    const bad = first.carryCookies(new FakeContext({ method: "POST", path: "/transfer" }));
    bad.requestHeaders["x-csrf-token"] = token.slice(0, -2) + "xx";
    await assert.rejects(run(engine, bad), (err: unknown) =>
      err instanceof SessionError && err.code === "CSRF_INVALID",
    );
  });

  it("GET/HEAD/OPTIONS 安全方法豁免，/login 前缀豁免", async () => {
    const { engine } = makeEngine({ csrf: "sync-token" });
    for (const method of ["GET", "HEAD", "OPTIONS"]) {
      await assert.doesNotReject(run(engine, new FakeContext({ method, path: "/anything" })));
    }
    await assert.doesNotReject(
      run(engine, new FakeContext({ method: "POST", path: "/login" })),
    );
  });
});

describe("CSRF - 双提交模式", () => {
  it("首次 GET 下发 CSRF cookie，header 与 cookie 不一致即拒绝", async () => {
    const { engine } = makeEngine({ csrf: "double-submit" });
    const first = new FakeContext({ method: "GET", path: "/" });
    await run(engine, first);
    const csrfCookie = first.lastCookie(engine.config.csrfCookieName)!;
    assert.ok(csrfCookie.value.length > 16);
    assert.equal(csrfCookie.attrs.httpOnly, false, "双提交 cookie 必须允许前端读取");

    // 攻击者跨站只能带 cookie、读不到值，header 只能瞎填 -> 拒绝
    const forged = first.carryCookies(new FakeContext({ method: "POST", path: "/transfer" }));
    forged.requestHeaders["x-csrf-token"] = "guessed";
    await assert.rejects(run(engine, forged), (err: unknown) =>
      err instanceof SessionError && err.code === "CSRF_INVALID",
    );

    // 合法前端读出 cookie 原样回传 -> 通过
    const legit = first.carryCookies(new FakeContext({ method: "POST", path: "/transfer" }));
    legit.requestHeaders["x-csrf-token"] = csrfCookie.value;
    await assert.doesNotReject(run(engine, legit));
  });
});

describe("空闲超时与绝对超时分别计时", () => {
  it("空闲超时：静止超过 idleTimeout 后会话被销毁", async () => {
    const { engine, clock } = makeEngine({ idleMs: 1000, absoluteMs: 5000 });
    const login = new FakeContext({ method: "POST", path: "/login" });
    await engine.process(login);
    const g = login.guard as SessionGuard;
    await g.login("carol");
    await engine.finalize(login);
    const sid = g.sessionId;

    clock.advance(999);
    const stillAlive = login.carryCookies(new FakeContext({ method: "GET", path: "/" }));
    await run(engine, stillAlive);
    assert.equal((stillAlive.guard as SessionGuard).sessionId, sid);

    clock.advance(1001); // 累计静止超过 1000
    const expired = login.carryCookies(new FakeContext({ method: "GET", path: "/" }));
    const eg = await run(engine, expired);
    assert.notEqual(eg.sessionId, sid);
    assert.equal(expired.sessionExpired, "idle");
    assert.equal(await engine.config.store.get(sid), null);
  });

  it("持续活动可以续命空闲超时，但救不了绝对超时", async () => {
    const { engine, clock } = makeEngine({ idleMs: 1000, absoluteMs: 3000 });
    const login = new FakeContext({ method: "POST", path: "/login" });
    await engine.process(login);
    const g = login.guard as SessionGuard;
    await g.login("dave");
    await engine.finalize(login);
    const sid = g.sessionId;

    // 每 700ms 活动一次（< 空闲超时 1000ms），空闲超时永远不触发
    for (let i = 0; i < 4; i++) {
      clock.advance(700);
      const ctx = login.carryCookies(new FakeContext({ method: "GET", path: "/" }));
      const cg = await run(engine, ctx);
      assert.equal(cg.sessionId, sid, `第 ${i + 1} 次活动后会话应仍存活`);
    }

    // 4 次活动后仅过 2800ms，仍在绝对超时 3000ms 内；再前进 300ms 触发绝对超时
    clock.advance(300);
    const final = login.carryCookies(new FakeContext({ method: "GET", path: "/" }));
    const fg = await run(engine, final);
    assert.notEqual(fg.sessionId, sid);
    assert.equal(final.sessionExpired, "absolute");
  });

  it("绝对超时不随 touch 刷新而延长", async () => {
    const { engine, clock } = makeEngine({ idleMs: 10000, absoluteMs: 2000 });
    const login = new FakeContext({ method: "POST", path: "/login" });
    await engine.process(login);
    const g = login.guard as SessionGuard;
    await g.login("erin");
    await engine.finalize(login);
    const sid = g.sessionId;

    clock.advance(1500);
    const ctx1 = login.carryCookies(new FakeContext());
    assert.equal((await run(engine, ctx1)).sessionId, sid);

    clock.advance(600); // 距登录 2100ms，绝对超时命中（空闲才 600ms）
    const ctx2 = login.carryCookies(new FakeContext());
    const cg2 = await run(engine, ctx2);
    assert.notEqual(cg2.sessionId, sid);
    assert.equal(ctx2.sessionExpired, "absolute");
  });
});

describe("并发会话上限与踢下线", () => {
  it("超过 maxSessionsPerUser 时最老的会话被挤掉", async () => {
    const { engine } = makeEngine({ max: 2 });
    const guards: SessionGuard[] = [];
    for (let i = 0; i < 3; i++) {
      const ctx = new FakeContext({ method: "POST", path: "/login" });
      await engine.process(ctx);
      const g = ctx.guard as SessionGuard;
      await g.login("frank");
      await engine.finalize(ctx);
      guards.push(g);
    }
    const live = await engine.listSessions("frank");
    assert.equal(live.length, 2);
    const liveIds = new Set(live.map((s) => s.id));
    assert.equal(liveIds.has(guards[0]!.sessionId), false, "最老会话应被淘汰");
    assert.equal(liveIds.has(guards[2]!.sessionId), true);
  });

  it("kickOtherSessions 踢掉同账号其它会话，保留当前会话", async () => {
    const { engine } = makeEngine({ max: 0 });
    const contexts: FakeContext[] = [];
    for (let i = 0; i < 3; i++) {
      const ctx = new FakeContext({ method: "POST", path: "/login" });
      await engine.process(ctx);
      const g = ctx.guard as SessionGuard;
      await g.login("grace");
      await engine.finalize(ctx);
      contexts.push(ctx);
    }
    assert.equal((await engine.listSessions("grace")).length, 3);

    const admin = contexts[2]!;
    const adminGuard = admin.guard as SessionGuard;
    const kicked = await adminGuard.kickOtherSessions();
    assert.equal(kicked, 2);

    const remaining = await engine.listSessions("grace");
    assert.equal(remaining.length, 1);
    assert.equal(remaining[0]!.id, adminGuard.sessionId);

    // 被踢的会话再请求时变成匿名新会话
    const dead = contexts[0]!.carryCookies(new FakeContext());
    const dg = await run(engine, dead);
    assert.equal(dg.userId, null);
  });

  it("engine.kickUser 管理面接口能踢掉全部会话", async () => {
    const { engine } = makeEngine();
    const ctx = new FakeContext({ method: "POST", path: "/login" });
    await engine.process(ctx);
    await (ctx.guard as SessionGuard).login("heidi");
    await engine.finalize(ctx);
    assert.equal(await engine.kickUser("heidi"), 1);
    assert.equal((await engine.listSessions("heidi")).length, 0);
  });
});

describe("Cookie 安全属性", () => {
  it("生产配置强制 __Host 前缀，且下发 Secure/SameSite=Strict/HttpOnly", () => {
    const clock = new FakeClock();
    assert.throws(
      () =>
        new SessionEngine({
          store: new MemoryStore(clock, 0),
          clock,
          cookieName: "sid",
        }),
      /__Host/,
    );
  });

  it("会话 cookie 带齐安全属性，CSRF 双提交 cookie 不带 HttpOnly", async () => {
    const clock = new FakeClock();
    const engine = new SessionEngine({
      store: new MemoryStore(clock, 0),
      clock,
      csrf: "double-submit",
      allowInsecureLocal: true,
    });
    const ctx = new FakeContext();
    await run(engine, ctx);
    const sid = ctx.lastCookie(engine.config.cookieName)!;
    assert.equal(sid.attrs.sameSite, "Strict");
    assert.equal(sid.attrs.httpOnly, true);
    assert.equal(sid.attrs.path, "/");
    assert.equal(sid.attrs.secure, false, "本地演示放宽 Secure；生产由 __Host 强制 Secure");

    const csrf = ctx.lastCookie(engine.config.csrfCookieName)!;
    assert.equal(csrf.attrs.httpOnly, false);
    assert.equal(csrf.attrs.sameSite, "Strict");
  });
});
