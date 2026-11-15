/**
 * 引擎安全属性单元测试 —— 内存存储与 Redis 存储各跑同一套用例（矩阵化）。
 */
import { describe, it, expect, beforeEach } from 'vitest';
import { SessionEngine } from '../src/engine.js';
import { MemorySessionStore } from '../src/stores/memory.js';
import { RedisSessionStore } from '../src/stores/redis.js';
import { FakeRedis } from './helpers/fake-redis.js';
import type { FrameworkRequest, FrameworkResponse } from '../src/engine.js';
import type { SessionStore } from '../src/types.js';

interface FakeClock {
  now(): number;
  advance(ms: number): void;
}

function makeClock(start = 1_000_000): FakeClock {
  let t = start;
  return {
    now: () => t,
    advance: (ms) => {
      t += ms;
    },
  };
}

function makeReq(
  opts: {
    cookie?: string;
    method?: string;
    csrfHeader?: string;
  } = {},
): FrameworkRequest {
  return {
    cookieHeader: () => opts.cookie,
    header: (name) =>
      name.toLowerCase() === 'x-csrf-token' ? opts.csrfHeader : undefined,
    method: () => opts.method ?? 'GET',
  };
}

function makeRes(): FrameworkResponse & { cookies: string[] } {
  const cookies: string[] = [];
  return {
    cookies,
    appendSetCookie: (c) => cookies.push(c),
  };
}

function cookieValue(setCookies: string[], name: string): string | undefined {
  const line = setCookies.find((c) => c.startsWith(`${name}=`));
  return line?.split(';')[0]?.slice(name.length + 1);
}

const IDLE = 60_000;
const ABSOLUTE = 300_000;

function makeEngine(store: SessionStore, clock: FakeClock, csrfMode: 'synchronizer' | 'double-submit' = 'synchronizer', maxSessions = 10) {
  return new SessionEngine({
    store,
    idleTimeoutMs: IDLE,
    absoluteTimeoutMs: ABSOLUTE,
    maxSessionsPerUser: maxSessions,
    csrfMode,
    csrfSecret: 'x'.repeat(44),
    hostPrefix: true,
    now: clock.now,
  });
}

const storeFactories: Array<[string, (clock: FakeClock) => SessionStore]> = [
  ['MemorySessionStore', (clock) => new MemorySessionStore({ sweepIntervalMs: 0, now: clock.now })],
  ['RedisSessionStore', (clock) => new RedisSessionStore({ client: new FakeRedis({ now: clock.now }) })],
];

describe.each(storeFactories)('SessionEngine on %s', (_label, makeStore) => {
  let clock: FakeClock;
  let store: SessionStore;
  let engine: SessionEngine;

  beforeEach(() => {
    clock = makeClock();
    store = makeStore(clock);
    engine = makeEngine(store, clock);
  });

  it('新请求自动建立匿名会话并下发 __Host- 前缀 cookie', async () => {
    const res = makeRes();
    const result = await engine.process(makeReq());
    expect(result.handle.isAuthenticated()).toBe(false);
    await engine.finalize(res, result.handle);

    const sidLine = res.cookies.find((c) => c.startsWith('__Host-sid='));
    expect(sidLine).toBeDefined();
    expect(sidLine).toContain('Secure');
    expect(sidLine).toContain('HttpOnly');
    expect(sidLine).toContain('SameSite=Lax');
    expect(sidLine).toContain('Path=/');
    expect(sidLine).not.toContain('Domain=');
  });

  it('登录后轮换会话 ID 与 CSRF token，旧 ID 立即失效（防会话固定）', async () => {
    // 攻击者预先在受害者浏览器种了一个匿名会话 ID
    const res1 = makeRes();
    const anon = await engine.process(makeReq());
    await engine.finalize(res1, anon.handle);
    const fixedId = anon.handle.record.id;
    expect(await store.get(fixedId)).not.toBeNull();

    // 受害者用这个固定 ID 发起登录
    const res2 = makeRes();
    const loginReq = await engine.process(
      makeReq({ cookie: `__Host-sid=${fixedId}`, method: 'POST' }),
    );
    const newCsrf = loginReq.handle.record.csrfToken;
    const newId = await loginReq.handle.login('user-1');
    await engine.finalize(res2, loginReq.handle);

    expect(newId).not.toBe(fixedId);
    // 旧会话已被销毁，固定的 session id 无法再复活登录态
    expect(await store.get(fixedId)).toBeNull();
    // 下发给浏览器的是新 ID
    expect(cookieValue(res2.cookies, '__Host-sid')).toBe(newId);

    // 攻击者拿着旧 ID 回来，只能得到一个全新匿名会话，拿不到 user-1 的身份
    const attack = await engine.process(
      makeReq({ cookie: `__Host-sid=${fixedId}` }),
    );
    expect(attack.handle.isAuthenticated()).toBe(false);
    expect(attack.handle.record.userId).toBeNull();
    expect(attack.handle.record.id).not.toBe(newId);
    void newCsrf;
  });

  it('同步令牌模式：无 token / 错误 token 的 POST 被拒，正确 token 放行', async () => {
    const login = await engine.process(makeReq({ method: 'POST' }));
    await login.handle.login('user-1');
    const sid = login.handle.record.id;
    const token = login.handle.csrfToken!;

    const noToken = await engine.process(
      makeReq({ cookie: `__Host-sid=${sid}`, method: 'POST' }),
    );
    expect(noToken.csrfFailed).toBe(true);
    expect(noToken.csrfFailureReason).toBe('no-token');

    const badToken = await engine.process(
      makeReq({ cookie: `__Host-sid=${sid}`, method: 'POST', csrfHeader: 'forged' }),
    );
    expect(badToken.csrfFailed).toBe(true);
    expect(badToken.csrfFailureReason).toBe('token-mismatch');

    const ok = await engine.process(
      makeReq({ cookie: `__Host-sid=${sid}`, method: 'POST', csrfHeader: token }),
    );
    expect(ok.csrfFailed).toBe(false);
  });

  it('安全方法（GET/HEAD/OPTIONS）不触发 CSRF 校验', async () => {
    const login = await engine.process(makeReq());
    await login.handle.login('user-1');
    for (const method of ['GET', 'HEAD', 'OPTIONS']) {
      const r = await engine.process(
        makeReq({ cookie: `__Host-sid=${login.handle.record.id}`, method }),
      );
      expect(r.csrfFailed).toBe(false);
    }
  });

  it('登录请求本身也受 CSRF 保护（防登录 CSRF），匿名 token 校验通过后才允许 login', async () => {
    // 无 token 的登录请求先被 CSRF 拦截，业务 login 根本不会执行
    const blocked = await engine.process(makeReq({ method: 'POST' }));
    expect(blocked.csrfFailed).toBe(true);
    expect(blocked.handle.isAuthenticated()).toBe(false);

    // 带匿名会话自身 token 的登录请求放行，login 后拿到身份
    const warm = await engine.process(makeReq());
    const allowed = await engine.process(
      makeReq({
        cookie: `__Host-sid=${warm.handle.record.id}`,
        method: 'POST',
        csrfHeader: warm.handle.record.csrfToken!,
      }),
    );
    expect(allowed.csrfFailed).toBe(false);
    await allowed.handle.login('user-1');
    expect(allowed.handle.isAuthenticated()).toBe(true);
  });

  it('轮换后旧 CSRF token 立即失效，必须用新会话的 token', async () => {
    const anon = await engine.process(makeReq());
    const oldToken = anon.handle.record.csrfToken!;
    const sid = await anon.handle.login('user-1');
    // 旧 token 与新会话里存的 token 不同
    expect(anon.handle.record.csrfToken).not.toBe(oldToken);
    const stale = await engine.process(
      makeReq({ cookie: `__Host-sid=${sid}`, method: 'POST', csrfHeader: oldToken }),
    );
    expect(stale.csrfFailed).toBe(true);
    const fresh = await engine.process(
      makeReq({
        cookie: `__Host-sid=${sid}`,
        method: 'POST',
        csrfHeader: anon.handle.record.csrfToken!,
      }),
    );
    expect(fresh.csrfFailed).toBe(false);
  });

  it('空闲超时：超过 idleTimeout 未活动的会话被销毁并标记 timedOut=idle', async () => {
    const login = await engine.process(makeReq());
    await login.handle.login('user-1');
    const sid = login.handle.record.id;

    clock.advance(IDLE + 1);
    const r = await engine.process(makeReq({ cookie: `__Host-sid=${sid}` }));
    expect(r.timedOut).toBe('idle');
    expect(r.handle.isAuthenticated()).toBe(false);
    expect(await store.get(sid)).toBeNull();
  });

  it('活动请求会续期空闲超时，但不改变 createdAt（绝对寿命独立计算）', async () => {
    const login = await engine.process(makeReq());
    await login.handle.login('user-1');
    const sid = login.handle.record.id;
    const createdAt = login.handle.record.createdAt;

    clock.advance(IDLE - 1_000);
    const res = makeRes();
    const active = await engine.process(makeReq({ cookie: `__Host-sid=${sid}` }));
    expect(active.timedOut).toBeNull();
    await engine.finalize(res, active.handle);
    expect(active.handle.record.createdAt).toBe(createdAt);
    expect(active.handle.record.lastSeenAt).toBe(clock.now());

    // 再跨过接近一个空闲窗口（59s < 60s），因为上次请求已把 lastSeenAt 续到 59s，
    // 此刻间隔只有 59s，仍然活着 —— 证明续期生效
    clock.advance(IDLE - 1_000);
    const stillAlive = await engine.process(
      makeReq({ cookie: `__Host-sid=${sid}` }),
    );
    expect(stillAlive.timedOut).toBeNull();
    expect(stillAlive.handle.record.userId).toBe('user-1');
  });

  it('绝对超时：无论期间多活跃，到点强制失效并标记 timedOut=absolute', async () => {
    const login = await engine.process(makeReq());
    await login.handle.login('user-1');
    const sid = login.handle.record.id;
    const createdAt = login.handle.record.createdAt;

    // 每 30s 活动一次（30s < 空闲窗口 60s），空闲超时始终不可能先触发；
    // 一直活动到越过绝对死线（300s），证明绝对寿命独立于活跃度
    let lastAliveAt = 0;
    while (clock.now() - createdAt < ABSOLUTE) {
      clock.advance(30_000);
      const active = await engine.process(makeReq({ cookie: `__Host-sid=${sid}` }));
      if (clock.now() - createdAt < ABSOLUTE) {
        expect(active.timedOut).toBeNull();
        expect(active.handle.record.userId).toBe('user-1');
        lastAliveAt = clock.now();
        const res = makeRes();
        await engine.finalize(res, active.handle);
      } else {
        // 越过绝对死线的这一跳：会话已被绝对超时终结
        expect(active.timedOut).toBe('absolute');
        expect(active.handle.isAuthenticated()).toBe(false);
      }
    }
    expect(lastAliveAt).toBeGreaterThan(0);
    expect(await store.get(sid)).toBeNull();
  });

  it('并发会话上限：第 3 个登录挤掉最早的会话（上限=2）', async () => {
    const limitEngine = makeEngine(store, clock, 'synchronizer', 2);
    const sessions: string[] = [];
    for (let i = 0; i < 3; i++) {
      const r = await limitEngine.process(makeReq({ method: 'POST' }));
      await r.handle.login('user-1');
      sessions.push(r.handle.record.id);
      clock.advance(1_000); // 保证 createdAt 严格递增
    }
    const [oldest, middle, newest] = sessions;
    expect(await store.get(oldest!)).toBeNull();
    expect(await store.get(middle!)).not.toBeNull();
    expect(await store.get(newest!)).not.toBeNull();
  });

  it('kickOthers 踢掉同账号其它会话，保留当前会话', async () => {
    const a = await engine.process(makeReq());
    await a.handle.login('user-1');
    clock.advance(1_000);
    const b = await engine.process(makeReq());
    await b.handle.login('user-1');

    const killed = await b.handle.kickOthers();
    expect(killed).toContain(a.handle.record.id);
    expect(await store.get(a.handle.record.id)).toBeNull();
    expect(await store.get(b.handle.record.id)).not.toBeNull();
  });

  it('管理员一键踢整个账号下线', async () => {
    const a = await engine.process(makeReq());
    await a.handle.login('user-1');
    const b = await engine.process(makeReq());
    await b.handle.login('user-1');

    const killed = await engine.kickUser('user-1');
    expect(killed.sort()).toEqual([a.handle.record.id, b.handle.record.id].sort());
    expect(await store.get(a.handle.record.id)).toBeNull();
    expect(await store.get(b.handle.record.id)).toBeNull();
  });

  it('logout 销毁服务端会话，后续携带旧 cookie 不再认证', async () => {
    const login = await engine.process(makeReq());
    await login.handle.login('user-1');
    const sid = login.handle.record.id;
    await login.handle.logout();
    expect(await store.get(sid)).toBeNull();

    const back = await engine.process(makeReq({ cookie: `__Host-sid=${sid}` }));
    expect(back.handle.isAuthenticated()).toBe(false);
  });

  it('剩余 TTL 取空闲与绝对死线的较小值', async () => {
    const r = await engine.process(makeReq());
    await r.handle.login('user-1');
    clock.advance(10_000);
    const ttl = engine.remainingTtlSeconds(r.handle.record);
    // 空闲剩余 50s，绝对剩余 290s → 取 50（向上取整）
    expect(ttl).toBe(50);
  });
});

describe('双提交 CSRF 模式', () => {
  it('cookie 与 header 一致且 HMAC 签名合法才放行；自造 token 被拒', async () => {
    const clock = makeClock();
    const redis = new FakeRedis();
    const store = new RedisSessionStore({ client: redis });
    const engine = makeEngine(store, clock, 'double-submit');

    const login = await engine.process(makeReq({ method: 'POST' }));
    await login.handle.login('user-1');
    const sid = login.handle.record.id;
    const token = login.handle.csrfToken!;
    expect(token).toMatch(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);

    // 正常双提交：cookie 与 header 同值
    const ok = await engine.process(
      makeReq({
        cookie: `__Host-sid=${sid}; __Host-csrf_token=${token}`,
        method: 'POST',
        csrfHeader: token,
      }),
    );
    expect(ok.csrfFailed).toBe(false);

    // 攻击者自造随机 token（无合法 HMAC）
    const forged = 'AAAAAAAAAAAAAAAA.AAAAAAAAAAAAAAAA';
    const attack1 = await engine.process(
      makeReq({
        cookie: `__Host-sid=${sid}; __Host-csrf_token=${forged}`,
        method: 'POST',
        csrfHeader: forged,
      }),
    );
    expect(attack1.csrfFailed).toBe(true);
    expect(attack1.csrfFailureReason).toBe('bad-signature');

    // cookie 与 header 不一致
    const attack2 = await engine.process(
      makeReq({
        cookie: `__Host-sid=${sid}; __Host-csrf_token=${token}`,
        method: 'POST',
        csrfHeader: forged,
      }),
    );
    expect(attack2.csrfFailed).toBe(true);
    expect(attack2.csrfFailureReason).toBe('token-mismatch');
  });
});
