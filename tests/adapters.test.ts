/**
 * 适配器集成测试：通过真实 HTTP 调用验证 cookie 流转、CSRF 403、轮换等端到端行为。
 * Express 与 Hono 各跑一套相同断言。
 *
 * 注意：/login 本身也是状态变更请求，同样受 CSRF 保护（登录 CSRF 是真实攻击面）。
 * 正确流程：GET 建立匿名会话并取得 csrfToken → 带 token 调 POST /login。
 */
import { describe, it, beforeEach, expect } from 'vitest';
import express from 'express';
import { Hono } from 'hono';
import { nodeServer } from './helpers/hono-node.js';
import request from 'supertest';
import { SessionEngine } from '../src/engine.js';
import { MemorySessionStore } from '../src/stores/memory.js';
import { sessionMiddleware as expressSession } from '../src/adapters/express.js';
import { sessionMiddleware as honoSession, SESSION_HANDLE_KEY } from '../src/adapters/hono.js';
import type { SessionHandle } from '../src/types.js';

/** 极简 cookie jar：收集 name=value，供跨请求携带 */
class CookieJar {
  private readonly values = new Map<string, string>();

  absorb(setCookies: string[] | undefined): void {
    for (const sc of setCookies ?? []) {
      const pair = sc.split(';')[0]!;
      const eq = pair.indexOf('=');
      if (eq > 0) this.values.set(pair.slice(0, eq), pair.slice(eq + 1));
    }
  }

  header(): string {
    return [...this.values.entries()].map(([k, v]) => `${k}=${v}`).join('; ');
  }

  get(name: string): string | undefined {
    return this.values.get(name);
  }
}

function buildExpressApp() {
  const store = new MemorySessionStore({ sweepIntervalMs: 0 });
  const engine = new SessionEngine({ store, hostPrefix: false });
  const app = express();
  app.use(express.json());
  app.use(expressSession(engine));

  // 暴露当前会话的 CSRF token，模拟前端页面渲染时注入
  app.get('/csrf', (req, res) => {
    res.json({ csrfToken: req.session.csrfToken });
  });
  app.post('/login', async (req, res) => {
    await req.session.login('user-1');
    res.json({ ok: true, csrfToken: req.session.csrfToken });
  });
  app.get('/me', (req, res) => {
    res.json({ userId: req.session.record.userId });
  });
  app.post('/action', (req, res) => {
    res.json({ acted: req.session.record.userId });
  });
  app.post('/logout', async (req, res) => {
    await req.session.logout();
    res.json({ ok: true });
  });
  return { app, store };
}

function buildHonoApp() {
  const store = new MemorySessionStore({ sweepIntervalMs: 0 });
  const engine = new SessionEngine({ store, hostPrefix: false });
  const app = new Hono<{
    Variables: {
      session: SessionHandle;
      sessionTimedOut: 'idle' | 'absolute' | null;
    };
  }>();
  app.use('*', honoSession(engine));

  app.get('/csrf', (c) => {
    const session = c.get(SESSION_HANDLE_KEY);
    return c.json({ csrfToken: session.csrfToken });
  });
  app.post('/login', async (c) => {
    const session = c.get(SESSION_HANDLE_KEY);
    await session.login('user-1');
    return c.json({ ok: true, csrfToken: session.csrfToken });
  });
  app.get('/me', (c) => {
    const session = c.get(SESSION_HANDLE_KEY);
    return c.json({ userId: session.record.userId });
  });
  app.post('/action', (c) => {
    const session = c.get(SESSION_HANDLE_KEY);
    return c.json({ acted: session.record.userId });
  });
  app.post('/logout', async (c) => {
    const session = c.get(SESSION_HANDLE_KEY);
    await session.logout();
    return c.json({ ok: true });
  });
  return { app: nodeServer(app), store };
}

const frameworks = [
  ['Express', buildExpressApp],
  ['Hono', buildHonoApp],
] as const;

describe.each(frameworks)('%s 适配器端到端', (_name, build) => {
  let app: ReturnType<typeof build>['app'];

  beforeEach(() => {
    app = build().app;
  });

  /** supertest 的 set-cookie 类型是 string | string[] | undefined，统一成数组 */
  function setCookiesOf(res: { headers: Record<string, unknown> }): string[] {
    const sc = res.headers['set-cookie'];
    if (!sc) return [];
    return Array.isArray(sc) ? (sc as string[]) : [sc as string];
  }

  /** 建立匿名会话并拿到 CSRF token 的标准前置 */
  async function establishSession(): Promise<{ jar: CookieJar; token: string }> {
    const jar = new CookieJar();
    const csrf = await request(app).get('/csrf');
    jar.absorb(setCookiesOf(csrf));
    return { jar, token: csrf.body.csrfToken as string };
  }

  it('完整登录流程：匿名 → 登录（Set-Cookie 换新 ID）→ 带 cookie 访问受保护资源', async () => {
    const { jar, token } = await establishSession();
    const anonSid = jar.get('sid');
    expect(anonSid).toBeTruthy();

    const login = await request(app)
      .post('/login')
      .set('Cookie', jar.header())
      .set('x-csrf-token', token)
      .send({});
    expect(login.status).toBe(200);
    jar.absorb(setCookiesOf(login));
    expect(login.body.ok).toBe(true);
    // 会话固定防御：登录后 SID 与匿名 SID 不同
    expect(jar.get('sid')).not.toBe(anonSid);
    // 登录后 CSRF token 也随会话一起轮换
    expect(login.body.csrfToken).not.toBe(token);

    const me = await request(app).get('/me').set('Cookie', jar.header());
    expect(me.body).toEqual({ userId: 'user-1' });
  });

  it('无 CSRF token 的 POST 被 403 拒绝；携带同步令牌后放行', async () => {
    const { jar, token } = await establishSession();
    // 先登录
    const login = await request(app)
      .post('/login')
      .set('Cookie', jar.header())
      .set('x-csrf-token', token)
      .send({});
    jar.absorb(setCookiesOf(login));
    const sessionToken = login.body.csrfToken as string;

    const blocked = await request(app)
      .post('/action')
      .set('Cookie', jar.header())
      .send({});
    expect(blocked.status).toBe(403);
    expect(blocked.body.error).toBe('csrf_rejected');

    // 旧的匿名 token 在登录轮换后已失效
    const stale = await request(app)
      .post('/action')
      .set('Cookie', jar.header())
      .set('x-csrf-token', token)
      .send({});
    expect(stale.status).toBe(403);

    const allowed = await request(app)
      .post('/action')
      .set('Cookie', jar.header())
      .set('x-csrf-token', sessionToken)
      .send({});
    expect(allowed.status).toBe(200);
    expect(allowed.body.acted).toBe('user-1');
  });

  it('logout 后旧 cookie 失效，再访问回到匿名身份', async () => {
    const { jar, token } = await establishSession();
    const login = await request(app)
      .post('/login')
      .set('Cookie', jar.header())
      .set('x-csrf-token', token)
      .send({});
    jar.absorb(setCookiesOf(login));
    const sessionToken = login.body.csrfToken as string;

    const bye = await request(app)
      .post('/logout')
      .set('Cookie', jar.header())
      .set('x-csrf-token', sessionToken);
    expect(bye.status).toBe(200);
    jar.absorb(setCookiesOf(bye));

    const after = await request(app).get('/me').set('Cookie', jar.header());
    expect(after.body).toEqual({ userId: null });
  });

  it('cookie 属性：HttpOnly + SameSite=Lax（本测试关闭 hostPrefix 以走 http）', async () => {
    const res = await request(app).get('/csrf');
    const sc = setCookiesOf(res);
    const sidCookie = sc.find((c) => c.startsWith('sid='));
    expect(sidCookie).toBeDefined();
    expect(sidCookie).toContain('HttpOnly');
    expect(sidCookie).toContain('SameSite=Lax');
    expect(sidCookie).not.toContain('Domain=');
  });
});
