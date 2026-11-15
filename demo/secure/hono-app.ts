/**
 * 安全站（Hono + 双提交 CSRF）。
 * 与 Express 版接口完全一致，证明同一套 SessionEngine 可挂不同框架。
 * 双提交模式：CSRF token 放在可读 cookie 里，前端读出后用 x-csrf-token 回传，
 * 引擎校验 cookie 与 header 一致且 HMAC 签名合法。
 */
import { Hono, type Context } from 'hono';
import { SessionEngine } from '../../src/engine.js';
import { MemorySessionStore } from '../../src/stores/memory.js';
import {
  sessionMiddleware,
  SESSION_HANDLE_KEY,
} from '../../src/adapters/hono.js';
import { Bank, USERS } from '../shared/bank.js';
import { SECURE_ENGINE_DEFAULTS, DEMO_CSRF_SECRET } from '../shared/config.js';
import type { SessionStore } from '../../src/index.js';
import type { SessionHandle } from '../../src/types.js';

export interface SecureHonoHandle {
  app: Hono;
  bank: Bank;
  engine: SessionEngine;
  store: SessionStore;
}

export function createSecureHonoApp(
  store: SessionStore = new MemorySessionStore({ sweepIntervalMs: 0 }),
): SecureHonoHandle {
  const app = new Hono();
  const bank = new Bank();
  const engine = new SessionEngine({
    ...SECURE_ENGINE_DEFAULTS,
    store,
    csrfMode: 'double-submit',
    csrfSecret: DEMO_CSRF_SECRET,
  });
  app.use('*', sessionMiddleware(engine));

  const sessionOf = (c: Context): SessionHandle =>
    c.get(SESSION_HANDLE_KEY) as SessionHandle;

  app.get('/api/csrf', (c) => c.json({ csrfToken: sessionOf(c).csrfToken }));

  app.get('/api/session', (c) => {
    const s = sessionOf(c);
    return c.json({
      sid: s.record.id,
      userId: s.record.userId,
      authenticated: s.isAuthenticated(),
    });
  });

  app.post('/api/login', async (c) => {
    const body = (await c.req.json().catch(() => ({}))) as {
      username?: string;
      password?: string;
    };
    if (!body.username || USERS[body.username] !== body.password) {
      return c.json({ error: 'bad credentials' }, 401);
    }
    const s = sessionOf(c);
    const newSid = await s.login(body.username);
    return c.json({ ok: true, sid: newSid, csrfToken: s.csrfToken });
  });

  app.get('/api/balance', (c) => {
    const s = sessionOf(c);
    if (!s.isAuthenticated()) return c.json({ error: 'unauthenticated' }, 401);
    return c.json({ user: s.record.userId, balance: bank.balance(s.record.userId!) });
  });

  app.post('/api/transfer', async (c) => {
    const s = sessionOf(c);
    if (!s.isAuthenticated()) return c.json({ error: 'unauthenticated' }, 401);
    const body = (await c.req.json().catch(() => ({}))) as {
      to?: string;
      amount?: number;
    };
    const ok = bank.transfer(s.record.userId!, String(body.to), Number(body.amount));
    return c.json({ ok, balance: bank.balance(s.record.userId!) });
  });

  app.post('/api/logout', async (c) => {
    await sessionOf(c).logout();
    return c.json({ ok: true });
  });

  app.post('/api/kick-others', async (c) => {
    const s = sessionOf(c);
    if (!s.isAuthenticated()) return c.json({ error: 'unauthenticated' }, 401);
    return c.json({ ok: true, killed: await s.kickOthers() });
  });

  app.post('/api/admin/kick-user', async (c) => {
    const body = (await c.req.json().catch(() => ({}))) as { userId?: string };
    if (!body.userId) return c.json({ error: 'userId required' }, 400);
    return c.json({ ok: true, killed: await engine.kickUser(body.userId) });
  });

  return { app, bank, engine, store };
}
