/**
 * 安全站（Express + 同步令牌 CSRF）。
 * 与漏洞站业务接口一一对应，安全语义全部由 session-secure 中间件提供。
 */
import express from 'express';
import { SessionEngine } from '../../src/engine.js';
import { MemorySessionStore } from '../../src/stores/memory.js';
import { sessionMiddleware } from '../../src/adapters/express.js';
import { Bank, USERS } from '../shared/bank.js';
import { SECURE_ENGINE_DEFAULTS } from '../shared/config.js';
import type { SessionStore } from '../../src/index.js';

export interface SecureAppHandle {
  app: express.Express;
  bank: Bank;
  engine: SessionEngine;
  store: SessionStore;
}

export function createSecureExpressApp(
  store: SessionStore = new MemorySessionStore({ sweepIntervalMs: 0 }),
): SecureAppHandle {
  const app = express();
  app.use(express.json());
  const bank = new Bank();

  const engine = new SessionEngine({
    ...SECURE_ENGINE_DEFAULTS,
    store,
    csrfMode: 'synchronizer',
  });
  app.use(sessionMiddleware(engine));

  // 页面/客户端在渲染时取当前 CSRF token（同步令牌模式：token 存在服务端会话里）
  app.get('/api/csrf', (req, res) => {
    res.json({ csrfToken: req.session.csrfToken });
  });

  app.get('/api/session', (req, res) => {
    res.json({
      sid: req.session.record.id,
      userId: req.session.record.userId,
      authenticated: req.session.isAuthenticated(),
    });
  });

  app.post('/api/login', async (req, res) => {
    const { username, password } = req.body as { username?: string; password?: string };
    if (!username || USERS[username] !== password) {
      return res.status(401).json({ error: 'bad credentials' });
    }
    // 登录轮换在引擎内部完成：旧 SID 销毁、新 SID + 新 CSRF token
    const newSid = await req.session.login(username);
    res.json({ ok: true, sid: newSid, csrfToken: req.session.csrfToken });
  });

  app.get('/api/balance', (req, res) => {
    if (!req.session.isAuthenticated()) {
      return res.status(401).json({ error: 'unauthenticated' });
    }
    res.json({ user: req.session.record.userId, balance: bank.balance(req.session.record.userId!) });
  });

  app.post('/api/transfer', (req, res) => {
    if (!req.session.isAuthenticated()) {
      return res.status(401).json({ error: 'unauthenticated' });
    }
    // 能到这里说明 CSRF 已通过（中间件已拦 403）
    const { to, amount } = req.body as { to?: string; amount?: number };
    const ok = bank.transfer(req.session.record.userId!, String(to), Number(amount));
    res.json({ ok, balance: bank.balance(req.session.record.userId!) });
  });

  app.post('/api/logout', async (req, res) => {
    await req.session.logout();
    res.json({ ok: true });
  });

  // 踢同账号其它会话
  app.post('/api/kick-others', async (req, res) => {
    if (!req.session.isAuthenticated()) {
      return res.status(401).json({ error: 'unauthenticated' });
    }
    const killed = await req.session.kickOthers();
    res.json({ ok: true, killed });
  });

  // 管理员一键踢整个账号
  app.post('/api/admin/kick-user', async (req, res) => {
    const { userId } = req.body as { userId?: string };
    if (!userId) return res.status(400).json({ error: 'userId required' });
    const killed = await engine.kickUser(userId);
    res.json({ ok: true, killed });
  });

  return { app, bank, engine, store };
}
