/**
 * ⚠️ 故意不安全的对照站 —— 严禁用于任何真实环境。
 *
 * 集中复现老 Node 服务的六类会话管理缺陷，每处都带 [VULN-n] 标记，
 * 与安全站的防护点一一对应，攻击脚本 tests/attack/cli.ts 逐个利用并对照结果。
 *
 * 缺陷清单：
 *   VULN-1 会话固定：登录不换会话 ID；且 /api/fixate 允许任意外部指定 SID
 *   VULN-2 无 CSRF 防护：状态变更接口只认 cookie，不校验任何令牌/来源
 *   VULN-3 Cookie 硬伤：无 __Host 前缀、无 Secure、无 SameSite、无 HttpOnly
 *   VULN-4 会话 ID 可预测：自增计数器生成 ID（sess-1, sess-2 ...）
 *   VULN-5 无超时：会话永不过期，没有空闲/绝对寿命概念
 *   VULN-6 无并发上限、无踢人：同账号无限会话，且无法集中吊销
 */
import express from 'express';
import { Bank, USERS } from '../shared/bank.js';

interface NaiveSession {
  id: string;
  userId: string | null;
}

export function createVulnerableApp() {
  const app = express();
  app.use(express.json());
  const bank = new Bank();

  // [VULN-4] 自增 ID，攻击者枚举 sess-N 即可撞上有效会话
  let counter = 0;
  const sessions = new Map<string, NaiveSession>();
  const COOKIE = 'SID';

  function parseCookies(header: string | undefined): Record<string, string> {
    const out: Record<string, string> = {};
    for (const part of header?.split(';') ?? []) {
      const eq = part.indexOf('=');
      if (eq > 0) out[part.slice(0, eq).trim()] = part.slice(eq + 1).trim();
    }
    return out;
  }

  // 朴素会话中间件：有 cookie 就用，没有就建一个
  app.use((req, res, next) => {
    const cookies = parseCookies(req.headers.cookie);
    let sid = cookies[COOKIE];
    if (!sid || !sessions.has(sid)) {
      counter += 1;
      sid = `sess-${counter}`;
      sessions.set(sid, { id: sid, userId: null });
    }
    // [VULN-3] 裸 cookie：没有任何安全属性，XSS 可读、跨站会自动携带、可被子域覆盖
    res.setHeader('Set-Cookie', `${COOKIE}=${sid}; Path=/`);
    (req as unknown as { session: NaiveSession }).session = sessions.get(sid)!;
    next();
  });

  // [VULN-1] 会话固定原语：攻击者把任意 SID 种进受害者浏览器（模拟子域注入/URL 传 SID）
  app.get('/api/fixate', (req, res) => {
    const sid = String(req.query.sid ?? '');
    if (!sid) return res.status(400).json({ error: 'sid required' });
    if (!sessions.has(sid)) sessions.set(sid, { id: sid, userId: null });
    res.setHeader('Set-Cookie', `${COOKIE}=${sid}; Path=/`);
    res.json({ ok: true, planted: sid });
  });

  app.get('/api/session', (req, res) => {
    const session = (req as unknown as { session: NaiveSession }).session;
    res.json({ sid: session.id, userId: session.userId });
  });

  app.post('/api/login', (req, res) => {
    const { username, password } = req.body as { username?: string; password?: string };
    if (!username || USERS[username] !== password) {
      return res.status(401).json({ error: 'bad credentials' });
    }
    const session = (req as unknown as { session: NaiveSession }).session;
    // [VULN-1] 核心缺陷：登录直接在原会话对象上挂 userId，会话 ID 保持不变
    session.userId = username;
    res.json({ ok: true, sid: session.id, userId: username });
  });

  app.get('/api/balance', (req, res) => {
    const session = (req as unknown as { session: NaiveSession }).session;
    if (!session.userId) return res.status(401).json({ error: 'unauthenticated' });
    res.json({ user: session.userId, balance: bank.balance(session.userId) });
  });

  // [VULN-2] 转账只看 cookie 里的会话，没有任何 CSRF token / Origin 校验
  app.post('/api/transfer', (req, res) => {
    const session = (req as unknown as { session: NaiveSession }).session;
    if (!session.userId) return res.status(401).json({ error: 'unauthenticated' });
    const { to, amount } = req.body as { to?: string; amount?: number };
    const ok = bank.transfer(session.userId, String(to), Number(amount));
    res.json({ ok, from: session.userId, to, amount, balance: bank.balance(session.userId) });
  });

  app.post('/api/logout', (req, res) => {
    const session = (req as unknown as { session: NaiveSession }).session;
    sessions.delete(session.id);
    res.json({ ok: true });
  });

  // 调试/演示：当前服务端会话总数（用来证明 VULN-6 无上限增长）
  app.get('/api/_debug/session-count', (_req, res) => {
    res.json({ count: sessions.size });
  });

  return { app, bank, sessions };
}
