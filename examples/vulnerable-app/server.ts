/**
 * !!! 故意不安全的对照站 !!!
 *
 * 刻意复现老 Node 服务的典型问题，仅用于攻击脚本演示"漏洞长什么样"：
 *  1. 会话固定：登录前后沿用同一个会话 ID，且接受 URL 传入的攻击者预设 ID
 *  2. Cookie 无 Secure / 无 SameSite / 无 __Host 前缀，可被子域覆盖、可随跨站请求携带
 *  3. 无任何 CSRF 防护，状态变更接口跨站表单可直接打
 *  4. 会话不过期、无并发限制、无踢下线
 *
 * 不要把本文件的任何写法抄到真实项目里。
 */
import express from "express";

const app = express();
app.use(express.json());

interface VulnSession {
  id: string;
  userId: string | null;
  data: Record<string, unknown>;
}

const sessions = new Map<string, VulnSession>();
const PORT = Number(process.env.PORT ?? 4101);

function getOrCreateSession(req: express.Request, res: express.Response): VulnSession {
  // 漏洞 1：会话 ID 可由客户端通过 query/cookie 任意指定（会话固定的温床）
  let sid =
    (req.query.sid as string | undefined) ??
    req.headers.cookie?.match(/(?:^|;\s*)sid=([^;]+)/)?.[1];
  if (!sid) {
    sid = `fixed-${Math.random().toString(36).slice(2)}`;
  }
  let session = sessions.get(sid);
  if (!session) {
    session = { id: sid, userId: null, data: {} };
    sessions.set(sid, session);
  }
  // 漏洞 2：弱 cookie 属性 —— 无 Secure、无 SameSite、普通名可被子域覆盖
  res.append("Set-Cookie", `sid=${sid}; Path=/; HttpOnly`);
  return session;
}

app.use((req, _res, next) => {
  (req as express.Request & { vulnSession?: VulnSession }).vulnSession =
    getOrCreateSession(req, _res);
  next();
});

app.get("/", (_req, res) => {
  res.json({ app: "vulnerable", warning: "本站点故意保留会话固定与 CSRF 漏洞" });
});

app.post("/login", (req, res) => {
  const { username, password } = req.body as { username?: string; password?: string };
  if (!username || password !== "pw") {
    res.status(401).json({ error: "bad credentials" });
    return;
  }
  const session = (req as express.Request & { vulnSession: VulnSession }).vulnSession;
  // 漏洞 1（核心）：登录后不轮转 ID，攻击者预设的 sid 直接变成已认证会话
  session.userId = username;
  res.json({ ok: true, sid: session.id, userId: session.userId });
});

app.get("/me", (req, res) => {
  const session = (req as express.Request & { vulnSession: VulnSession }).vulnSession;
  res.json({ sid: session.id, userId: session.userId, data: session.data });
});

// 漏洞 3：无 CSRF 防护的状态变更接口
app.post("/transfer", (req, res) => {
  const session = (req as express.Request & { vulnSession: VulnSession }).vulnSession;
  if (!session.userId) {
    res.status(401).json({ error: "unauthenticated" });
    return;
  }
  const { to, amount } = req.body as { to?: string; amount?: number };
  session.data.lastTransfer = { to, amount, at: Date.now() };
  res.json({ ok: true, transferred: { to, amount } });
});

app.post("/logout", (req, res) => {
  const session = (req as express.Request & { vulnSession: VulnSession }).vulnSession;
  sessions.delete(session.id);
  res.append("Set-Cookie", "sid=; Path=/; Max-Age=0");
  res.json({ ok: true });
});

const server = app.listen(PORT, () => {
  console.log(`[vulnerable] 故意不安全的站点监听 http://127.0.0.1:${PORT}`);
});

export { app, server };
