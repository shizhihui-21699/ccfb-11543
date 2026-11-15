/**
 * 七个攻击场景，每个都对漏洞站与安全站发起同样的攻击并比对结果。
 */
import { HttpClient, waitReady } from './http-client.js';
import type { RunningServers } from './servers.js';
import type { ScenarioResult, Verdict } from './report.js';

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

export async function runScenarios(servers: RunningServers): Promise<ScenarioResult[]> {
  await waitReady(servers.vulnerable.base);
  await waitReady(servers.secureExpress.base);
  await waitReady(servers.secureHono.base);
  const results: ScenarioResult[] = [];

  // ── A1 会话固定 ────────────────────────────────────────────────
  results.push(await attackSessionFixation(servers));
  // ── A2 CSRF（同步令牌视角）────────────────────────────────────
  results.push(await attackCsrfSynchronizer(servers));
  // ── A3 CSRF（双提交视角，针对 Hono 版）────────────────────────
  results.push(await attackCsrfDoubleSubmit(servers));
  // ── A4 Cookie 安全属性 ────────────────────────────────────────
  results.push(await attackCookieFlags(servers));
  // ── A5 空闲超时 ───────────────────────────────────────────────
  results.push(await attackIdleTimeout(servers));
  // ── A6 绝对超时 ───────────────────────────────────────────────
  results.push(await attackAbsoluteTimeout(servers));
  // ── A7 并发上限 + 一键踢下线 ─────────────────────────────────
  results.push(await attackConcurrencyAndKick(servers));

  return results;
}

/** A1：攻击者先固定一个 SID，受害者登录后，攻击者用该 SID 是否能继承登录态 */
async function attackSessionFixation(servers: RunningServers): Promise<ScenarioResult> {
  // 漏洞站
  const attacker = new HttpClient();
  const fixedSid = `attacker-fixed-${Date.now()}`;
  await attacker.get(servers.vulnerable.base, `/api/fixate?sid=${fixedSid}`);
  // 受害者浏览器被种入同一 SID 后登录
  const victim = new HttpClient();
  victim.setExtraCookie('SID', fixedSid);
  const login = await victim.post(servers.vulnerable.base, '/api/login', {
    username: 'alice',
    password: 'alice-pw',
  });
  victim.clearExtraCookies();
  victim.absorb(login);
  // 攻击者回头用固定 SID 访问
  const attackerBack = new HttpClient();
  attackerBack.setExtraCookie('SID', fixedSid);
  const probe = await attackerBack.get(servers.vulnerable.base, '/api/balance');
  attackerBack.clearExtraCookies();
  const vulnExploited = probe.status === 200 && probe.body?.user === 'alice';

  // 安全站（Express）：尝试同样的固定手法
  const secAttacker = new HttpClient();
  // 先正常建立一个匿名会话拿到引擎签发的 SID，再试图“固定”它（安全站没有 fixate 接口，
  // 直接手动指定一个外来 SID，模拟注入）
  const warm = await secAttacker.get(servers.secureExpress.base, '/api/csrf');
  secAttacker.absorb(warm);
  const anonSid = secAttacker.cookieValue('sid')!;
  const csrfBefore = warm.body?.csrfToken as string;

  const secVictim = new HttpClient();
  secVictim.setExtraCookie('sid', anonSid);
  const secLogin = await secVictim.post(
    servers.secureExpress.base,
    '/api/login',
    { username: 'alice', password: 'alice-pw' },
    { 'x-csrf-token': csrfBefore },
  );
  secVictim.clearExtraCookies();
  secVictim.absorb(secLogin);
  const rotatedSid = secVictim.cookieValue('sid');

  const secAttackerBack = new HttpClient();
  secAttackerBack.setExtraCookie('sid', anonSid);
  const secProbe = await secAttackerBack.get(servers.secureExpress.base, '/api/balance');
  secAttackerBack.clearExtraCookies();
  const secBlocked =
    secLogin.status === 200 &&
    rotatedSid !== anonSid &&
    (secProbe.status === 401 || secProbe.body?.userId === null);

  return {
    id: 'A1',
    title: '会话固定（登录不换 SID）',
    vulnerable: {
      verdict: vulnExploited ? 'exploited' : 'blocked',
      detail: vulnExploited
        ? `固定 SID=${fixedSid} 在 alice 登录后直接读到其账户余额 ${probe.body?.balance}`
        : '固定 SID 未获得登录态（意外）',
    },
    secure: {
      verdict: secBlocked ? 'blocked' : 'exploited',
      detail: secBlocked
        ? `登录后 SID 轮换：${anonSid.slice(0, 10)}… → ${rotatedSid?.slice(0, 10)}…，旧 SID 探测返回 ${secProbe.status}`
        : `旧 SID 仍可访问（意外，status=${secProbe.status}）`,
    },
    passed: vulnExploited && secBlocked,
  };
}

/** A2：跨站伪造转账（同步令牌模式，针对 Express 安全站） */
async function attackCsrfSynchronizer(servers: RunningServers): Promise<ScenarioResult> {
  // 漏洞站：受害者已登录，攻击者诱导其浏览器跨站 POST（cookie 自动携带，无 token）
  const victim = new HttpClient();
  await victim.absorb(await victim.post(servers.vulnerable.base, '/api/login', {
    username: 'alice',
    password: 'alice-pw',
  }));
  const beforeVuln = (await victim.get(servers.vulnerable.base, '/api/balance')).body?.balance;
  const forged = await victim.post(servers.vulnerable.base, '/api/transfer', {
    to: 'bob',
    amount: 100,
  }); // 故意不带任何 CSRF token
  const afterVuln = (await victim.get(servers.vulnerable.base, '/api/balance')).body?.balance;
  const vulnExploited = forged.status === 200 && forged.body?.ok === true && afterVuln === beforeVuln - 100;

  // 安全站 Express：同样的无 token 跨站 POST
  const secVictim = new HttpClient();
  const warm = await secVictim.get(servers.secureExpress.base, '/api/csrf');
  secVictim.absorb(warm);
  const login = await secVictim.post(
    servers.secureExpress.base,
    '/api/login',
    { username: 'alice', password: 'alice-pw' },
    { 'x-csrf-token': warm.body.csrfToken },
  );
  secVictim.absorb(login);
  const secForged = await secVictim.post(servers.secureExpress.base, '/api/transfer', {
    to: 'bob',
    amount: 100,
  });
  // 拿到合法 token 后应成功（证明接口本身可用，只是无 token 被拦）
  const legit = await secVictim.post(
    servers.secureExpress.base,
    '/api/transfer',
    { to: 'bob', amount: 1 },
    { 'x-csrf-token': login.body.csrfToken },
  );
  const secBlocked = secForged.status === 403 && secForged.body?.error === 'csrf_rejected' && legit.status === 200;

  return {
    id: 'A2',
    title: 'CSRF 跨站伪造转账（无令牌）',
    vulnerable: {
      verdict: vulnExploited ? 'exploited' : 'blocked',
      detail: vulnExploited
        ? `无 token 的转账成功，余额 ${beforeVuln} → ${afterVuln}`
        : '转账被拒（意外）',
    },
    secure: {
      verdict: secBlocked ? 'blocked' : 'exploited',
      detail: secBlocked
        ? `无 token POST 返回 403(${secForged.body?.reason})，带合法 token 的 POST 返回 ${legit.status}`
        : `防护失效（forged=${secForged.status}, legit=${legit.status}）`,
    },
    passed: vulnExploited && secBlocked,
  };
}

/** A3：双提交模式下攻击者自造 token（针对 Hono 安全站）；漏洞站依旧无防护 */
async function attackCsrfDoubleSubmit(servers: RunningServers): Promise<ScenarioResult> {
  // 漏洞站基线：同样能打
  const v = new HttpClient();
  v.absorb(await v.post(servers.vulnerable.base, '/api/login', {
    username: 'alice',
    password: 'alice-pw',
  }));
  const vForged = await v.post(servers.vulnerable.base, '/api/transfer', { to: 'bob', amount: 5 });
  const vulnExploited = vForged.body?.ok === true;

  // Hono 安全站：登录拿双提交 cookie
  const h = new HttpClient();
  h.absorb(await h.get(servers.secureHono.base, '/api/csrf'));
  const warmToken = h.cookieValue('csrf_token');
  const hLogin = await h.post(
    servers.secureHono.base,
    '/api/login',
    { username: 'alice', password: 'alice-pw' },
    { 'x-csrf-token': warmToken },
  );
  h.absorb(hLogin);
  const realToken = h.cookieValue('csrf_token');

  // 攻击 1：完全自造 token，cookie 与 header 同值但无合法 HMAC
  const forgedPair = 'AAAAAAAAAAAAAAAAAAAAAAAA.aaaaaaaaaaaaaaaaaaaaaaaa';
  const a1 = new HttpClient();
  a1.setExtraCookie('sid', h.cookieValue('sid')!);
  a1.setExtraCookie('csrf_token', forgedPair);
  const forged1 = await a1.post(
    servers.secureHono.base,
    '/api/transfer',
    { to: 'bob', amount: 5 },
    { 'x-csrf-token': forgedPair },
  );
  a1.clearExtraCookies();

  // 攻击 2：只改 header，cookie 保持真 token（不一致）
  const a2 = new HttpClient();
  a2.setExtraCookie('sid', h.cookieValue('sid')!);
  a2.setExtraCookie('csrf_token', realToken!);
  const forged2 = await a2.post(
    servers.secureHono.base,
    '/api/transfer',
    { to: 'bob', amount: 5 },
    { 'x-csrf-token': forgedPair },
  );
  a2.clearExtraCookies();

  // 合法请求：cookie 自动带 + header 放真 token
  const legit = await h.post(
    servers.secureHono.base,
    '/api/transfer',
    { to: 'bob', amount: 1 },
    { 'x-csrf-token': realToken },
  );

  const honoBlocked =
    forged1.status === 403 &&
    forged2.status === 403 &&
    (forged1.body?.reason === 'bad-signature' || forged2.body?.reason === 'token-mismatch') &&
    legit.status === 200;

  return {
    id: 'A3',
    title: 'CSRF 双提交伪造（自造/篡改 token）',
    vulnerable: {
      verdict: vulnExploited ? 'exploited' : 'blocked',
      detail: vulnExploited ? '漏洞站无 CSRF 概念，转账成功' : '转账被拒（意外）',
    },
    secure: { verdict: 'n/a', detail: 'Express 用同步令牌，见 A2' },
    secureHono: {
      verdict: honoBlocked ? 'blocked' : 'exploited',
      detail: honoBlocked
        ? `自造 token→403(${forged1.body?.reason})，header/cookie 不一致→403(${forged2.body?.reason})，合法请求→${legit.status}`
        : `防护失效（${forged1.status}/${forged2.status}/${legit.status}）`,
    },
    passed: vulnExploited && honoBlocked,
  };
}

/** A4：Cookie 安全属性对照 */
async function attackCookieFlags(servers: RunningServers): Promise<ScenarioResult> {
  const vulnRes = await new HttpClient().get(servers.vulnerable.base, '/api/session');
  const vulnCookie = vulnRes.rawCookies.find((c) => c.startsWith('SID=')) ?? '';
  const vulnWeak =
    !vulnCookie.includes('HttpOnly') &&
    !vulnCookie.includes('Secure') &&
    !vulnCookie.includes('SameSite') &&
    !vulnCookie.includes('__Host-');

  const secRes = await new HttpClient().get(servers.secureExpress.base, '/api/csrf');
  const secCookie = secRes.rawCookies.find((c) => c.startsWith('sid=')) ?? '';
  // 演示配置关了 hostPrefix 以走 http，但 HttpOnly + SameSite 必须在
  const secHardened = secCookie.includes('HttpOnly') && secCookie.includes('SameSite=Lax');

  const honoRes = await new HttpClient().get(servers.secureHono.base, '/api/csrf');
  const honoCookie = honoRes.rawCookies.find((c) => c.startsWith('sid=')) ?? '';
  const honoHardened = honoCookie.includes('HttpOnly') && honoCookie.includes('SameSite=Lax');

  return {
    id: 'A4',
    title: 'Cookie 安全属性缺失',
    vulnerable: {
      verdict: vulnWeak ? 'exploited' : 'blocked',
      detail: `漏洞站 cookie: "${vulnCookie}" —— XSS 可读、跨站自动携带、可被子域覆盖`,
    },
    secure: {
      verdict: secHardened ? 'blocked' : 'exploited',
      detail: `安全站 cookie: "${secCookie}"（生产开 hostPrefix 时为 __Host-sid; Secure; Path=/）`,
    },
    secureHono: {
      verdict: honoHardened ? 'blocked' : 'exploited',
      detail: `Hono 版 cookie: "${honoCookie}"`,
    },
    passed: vulnWeak && secHardened && honoHardened,
  };
}

/** A5：空闲超时 —— 静默超过 idleTimeout 后会话应失效 */
async function attackIdleTimeout(servers: RunningServers): Promise<ScenarioResult> {
  // 漏洞站：无超时概念，等 2.5s（安全站的 idle 窗口）后旧 SID 仍有效
  const v = new HttpClient();
  v.absorb(await v.post(servers.vulnerable.base, '/api/login', {
    username: 'alice',
    password: 'alice-pw',
  }));
  await sleep(2500);
  const vProbe = await v.get(servers.vulnerable.base, '/api/balance');
  const vulnExploited = vProbe.status === 200;

  // 安全站：idle=2s，静默 2.5s 后应被判 idle 超时
  const s = new HttpClient();
  s.absorb(await s.get(servers.secureExpress.base, '/api/csrf'));
  const sLogin = await s.post(
    servers.secureExpress.base,
    '/api/login',
    { username: 'alice', password: 'alice-pw' },
    { 'x-csrf-token': s.cookieValue('csrf_token') },
  );
  s.absorb(sLogin);
  const sidBefore = s.cookieValue('sid');
  await sleep(2500);
  const sProbe = await s.get(servers.secureExpress.base, '/api/balance');
  // 超时响应会下发新的匿名 SID，吸收后再比较
  s.absorb(sProbe);
  const sidAfter = s.cookieValue('sid');
  const issuedNewSession = sProbe.rawCookies.some((c) => c.startsWith('sid='));
  // 超时后引擎销毁旧会话并下发匿名新会话；旧 SID 不再认证
  const secBlocked = sProbe.status === 401 && issuedNewSession && sidAfter !== sidBefore;

  return {
    id: 'A5',
    title: '空闲超时缺失（静默 2.5s）',
    vulnerable: {
      verdict: vulnExploited ? 'exploited' : 'blocked',
      detail: `漏洞站会话无寿命，静默后 /api/balance 仍返回 ${vProbe.status}`,
    },
    secure: {
      verdict: secBlocked ? 'blocked' : 'exploited',
      detail: secBlocked
        ? `空闲 2s 过期，旧 SID 被销毁，/api/balance 返回 401 并签发新匿名 SID`
        : `超时未生效（status=${sProbe.status}）`,
    },
    passed: vulnExploited && secBlocked,
  };
}

/** A6：绝对超时 —— 持续活动也不能突破 absoluteTimeout */
async function attackAbsoluteTimeout(servers: RunningServers): Promise<ScenarioResult> {
  // 漏洞站：持续活动，6s 后仍然有效
  const v = new HttpClient();
  v.absorb(await v.post(servers.vulnerable.base, '/api/login', {
    username: 'alice',
    password: 'alice-pw',
  }));
  for (let i = 0; i < 3; i++) {
    await sleep(1800);
    await v.get(servers.vulnerable.base, '/api/session');
  }
  const vProbe = await v.get(servers.vulnerable.base, '/api/balance');
  const vulnExploited = vProbe.status === 200;

  // 安全站：absolute=5s，每 1.5s 活动一次（不触发 idle=2s），越过 5s 后必须失效
  const s = new HttpClient();
  s.absorb(await s.get(servers.secureExpress.base, '/api/csrf'));
  s.absorb(
    await s.post(
      servers.secureExpress.base,
      '/api/login',
      { username: 'alice', password: 'alice-pw' },
      { 'x-csrf-token': s.cookieValue('csrf_token') },
    ),
  );
  const sidBefore = s.cookieValue('sid');
  let lastStatus = 0;
  for (let i = 0; i < 4; i++) {
    await sleep(1500);
    const r = await s.get(servers.secureExpress.base, '/api/balance');
    lastStatus = r.status;
    s.absorb(r);
  }
  const secBlocked = lastStatus === 401 && s.cookieValue('sid') !== sidBefore;

  return {
    id: 'A6',
    title: '绝对超时缺失（持续活动 6s）',
    vulnerable: {
      verdict: vulnExploited ? 'exploited' : 'blocked',
      detail: `漏洞站会话永生，持续活动 6s 后 /api/balance 仍返回 ${vProbe.status}`,
    },
    secure: {
      verdict: secBlocked ? 'blocked' : 'exploited',
      detail: secBlocked
        ? `绝对寿命 5s 到期，即便每 1.5s 活跃也被强制注销，末次 /api/balance=${lastStatus}`
        : `绝对超时未生效（lastStatus=${lastStatus}）`,
    },
    passed: vulnExploited && secBlocked,
  };
}

/** A7：并发会话上限 + 一键踢下线 */
async function attackConcurrencyAndKick(servers: RunningServers): Promise<ScenarioResult> {
  // 漏洞站：连登 4 次，服务端会话数只增不减，旧会话全部存活，无法吊销
  const vulnClients: HttpClient[] = [];
  for (let i = 0; i < 4; i++) {
    const c = new HttpClient();
    c.absorb(await c.post(servers.vulnerable.base, '/api/login', {
      username: 'alice',
      password: 'alice-pw',
    }));
    vulnClients.push(c);
  }
  const count = (await new HttpClient().get(servers.vulnerable.base, '/api/_debug/session-count')).body?.count;
  const oldestStillAlive = (await vulnClients[0]!.get(servers.vulnerable.base, '/api/balance')).status === 200;
  const vulnExploited = count >= 4 && oldestStillAlive;

  // 安全站 Express：上限 2，第 3、4 次登录会挤掉最旧会话
  // 同步令牌模式下 token 在响应 body 里（不是 cookie），从 body 取
  const secClients: HttpClient[] = [];
  for (let i = 0; i < 4; i++) {
    const c = new HttpClient();
    const warm = await c.get(servers.secureExpress.base, '/api/csrf');
    c.absorb(warm);
    c.absorb(
      await c.post(
        servers.secureExpress.base,
        '/api/login',
        { username: 'alice', password: 'alice-pw' },
        { 'x-csrf-token': warm.body.csrfToken },
      ),
    );
    await sleep(20); // 保证 createdAt 严格递增
    secClients.push(c);
  }
  const oldest = secClients[0]!;
  const oldestProbe = await oldest.get(servers.secureExpress.base, '/api/balance');
  const newest = secClients[3]!;
  const newestProbe = await newest.get(servers.secureExpress.base, '/api/balance');
  const limitWorks = oldestProbe.status === 401 && newestProbe.status === 200;

  // 一键踢下线：管理员（独立会话）带 CSRF token 踢 alice，最新会话也立即失效
  const admin = new HttpClient();
  const adminWarm = await admin.get(servers.secureExpress.base, '/api/csrf');
  admin.absorb(adminWarm);
  const adminLogin = await admin.post(
    servers.secureExpress.base,
    '/api/login',
    { username: 'bob', password: 'bob-pw' },
    { 'x-csrf-token': adminWarm.body.csrfToken },
  );
  admin.absorb(adminLogin);
  const kick = await admin.post(
    servers.secureExpress.base,
    '/api/admin/kick-user',
    { userId: 'alice' },
    { 'x-csrf-token': adminLogin.body.csrfToken },
  );
  const afterKick = await newest.get(servers.secureExpress.base, '/api/balance');
  const kickWorks = kick.status === 200 && Array.isArray(kick.body?.killed) && afterKick.status === 401;

  return {
    id: 'A7',
    title: '并发会话无上限 / 无法踢下线',
    vulnerable: {
      verdict: vulnExploited ? 'exploited' : 'blocked',
      detail: `连登 4 次后服务端残留 ${count} 个会话，最早会话仍可访问（status=200），无吊销手段`,
    },
    secure: {
      verdict: limitWorks && kickWorks ? 'blocked' : 'exploited',
      detail:
        limitWorks && kickWorks
          ? `上限 2：最旧会话被挤掉(401)、最新会话存活(200)；管理员 kick-user 后最新会话也变 401`
          : `上限/踢人异常（limit=${limitWorks}, kick=${kickWorks}）`,
    },
    passed: vulnExploited && limitWorks && kickWorks,
  };
}
