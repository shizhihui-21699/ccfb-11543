/**
 * 攻击测试脚本：对三个站点（1 个故意有漏洞 + 2 个加固站）跑同一组攻击，
 * 用结果对比证明会话固定与 CSRF 防护真实有效。
 *
 * 攻击清单：
 *   A. 会话固定（Session Fixation）
 *      攻击者预先取得/指定一个会话 ID，诱使受害者用它登录，
 *      然后攻击者用同一 ID 访问受害者账户。
 *   B. CSRF（跨站请求伪造）
 *      攻击者在第三方页面构造状态变更请求，借浏览器自动携带的 cookie 发起。
 *      脚本模拟"只带 cookie、不带/带错误 CSRF 令牌"的跨站请求。
 *
 * 预期：
 *   - 漏洞站：A 得手（攻击者拿到已认证会话）、B 得手（转账被执行）
 *   - 加固站：A 失败（登录轮转 ID，旧 ID 失效）、B 失败（403）
 *
 * 用法：npm run attack   （会自动启动三个示例站，跑完自动关闭）
 */
import { spawn, type ChildProcess } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
// 编译后位于 dist/scripts，工程根是上两级；tsc 源码运行时这里是 scripts，同样上两级
const root = join(here, "..", "..");
const distRoot = join(root, "dist");

interface Target {
  name: string;
  port: number;
  entry: string;
  csrfMode: "none" | "sync-token" | "double-submit";
}

const TARGETS: Target[] = [
  { name: "vulnerable", port: 4101, entry: join(distRoot, "examples/vulnerable-app/server.js"), csrfMode: "none" },
  { name: "secure-express", port: 4102, entry: join(distRoot, "examples/secure-express/server.js"), csrfMode: "sync-token" },
  { name: "secure-hono", port: 4103, entry: join(distRoot, "examples/secure-hono/server.js"), csrfMode: "double-submit" },
];

/** 极简 cookie 罐，模拟浏览器自动携带 */
class Jar {
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
  header(): string {
    return [...this.values].map(([k, v]) => `${k}=${v}`).join("; ");
  }
  get(name: string): string | undefined {
    return this.values.get(name);
  }
}

interface AttackResult {
  attack: string;
  target: string;
  expected: "BLOCKED" | "EXPLOITED";
  actual: "BLOCKED" | "EXPLOITED";
  detail: string;
}

const results: AttackResult[] = [];

function record(attack: string, t: Target, expected: "BLOCKED" | "EXPLOITED", actual: "BLOCKED" | "EXPLOITED", detail: string): void {
  results.push({ attack, target: t.name, expected, actual, detail });
}

async function waitReady(port: number, timeoutMs = 8000): Promise<void> {
  const net = await import("node:net");
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const ok = await new Promise<boolean>((resolve) => {
      const sock = net.createConnection({ port, host: "127.0.0.1" });
      sock.once("connect", () => {
        sock.end();
        resolve(true);
      });
      sock.once("error", () => resolve(false));
    });
    if (ok) return;
    if (Date.now() > deadline) throw new Error(`端口 ${port} 等待超时`);
    await new Promise((r) => setTimeout(r, 120));
  }
}

// ---------- 攻击 A：会话固定 ----------
async function attackSessionFixation(t: Target): Promise<void> {
  const base = `http://127.0.0.1:${t.port}`;

  // 1) 攻击者先访问站点，拿到一个会话 ID（漏洞站还允许直接指定）
  const attackerJar = new Jar();
  if (t.csrfMode === "none") {
    // 漏洞站：攻击者通过 URL 直接固定一个自己选定的 ID
    const fixedId = "attacker-fixed-sid-12345";
    const r = await fetch(`${base}/?sid=${fixedId}`);
    attackerJar.absorb(r);
  } else {
    const r = await fetch(base);
    attackerJar.absorb(r);
  }
  const sidName = t.csrfMode === "none" ? "sid" : "__Host-session.sid";
  const attackerKnownSid = attackerJar.get(sidName)!;

  // 2) 受害者在不知情的情况下带着这个 ID 登录
  const victimJar = new Jar();
  // 模拟受害者浏览器被种下了攻击者的会话 ID
  victimJar.absorb(new Response(null, {
    headers: { "Set-Cookie": `${sidName}=${attackerKnownSid}; Path=/` },
  }));
  const loginHeaders: Record<string, string> = {
    "content-type": "application/json",
    cookie: victimJar.header(),
  };
  // 加固站的 /login 豁免 CSRF，无需令牌
  const loginRes = await fetch(`${base}/login`, {
    method: "POST",
    headers: loginHeaders,
    body: JSON.stringify({ username: "victim", password: "pw" }),
  });
  victimJar.absorb(loginRes);

  // 3) 攻击者用自己掌握的旧 ID 去访问 /me，看是否已经是受害者的登录态
  const probe = await fetch(`${base}/me`, {
    headers: { cookie: `${sidName}=${attackerKnownSid}` },
  });
  const body = (await probe.json().catch(() => ({}))) as { userId?: string | null };
  const exploited = body.userId === "victim";

  record(
    "会话固定 (Session Fixation)",
    t,
    t.csrfMode === "none" ? "EXPLOITED" : "BLOCKED",
    exploited ? "EXPLOITED" : "BLOCKED",
    exploited
      ? `攻击者用固定 ID 读到受害者身份 userId=${body.userId}`
      : `旧 ID 登录后已失效，/me 返回 userId=${body.userId ?? "null"}（攻击者拿不到登录态）`,
  );
}

// ---------- 攻击 B：CSRF ----------
async function attackCsrf(t: Target): Promise<void> {
  const base = `http://127.0.0.1:${t.port}`;
  const victim = new Jar();

  // 受害者正常登录
  const warm = await fetch(base);
  victim.absorb(warm);
  const login = await fetch(`${base}/login`, {
    method: "POST",
    headers: { "content-type": "application/json", cookie: victim.header() },
    body: JSON.stringify({ username: "victim", password: "pw" }),
  });
  victim.absorb(login);

  // 攻击者从第三方站点发起跨站 POST：浏览器会自动带 cookie，但攻击者拿不到 CSRF 令牌。
  // 场景 1：完全不带令牌
  const noToken = await fetch(`${base}/transfer`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      cookie: victim.header(), // 只有 cookie，没有 x-csrf-token
    },
    body: JSON.stringify({ to: "attacker", amount: 9999 }),
  });

  // 场景 2：带一个攻击者瞎猜的令牌
  const guessed = await fetch(`${base}/transfer`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      cookie: victim.header(),
      "x-csrf-token": "forged-token-by-attacker",
    },
    body: JSON.stringify({ to: "attacker", amount: 9999 }),
  });

  // 验证转账是否真的落库：受害者自己读 /me
  const me = await fetch(`${base}/me`, { headers: { cookie: victim.header() } });
  const meBody = (await me.json()) as { data?: { lastTransfer?: unknown } };
  const transferWentThrough =
    noToken.ok || guessed.ok
      ? true
      : (meBody.data?.lastTransfer != null &&
         JSON.stringify(meBody.data.lastTransfer).includes("attacker"));

  const blocked = noToken.status === 403 && guessed.status === 403 && !transferWentThrough;
  record(
    "CSRF（无令牌/伪造令牌的跨站转账）",
    t,
    t.csrfMode === "none" ? "EXPLOITED" : "BLOCKED",
    blocked ? "BLOCKED" : "EXPLOITED",
    blocked
      ? `两次跨站请求均被 403 拒绝（${noToken.status}/${guessed.status}），转账未执行`
      : `无令牌请求返回 ${noToken.status}、伪造令牌返回 ${guessed.status}，攻击者转账已进入会话数据`,
  );
}

// ---------- 主流程 ----------
async function main(): Promise<void> {
  const procs: ChildProcess[] = [];
  try {
    for (const t of TARGETS) {
      const proc = spawn(process.execPath, [t.entry], {
        cwd: root,
        env: { ...process.env, PORT: String(t.port) },
        stdio: ["ignore", "pipe", "pipe"],
      });
      procs.push(proc);
      proc.stdout?.on("data", () => {});
      proc.stderr?.on("data", (d) => process.stderr.write(`[${t.name}] ${d}`));
    }
    await Promise.all(TARGETS.map((t) => waitReady(t.port)));
    console.log("三个目标站点均已就绪，开始攻击测试…\n");

    for (const t of TARGETS) {
      await attackSessionFixation(t);
      await attackCsrf(t);
    }
  } finally {
    for (const p of procs) p.kill("SIGTERM");
  }

  // 输出报告
  console.log("=".repeat(78));
  console.log("攻击测试结果对比");
  console.log("=".repeat(78));
  let allMatch = true;
  for (const r of results) {
    const pass = r.actual === r.expected;
    if (!pass) allMatch = false;
    const icon = pass ? "✅" : "❌";
    console.log(
      `${icon} [${r.target.padEnd(14)}] ${r.attack}\n` +
        `    预期 ${r.expected.padEnd(9)} 实际 ${r.actual.padEnd(9)} ${r.detail}`,
    );
  }
  console.log("=".repeat(78));
  console.log(allMatch
    ? "结论：漏洞站如期被攻破，两个加固站全部拦截，防护有效。"
    : "结论：存在预期不符的用例，请检查 ❌ 项。");
  process.exitCode = allMatch ? 0 : 1;
}

main().catch((err) => {
  console.error("攻击脚本执行失败:", err);
  process.exitCode = 2;
});
