/**
 * 攻击脚本用的极简 HTTP 客户端 + cookie jar。
 * 不引第三方库，直接用全局 fetch（Node 18+），手动管理 Set-Cookie，
 * 以便精确模拟“浏览器自动带 cookie”“攻击者只持有固定 SID”等不同身份。
 */
export interface HttpResponse {
  status: number;
  headers: Headers;
  body: any;
  rawCookies: string[];
}

export class HttpClient {
  private readonly jar = new Map<string, string>();
  /** 当次请求要额外附加的 cookie（模拟跨站请求伪造时浏览器仍会自动带的 cookie） */
  private extraCookies: Record<string, string> = {};

  /** 吸收响应里的 Set-Cookie（只取 name=value，属性由测试单独断言） */
  absorb(res: HttpResponse): void {
    for (const sc of res.rawCookies) {
      const pair = sc.split(';')[0]!;
      const eq = pair.indexOf('=');
      if (eq > 0) this.jar.set(pair.slice(0, eq).trim(), pair.slice(eq + 1).trim());
    }
  }

  /** 只读取 cookie 值，不吸收（用于断言 cookie 属性） */
  cookieValue(name: string): string | undefined {
    return this.jar.get(name);
  }

  setExtraCookie(name: string, value: string): void {
    this.extraCookies[name] = value;
  }

  clearExtraCookies(): void {
    this.extraCookies = {};
  }

  /** 丢弃 jar 里的指定 cookie（模拟登出/清除） */
  dropCookie(name: string): void {
    this.jar.delete(name);
  }

  private cookieHeader(): string {
    const all = new Map(this.jar);
    for (const [k, v] of Object.entries(this.extraCookies)) all.set(k, v);
    return [...all.entries()].map(([k, v]) => `${k}=${v}`).join('; ');
  }

  async get(base: string, path: string, headers: Record<string, string | undefined> = {}): Promise<HttpResponse> {
    return this.request(base, path, { method: 'GET', headers });
  }

  async post(
    base: string,
    path: string,
    body?: unknown,
    headers: Record<string, string | undefined> = {},
  ): Promise<HttpResponse> {
    const h: Record<string, string | undefined> = { ...headers };
    let payload: string | undefined;
    if (body !== undefined) {
      h['content-type'] = h['content-type'] ?? 'application/json';
      payload = JSON.stringify(body);
    }
    return this.request(base, path, { method: 'POST', headers: h, body: payload });
  }

  private async request(
    base: string,
    path: string,
    init: { method: string; headers: Record<string, string | undefined>; body?: string },
  ): Promise<HttpResponse> {
    const cookie = this.cookieHeader();
    const headers = new Headers();
    for (const [k, v] of Object.entries(init.headers)) {
      // 跳过 undefined，避免把字符串 "undefined" 发出去
      if (v !== undefined) headers.set(k, v);
    }
    if (cookie) headers.set('cookie', cookie);
    const res = await fetch(`${base}${path}`, {
      method: init.method,
      headers,
      body: init.body,
    });
    const rawCookies = res.headers.getSetCookie?.() ?? [];
    const text = await res.text();
    let parsed: any = null;
    try {
      parsed = text ? JSON.parse(text) : null;
    } catch {
      parsed = text;
    }
    return { status: res.status, headers: res.headers, body: parsed, rawCookies };
  }
}

/** 等待 HTTP 服务就绪（轮询 /api/session 或指定路径） */
export async function waitReady(base: string, path = '/api/session', timeoutMs = 5000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  let lastErr: unknown;
  while (Date.now() < deadline) {
    try {
      const res = await fetch(`${base}${path}`);
      if (res.status < 500) return;
    } catch (err) {
      lastErr = err;
    }
    await new Promise((r) => setTimeout(r, 50));
  }
  throw new Error(`服务 ${base} 未在 ${timeoutMs}ms 内就绪: ${String(lastErr)}`);
}
