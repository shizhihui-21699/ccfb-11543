/**
 * 框架无关的 HTTP 上下文抽象。
 * Express / Hono 适配器把各自的 req/res 翻译成这一个接口，
 * 核心引擎只依赖它，不 import 任何框架代码。
 */
export interface WebContext {
  /** 小写方法名 */
  method: string;
  /** 原始路径（不含 query） */
  path: string;
  /** 取请求头（不区分大小写），不存在返回 undefined */
  header(name: string): string | undefined;
  /** 读 cookie 解析结果 */
  cookies: Record<string, string>;
  /** 追加一个 Set-Cookie 响应头（允许同名多次出现） */
  setCookie(name: string, value: string, attrs: CookieAttrs): void;
  /** 读 query 参数（CSRF token 允许走 query 作为兜底） */
  query(name: string): string | undefined;
  /** 读 JSON/表单 body 的字段；body 未解析时返回 undefined */
  bodyField(name: string): unknown;
  /** 引擎挂载的会话守卫，适配器把它转挂到框架的 req 上 */
  guard?: unknown;
  /** 引擎标记：本请求命中的超时类型，适配器可用于响应体提示 */
  sessionExpired?: "idle" | "absolute";
}

export interface CookieAttrs {
  /** 秒；会话 cookie（浏览器关闭失效）时不传 */
  maxAge?: number;
  domain?: string;
  path?: string;
  secure?: boolean;
  httpOnly?: boolean;
  sameSite?: "Strict" | "Lax" | "None";
}

/** 极简 cookie 解析（不引入第三方依赖） */
export function parseCookies(cookieHeader: string | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  if (!cookieHeader) return out;
  for (const part of cookieHeader.split(";")) {
    const eq = part.indexOf("=");
    if (eq === -1) continue;
    const key = part.slice(0, eq).trim();
    if (!key) continue;
    out[key] = decodeURIComponent(part.slice(eq + 1).trim());
  }
  return out;
}

/** 序列化单个 Set-Cookie 值 */
export function serializeCookie(name: string, value: string, attrs: CookieAttrs): string {
  let out = `${name}=${encodeURIComponent(value)}`;
  if (attrs.maxAge !== undefined) out += `; Max-Age=${Math.floor(attrs.maxAge)}`;
  if (attrs.domain) out += `; Domain=${attrs.domain}`;
  out += `; Path=${attrs.path ?? "/"}`;
  if (attrs.secure) out += "; Secure";
  if (attrs.httpOnly !== false) out += "; HttpOnly";
  if (attrs.sameSite) out += `; SameSite=${attrs.sameSite}`;
  return out;
}
