import assert from "node:assert/strict";
import type { CookieAttrs, WebContext } from "../src/http/context.js";
import type { Clock } from "../src/core/types.js";

/** 可控时钟：测试里手动推进时间，确定性验证超时 */
export class FakeClock implements Clock {
  private t: number;
  constructor(start = 1_000_000_000_000) {
    this.t = start;
  }
  now(): number {
    return this.t;
  }
  advance(ms: number): void {
    this.t += ms;
  }
}

export interface SetCookieRecord {
  name: string;
  value: string;
  attrs: CookieAttrs;
  raw: string;
}

/** 内存版 WebContext：不经过真实 socket，直接驱动引擎 */
export class FakeContext implements WebContext {
  method = "GET";
  path = "/";
  cookies: Record<string, string> = {};
  guard?: unknown;
  sessionExpired?: "idle" | "absolute";
  requestHeaders: Record<string, string> = {};
  queryParams: Record<string, string> = {};
  body: Record<string, unknown> = {};
  setCookies: SetCookieRecord[] = [];

  constructor(init?: Partial<Pick<FakeContext, "method" | "path">>) {
    if (init?.method) this.method = init.method;
    if (init?.path) this.path = init.path;
  }

  header(name: string): string | undefined {
    return this.requestHeaders[name.toLowerCase()];
  }

  setCookie(name: string, value: string, attrs: CookieAttrs): void {
    this.setCookies.push({ name, value, attrs, raw: serialize(name, value, attrs) });
    if (value === "" && attrs.maxAge === 0) {
      delete this.cookies[name];
    } else {
      this.cookies[name] = value;
    }
  }

  query(name: string): string | undefined {
    return this.queryParams[name];
  }

  bodyField(name: string): unknown {
    return this.body[name];
  }

  /** 模拟浏览器：把 Set-Cookie 的值带到下一个请求的 cookie 头 */
  carryCookies(next: FakeContext): FakeContext {
    next.cookies = { ...this.cookies };
    return next;
  }

  /** 取最近一次同名 Set-Cookie */
  lastCookie(name: string): SetCookieRecord | undefined {
    return [...this.setCookies].reverse().find((c) => c.name === name);
  }
}

function serialize(name: string, value: string, attrs: CookieAttrs): string {
  let out = `${name}=${value}`;
  if (attrs.maxAge !== undefined) out += `; Max-Age=${attrs.maxAge}`;
  out += `; Path=${attrs.path ?? "/"}`;
  if (attrs.secure) out += "; Secure";
  if (attrs.httpOnly !== false) out += "; HttpOnly";
  if (attrs.sameSite) out += `; SameSite=${attrs.sameSite}`;
  return out;
}

export const expect = assert;
