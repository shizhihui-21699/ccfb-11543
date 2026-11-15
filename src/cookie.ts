/**
 * Cookie 解析与序列化（不依赖第三方 cookie 包）。
 * 重点：__Host- 前缀的强制规则在一个地方集中实现，避免适配器各自拼错。
 */
import type { SameSite } from './types.js';

export interface SetCookieOptions {
  name: string;
  value: string;
  /** 启用 __Host- 前缀 */
  hostPrefix: boolean;
  httpOnly: boolean;
  secure: boolean;
  sameSite: SameSite;
  path?: string;
  /** 最大存活秒数；传 0 表示立即删除（Max-Age=0） */
  maxAgeSeconds?: number;
}

/**
 * 序列化 Set-Cookie 头的值。
 * __Host- 规则（RFC 6265bis）：必须 Secure、不得带 Domain、Path 必须为 /。
 * SameSite=None 时浏览器强制要求 Secure。
 */
export function serializeSetCookie(opts: SetCookieOptions): string {
  const name = opts.hostPrefix ? ensureHostPrefix(opts.name) : stripHostPrefix(opts.name);
  const parts = [`${name}=${opts.value}`];

  if (opts.hostPrefix) {
    parts.push('Path=/');
    parts.push('Secure');
  } else if (opts.path) {
    parts.push(`Path=${opts.path}`);
  }
  if (opts.secure && !opts.hostPrefix) parts.push('Secure');

  parts.push(
    opts.sameSite === 'none'
      ? 'SameSite=None'
      : opts.sameSite === 'strict'
        ? 'SameSite=Strict'
        : 'SameSite=Lax',
  );
  // SameSite=None 必须配 Secure，否则现代浏览器直接拒绝该 cookie
  if (opts.sameSite === 'none' && !parts.includes('Secure')) {
    parts.push('Secure');
  }
  if (opts.httpOnly) parts.push('HttpOnly');
  if (opts.maxAgeSeconds !== undefined) {
    parts.push(`Max-Age=${Math.max(0, Math.floor(opts.maxAgeSeconds))}`);
  }
  return parts.join('; ');
}

function ensureHostPrefix(name: string): string {
  return name.startsWith('__Host-') ? name : `__Host-${name}`;
}

function stripHostPrefix(name: string): string {
  return name.startsWith('__Host-') ? name.slice('__Host-'.length) : name;
}

/** 返回最终写进 Cookie 头 / 从 Cookie 头读取时使用的名字 */
export function effectiveCookieName(name: string, hostPrefix: boolean): string {
  return hostPrefix ? ensureHostPrefix(name) : stripHostPrefix(name);
}

/**
 * 解析请求的 Cookie 头为 map。
 * 只做朴素拆分；会话 ID 是 base64url，不含分号/逗号/空格/等号之外的特殊字符。
 */
export function parseCookieHeader(header: string | undefined | null): Record<string, string> {
  const out: Record<string, string> = {};
  if (!header) return out;
  for (const piece of header.split(';')) {
    const eq = piece.indexOf('=');
    if (eq < 1) continue;
    const key = piece.slice(0, eq).trim();
    const val = piece.slice(eq + 1).trim();
    if (key) out[key] = val;
  }
  return out;
}
