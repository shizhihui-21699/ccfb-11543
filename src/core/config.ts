import type { Clock, SessionStore } from "./types.js";

export type CsrfMode = "sync-token" | "double-submit" | "off";

export interface SessionConfig {
  store: SessionStore;
  clock?: Clock;

  /** 会话 cookie 名，默认 __Host-session.sid */
  cookieName?: string;
  /** 双提交 CSRF cookie 名（仅 double-submit 模式使用），默认 __Host-csrf.token */
  csrfCookieName?: string;
  /** 同步令牌模式下，前端读取 token 的响应头名 */
  csrfHeaderName?: string;

  /** 空闲超时：无活动多久后会话失效（毫秒），默认 30 分钟 */
  idleTimeoutMs?: number;
  /** 绝对超时：会话最长存活时间，无论是否活动（毫秒），默认 12 小时 */
  absoluteTimeoutMs?: number;

  /**
   * 同一账号并发会话上限。超过后新登录挤掉最老的会话。默认 5，0 表示不限。
   */
  maxSessionsPerUser?: number;

  /** CSRF 模式，默认 sync-token */
  csrf?: CsrfMode;
  /** 豁免 CSRF 校验的方法（默认安全方法 GET/HEAD/OPTIONS） */
  csrfSafeMethods?: string[];
  /** 这些路径前缀跳过 CSRF（如登录接口本身），匹配 path.startsWith */
  csrfExemptPrefixes?: string[];

  /**
   * 关闭 __Host 前缀强制。仅允许本地 http 开发使用——__Host 要求 Secure +
   * 无 Domain + Path=/，生产环境永远不要关。
   */
  allowInsecureLocal?: boolean;
}

export interface ResolvedConfig extends Required<Omit<SessionConfig, "store" | "clock">> {
  store: SessionStore;
  clock: Clock;
}

export const DEFAULTS = {
  cookieName: "__Host-session.sid",
  csrfCookieName: "__Host-csrf.token",
  csrfHeaderName: "x-csrf-token",
  idleTimeoutMs: 30 * 60 * 1000,
  absoluteTimeoutMs: 12 * 60 * 60 * 1000,
  maxSessionsPerUser: 5,
  csrf: "sync-token" as CsrfMode,
  csrfSafeMethods: ["GET", "HEAD", "OPTIONS"],
  csrfExemptPrefixes: [] as string[],
  allowInsecureLocal: false,
};

export function resolveConfig(config: SessionConfig): ResolvedConfig {
  return {
    ...DEFAULTS,
    ...config,
    store: config.store,
    clock: config.clock ?? { now: () => Date.now() },
    csrfSafeMethods: (config.csrfSafeMethods ?? DEFAULTS.csrfSafeMethods).map((m) =>
      m.toUpperCase()
    ),
    csrfExemptPrefixes: config.csrfExemptPrefixes ?? DEFAULTS.csrfExemptPrefixes,
  };
}
