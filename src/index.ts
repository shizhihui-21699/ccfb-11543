// 核心
export { SessionEngine } from "./core/engine.js";
export { SessionGuard, SessionError } from "./core/guard.js";
export {
  resolveConfig,
  DEFAULTS,
  type SessionConfig,
  type ResolvedConfig,
  type CsrfMode,
} from "./core/config.js";
export {
  type SessionStore,
  type SessionRecord,
  type Clock,
} from "./core/types.js";
export {
  generateSessionId,
  generateCsrfToken,
  timingSafeEqual,
} from "./core/random.js";

// HTTP 抽象
export {
  type WebContext,
  type CookieAttrs,
  parseCookies,
  serializeCookie,
} from "./http/context.js";

// 框架适配器
export { expressSession } from "./adapters/express.js";
export { honoSession, type SessionHonoVariables } from "./adapters/hono.js";

// 存储实现
export { MemoryStore } from "./stores/memory-store.js";
export { RedisStore, type RedisStoreOptions } from "./stores/redis-store.js";
export { RedisClient, type RedisClientOptions } from "./stores/redis-client.js";
