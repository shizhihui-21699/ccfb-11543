/**
 * 安全站共享配置：短超时便于攻击脚本在秒级验证空闲/绝对过期。
 */
import type { SessionEngineOptions } from '../../src/types.js';

export const SECURE_ENGINE_DEFAULTS = {
  // 本地 http 演示关闭 __Host（__Host 强制 Secure，http 下浏览器不收）；
  // 攻击脚本里单独验证“生产配置”下的 cookie 属性字符串。
  hostPrefix: false,
  sameSite: 'lax' as const,
  idleTimeoutMs: 2_000,
  absoluteTimeoutMs: 5_000,
  maxSessionsPerUser: 2,
  idBytes: 32,
} satisfies Partial<SessionEngineOptions>;

export const DEMO_CSRF_SECRET =
  'demo-only-csrf-secret-change-me-0123456789abcdefABCDEF';
