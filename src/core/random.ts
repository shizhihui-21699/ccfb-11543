import { randomBytes, randomUUID, timingSafeEqual as nodeTimingSafeEqual } from "node:crypto";

/** 常量时间字符串比较，防止 CSRF token / 会话 ID 比较的时序侧信道 */
export function timingSafeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a, "utf8");
  const bb = Buffer.from(b, "utf8");
  if (ab.length !== bb.length) {
    // 长度不同也要做一次等长比较，把耗时差异压到最小
    const padding = Buffer.alloc(ab.length);
    nodeTimingSafeEqual(ab, padding);
    return false;
  }
  return nodeTimingSafeEqual(ab, bb);
}

/** 生成高熵随机会话 ID（256 bit 熵，URL 安全） */
export function generateSessionId(): string {
  return randomBytes(32).toString("base64url");
}

/** 生成 CSRF token（128 bit 熵即可） */
export function generateCsrfToken(): string {
  return randomBytes(16).toString("base64url");
}

/** 生成不带连字符的随机标识（测试中起 redis 端口目录等场景用） */
export function randomLabel(): string {
  return randomUUID().replace(/-/g, "");
}
