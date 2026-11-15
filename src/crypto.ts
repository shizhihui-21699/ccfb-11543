/**
 * 安全相关的底层原语，全部基于 node:crypto，零第三方依赖。
 */
import {
  randomBytes,
  createHmac,
  createHash,
  timingSafeEqual,
} from 'node:crypto';

/** 生成高熵随机会话 ID（base64url，无填充） */
export function randomId(bytes = 32): string {
  return randomBytes(bytes).toString('base64url');
}

/** 生成 CSRF token（与 session id 同样使用 256 位熵） */
export function randomCsrfToken(bytes = 32): string {
  return randomBytes(bytes).toString('base64url');
}

/** HMAC-SHA256，输出 base64url */
export function hmacSign(secret: string, message: string): string {
  return createHmac('sha256', secret).update(message).digest('base64url');
}

/**
 * 双提交 token 设计：token = payload.signature
 * payload 本身是随机串（不携带身份信息），signature 让攻击者无法自行铸造。
 * 校验时重新计算签名并做恒定时间比较。
 */
export function signToken(secret: string, payload: string): string {
  return `${payload}.${hmacSign(secret, payload)}`;
}

export function verifySignedToken(
  secret: string,
  token: string,
): boolean {
  const dot = token.lastIndexOf('.');
  if (dot <= 0) return false;
  const payload = token.slice(0, dot);
  const sig = token.slice(dot + 1);
  const expected = hmacSign(secret, payload);
  // 长度不一致时 timingSafeEqual 会抛错，先做长度判断（长度本身不是秘密）
  if (sig.length !== expected.length) return false;
  try {
    return timingSafeEqual(Buffer.from(sig), Buffer.from(expected));
  } catch {
    return false;
  }
}

/** 恒定时间比较两个等长字符串（同步令牌比对用） */
export function safeEqual(a: string, b: string): boolean {
  const ba = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ba.length !== bb.length) return false;
  return timingSafeEqual(ba, bb);
}

/** SHA-256 摘要，用于演示脚本里给 cookie 做指纹、日志脱敏等 */
export function sha256(s: string): string {
  return createHash('sha256').update(s).digest('base64url');
}
