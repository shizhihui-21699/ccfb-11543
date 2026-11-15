/**
 * 真实 Redis 集成测试 —— 默认 skip。
 *
 * 本机/CI 装有 Redis 时这样运行：
 *   REDIS_URL=redis://127.0.0.1:6379 npx vitest run tests/redis-live.test.ts
 *
 * 没有 Redis 时本文件整体跳过；离线的 RESP 语义由 FakeRedis 在 store-contract 里覆盖。
 */
import { describe, it, expect } from 'vitest';
import { RedisSessionStore } from '../src/stores/redis.js';
import type { RedisLike } from '../src/stores/redis.js';
import type { SessionRecord } from '../src/types.js';

const redisUrl = process.env.REDIS_URL;

describe.skipIf(!redisUrl)('真实 Redis 存储集成', () => {
  let client: RedisLike & { quit?: () => Promise<string> };
  let store: RedisSessionStore;
  const runId = `live-${Date.now()}`;

  it('连接并跑通完整生命周期', async () => {
    const { Redis } = await import('ioredis');
    client = new Redis(redisUrl!) as unknown as RedisLike & { quit?: () => Promise<string> };
    store = new RedisSessionStore({ client, keyPrefix: `sessmw-test:${runId}:` });

    const rec: SessionRecord = {
      id: `${runId}-s1`,
      userId: `${runId}-u1`,
      createdAt: Date.now(),
      lastSeenAt: Date.now(),
      csrfToken: 'tok',
      data: { k: 'v' },
    };
    await store.put(rec, 30);
    expect(await store.get(rec.id)).toEqual(rec);

    await store.touch(rec.id, Date.now(), 20);
    expect((await store.get(rec.id))?.lastSeenAt).toBeGreaterThanOrEqual(rec.createdAt);

    const list = await store.listUserSessions(rec.userId!);
    expect(list.some((r) => r.id === rec.id)).toBe(true);

    const killed = await store.kickUser(rec.userId!);
    expect(killed).toContain(rec.id);
    expect(await store.get(rec.id)).toBeNull();
  });

  it('TTL 真的会让键过期', async () => {
    const rec: SessionRecord = {
      id: `${runId}-ttl`,
      userId: null,
      createdAt: Date.now(),
      lastSeenAt: Date.now(),
      csrfToken: null,
      data: {},
    };
    await store.put(rec, 1);
    expect(await store.get(rec.id)).not.toBeNull();
    await new Promise((r) => setTimeout(r, 1500));
    expect(await store.get(rec.id)).toBeNull();
  });

  it('清理连接', async () => {
    await client.quit?.();
  });
});
