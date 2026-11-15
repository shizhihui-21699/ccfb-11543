/**
 * 存储层契约测试：两种存储必须满足 SessionStore 的同一套语义。
 * 任何新存储实现（如真 Redis、数据库版）都应能跑通这同一组用例。
 */
import { describe, it, expect, beforeEach } from 'vitest';
import { MemorySessionStore } from '../src/stores/memory.js';
import { RedisSessionStore } from '../src/stores/redis.js';
import { FakeRedis } from './helpers/fake-redis.js';
import type { SessionRecord, SessionStore } from '../src/types.js';

function makeRecord(id: string, userId: string | null, createdAt: number): SessionRecord {
  return {
    id,
    userId,
    createdAt,
    lastSeenAt: createdAt,
    csrfToken: `csrf-${id}`,
    data: {},
  };
}

const factories: Array<[string, () => SessionStore]> = [
  ['MemorySessionStore', () => new MemorySessionStore({ sweepIntervalMs: 0 })],
  ['RedisSessionStore(FakeRedis)', () => new RedisSessionStore({ client: new FakeRedis() })],
];

describe.each(factories)('存储契约: %s', (_name, makeStore) => {
  let store: SessionStore;
  beforeEach(() => {
    store = makeStore();
  });

  it('put/get 往返一致', async () => {
    const rec = makeRecord('s1', 'u1', 1000);
    await store.put(rec, 60);
    const got = await store.get('s1');
    expect(got).toEqual(rec);
  });

  it('get 不存在的键返回 null', async () => {
    expect(await store.get('nope')).toBeNull();
  });

  it('destroy 后 get 返回 null，且重复 destroy 不报错', async () => {
    await store.put(makeRecord('s1', 'u1', 1000), 60);
    await store.destroy('s1');
    expect(await store.get('s1')).toBeNull();
    await expect(store.destroy('s1')).resolves.toBeUndefined();
  });

  it('touch 更新 lastSeenAt 且不改动其它字段', async () => {
    // 注入固定时钟，避免 TTL 与假时间戳混用导致惰性过期
    let now = 1000;
    const clocked =
      _name === 'MemorySessionStore'
        ? new MemorySessionStore({ sweepIntervalMs: 0, now: () => now })
        : new RedisSessionStore({ client: new FakeRedis({ now: () => now }) });
    await clocked.put(makeRecord('s1', 'u1', now), 60);
    now = 5000;
    await clocked.touch('s1', now, 30);
    const got = await clocked.get('s1');
    expect(got?.lastSeenAt).toBe(5000);
    expect(got?.createdAt).toBe(1000);
    expect(got?.userId).toBe('u1');
    expect(got?.csrfToken).toBe('csrf-s1');
  });

  it('touch 不存在的键静默成功', async () => {
    await expect(store.touch('ghost', 1, 10)).resolves.toBeUndefined();
  });

  it('listUserSessions 按 createdAt 升序，且只返回该用户的会话', async () => {
    await store.put(makeRecord('a', 'u1', 3000), 60);
    await store.put(makeRecord('b', 'u1', 1000), 60);
    await store.put(makeRecord('c', 'u2', 2000), 60);
    const list = await store.listUserSessions('u1');
    expect(list.map((r) => r.id)).toEqual(['b', 'a']);
  });

  it('kickUser 销毁该用户全部会话，exceptId 保留指定会话', async () => {
    await store.put(makeRecord('a', 'u1', 1000), 60);
    await store.put(makeRecord('b', 'u1', 2000), 60);
    await store.put(makeRecord('c', 'u2', 3000), 60);

    const killed = await store.kickUser('u1', 'b');
    expect(killed.sort()).toEqual(['a']);
    expect(await store.get('a')).toBeNull();
    expect(await store.get('b')).not.toBeNull();
    // 别的用户不受影响
    expect(await store.get('c')).not.toBeNull();
  });

  it('kickUser 无 exceptId 时清空该用户全部会话', async () => {
    await store.put(makeRecord('a', 'u1', 1000), 60);
    await store.put(makeRecord('b', 'u1', 2000), 60);
    const killed = await store.kickUser('u1');
    expect(killed.sort()).toEqual(['a', 'b']);
    expect(await store.listUserSessions('u1')).toEqual([]);
  });

  it('匿名会话（userId=null）不进入用户索引', async () => {
    await store.put(makeRecord('anon', null, 1000), 60);
    expect(await store.listUserSessions('whatever')).toEqual([]);
    expect(await store.get('anon')).not.toBeNull();
  });

  it('TTL 到期后键被淘汰', async () => {
    let now = 1000;
    // 用带时钟的存储实例单独验证 TTL
    const clocked =
      _name === 'MemorySessionStore'
        ? new MemorySessionStore({ sweepIntervalMs: 0, now: () => now })
        : new RedisSessionStore({ client: new FakeRedis({ now: () => now }) });
    await clocked.put(makeRecord('s1', 'u1', now), 10);
    expect(await clocked.get('s1')).not.toBeNull();
    now = 12_000; // 越过 10s TTL
    expect(await clocked.get('s1')).toBeNull();
  });
});
