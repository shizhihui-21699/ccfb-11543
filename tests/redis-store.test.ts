import assert from "node:assert/strict";
import { after, before, describe, it } from "node:test";
import { RedisStore } from "../src/stores/redis-store.js";
import { RedisClient } from "../src/stores/redis-client.js";
import type { SessionRecord } from "../src/core/types.js";
import { startRedis, type RedisFixture } from "./redis-fixture.js";

describe("RedisStore（真实 redis-server）", { skip: false }, () => {
  let fixture: RedisFixture | null = null;
  let store: RedisStore;
  let raw: RedisClient;

  before(async () => {
    fixture = await startRedis();
    if (!fixture) return; // 无 redis 二进制时整个 suite 跳过
  });

  after(async () => {
    await store?.close();
    await raw?.close();
    await fixture?.stop();
  });

  function record(id: string, userId: string | null, at: number): SessionRecord {
    return {
      id,
      userId,
      data: {},
      createdAt: at,
      lastAccessAt: at,
      authenticatedAt: userId ? at : null,
      csrfToken: null,
    };
  }

  it("基础读写与用户索引", async (t) => {
    if (!fixture) {
      t.skip("本机无 redis-server");
      return;
    }
    store = new RedisStore({ clientOptions: { port: fixture.port } });
    await store.connect();
    raw = new RedisClient({ port: fixture.port });
    await raw.connect();

    const r1 = record("sess-aaa", "alice", 1000);
    await store.save(r1, 10_000);
    const got = await store.get("sess-aaa");
    assert.equal(got?.userId, "alice");

    const r2 = record("sess-bbb", "alice", 2000);
    await store.save(r2, 10_000);
    const list = await store.listByUser("alice");
    assert.equal(list.length, 2);
  });

  it("GC TTL 是空闲超时的 2 倍，且引擎判活窗口内键不被 Redis 抢先淘汰", async (t) => {
    if (!fixture) {
      t.skip("本机无 redis-server");
      return;
    }
    await store.save(record("sess-ttl", "bob", 1000), 10_000);
    const ttl = await raw.send(["PTTL", "sg:session:sess-ttl"]);
    assert.ok(Number(ttl) > 10_000, `PTTL 应大于空闲超时，实际 ${ttl}`);
    assert.ok(Number(ttl) <= 20_000 + 200);
  });

  it("并发上限：超限淘汰在 Lua 中原子执行", async (t) => {
    if (!fixture) {
      t.skip("本机无 redis-server");
      return;
    }
    for (let i = 0; i < 4; i++) {
      await store.save(record(`sess-max-${i}`, "carol", 1000 + i), 10_000, 2);
    }
    const list = await store.listByUser("carol");
    assert.equal(list.length, 2, "上限 2，只应剩 2 条");
    const ids = list.map((r) => r.id).sort();
    assert.deepEqual(ids, ["sess-max-2", "sess-max-3"]);
  });

  it("destroy 与 destroyByUser 同步清理用户集合", async (t) => {
    if (!fixture) {
      t.skip("本机无 redis-server");
      return;
    }
    await store.save(record("sess-d1", "dave", 1000), 10_000);
    await store.save(record("sess-d2", "dave", 2000), 10_000);
    await store.destroy("sess-d1");
    assert.equal(await store.get("sess-d1"), null);
    assert.equal((await store.listByUser("dave")).length, 1);

    const n = await store.destroyByUser("dave");
    assert.equal(n, 1);
    assert.equal((await store.listByUser("dave")).length, 0);
    // 用户集合键也应被删除
    assert.equal(await raw.send(["EXISTS", "sg:user:dave"]), 0);
  });

  it("RESP 客户端：pipeline 按序返回多命令响应", async (t) => {
    if (!fixture) {
      t.skip("本机无 redis-server");
      return;
    }
    const replies = await raw.pipeline([
      ["SET", "sg:test:k1", "v1"],
      ["GET", "sg:test:k1"],
      ["INCR", "sg:test:counter"],
      ["INCR", "sg:test:counter"],
    ]);
    assert.equal(replies[0], "OK");
    assert.equal(replies[1], "v1");
    assert.equal(replies[2], 1);
    assert.equal(replies[3], 2);
  });
});
