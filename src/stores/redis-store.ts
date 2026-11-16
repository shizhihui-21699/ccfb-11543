import type { SessionRecord, SessionStore } from "../core/types.js";
import { RedisClient, type RedisClientOptions } from "./redis-client.js";

/**
 * Redis 会话存储。
 *
 * 键布局（prefix 默认 "sg"）：
 *   {prefix}:session:{id}  -> 会话 JSON，带 PX 兜底 GC TTL（每次 touch/save 刷新）
 *   {prefix}:user:{uid}    -> SET，存放该用户全部会话 id，用于并发上限与踢下线
 *
 * TTL 语义（重要）：
 * - 会话是否超时由引擎读 JSON 里的 lastAccessAt/authenticatedAt 权威判定；
 * - Redis 的 PX 只做垃圾回收兜底，取 2 倍空闲超时 —— 绝不能等于空闲超时，
 *   否则 Redis 会在引擎判定前就把键淘汰，引擎无法区分"超时"与"不存在"；
 * - 2 倍宽限保证：任何被引擎判活的会话，其键在下次访问前一定还在 Redis 里。
 *
 * 复合操作（登录注册+超限淘汰、删除、踢下线）全部用 Lua 脚本在服务端原子执行，
 * 避免"检查上限 -> 淘汰 -> 写入"之间被并发登录打穿。
 */

/** GC 兜底 TTL = 空闲超时的倍数 */
const GC_TTL_FACTOR = 2;

/**
 * 登录/轮转注册（原子）。
 * KEYS[1]=session key  KEYS[2]=user set key
 * ARGV[1]=recordJson  ARGV[2]=gcTtlMs  ARGV[3]=sessionPrefix
 * ARGV[4]=maxSessions(0=不限)  ARGV[5]=当前会话 id
 *
 * 超限时按会话记录里的 createdAt（会话首次建立时间）淘汰最老的，
 * 不能按 session id 字典序 —— 随机 id 的字典序与年龄毫无关系。
 */
const REGISTER_LUA = `
redis.call('SET', KEYS[1], ARGV[1], 'PX', tonumber(ARGV[2]))
redis.call('SADD', KEYS[2], ARGV[5])
local max = tonumber(ARGV[4])
if max > 0 then
  local ids = redis.call('SMEMBERS', KEYS[2])
  local alive = {}
  for _, sid in ipairs(ids) do
    local raw = redis.call('GET', ARGV[3] .. sid)
    if raw == false then
      redis.call('SREM', KEYS[2], sid)
    else
      -- 从会话 JSON 中取 createdAt；解码失败用 0 兜底（视为最老，优先淘汰）
      local created = tonumber(string.match(raw, '"createdAt":(%d+)')) or 0
      table.insert(alive, { sid = sid, created = created })
    end
  end
  local overflow = #alive - max
  if overflow > 0 then
    table.sort(alive, function(a, b) return a.created < b.created end)
    for i = 1, overflow do
      local sid = alive[i].sid
      redis.call('DEL', ARGV[3] .. sid)
      redis.call('SREM', KEYS[2], sid)
    end
  end
end
return 1
`;

/** 删会话并维护用户集合；KEYS[1]=session key KEYS[2]=user set key；ARGV[1]=sid ARGV[2]=userId */
const DESTROY_LUA = `
redis.call('DEL', KEYS[1])
if ARGV[2] ~= '' then
  redis.call('SREM', KEYS[2], ARGV[1])
end
return 1
`;

/** 踢下线：删掉用户集合里所有会话，返回数量。KEYS[1]=user set；ARGV[1]=sessionPrefix */
const DESTROY_USER_LUA = `
local ids = redis.call('SMEMBERS', KEYS[1])
local n = 0
for _, sid in ipairs(ids) do
  redis.call('DEL', ARGV[1] .. sid)
  n = n + 1
end
redis.call('DEL', KEYS[1])
return n
`;

export interface RedisStoreOptions {
  /** 复用已有客户端；不传则按 clientOptions 自建并在 close 时自行关闭 */
  client?: RedisClient;
  clientOptions?: RedisClientOptions;
  /** 键前缀，多系统共用一个 Redis 时做命名空间隔离 */
  keyPrefix?: string;
}

export class RedisStore implements SessionStore {
  readonly name = "redis";
  private readonly client: RedisClient;
  private readonly ownsClient: boolean;
  private readonly sessionPrefix: string;
  private readonly userPrefix: string;

  constructor(options: RedisStoreOptions = {}) {
    this.ownsClient = !options.client;
    this.client = options.client ?? new RedisClient(options.clientOptions);
    const prefix = options.keyPrefix ?? "sg";
    this.sessionPrefix = `${prefix}:session:`;
    this.userPrefix = `${prefix}:user:`;
  }

  /** 使用自建客户端时，需在首个请求前 await 一次 */
  async connect(): Promise<void> {
    if (this.ownsClient) await this.client.connect();
  }

  /** 读不过期：Redis TTL 只做 GC，超时判定权在引擎 */
  async get(id: string): Promise<SessionRecord | null> {
    const raw = await this.client.send(["GET", this.sessionPrefix + id]);
    if (raw === null) return null;
    return JSON.parse(raw as string) as SessionRecord;
  }

  async save(record: SessionRecord, idleTimeoutMs: number, maxSessions = 0): Promise<void> {
    const gcTtl = idleTimeoutMs * GC_TTL_FACTOR;
    const payload = JSON.stringify(record);
    if (!record.userId) {
      // 匿名会话不建用户索引
      await this.client.send([
        "SET", this.sessionPrefix + record.id, payload, "PX", gcTtl,
      ]);
      return;
    }
    await this.client.send([
      "EVAL", REGISTER_LUA, "2",
      this.sessionPrefix + record.id,
      this.userPrefix + record.userId,
      payload,
      String(gcTtl),
      this.sessionPrefix,
      String(maxSessions),
      record.id,
    ]);
  }

  async touch(id: string, lastAccessAt: number, idleTimeoutMs: number): Promise<void> {
    // 刷新 JSON 中的 lastAccessAt 与 GC TTL
    const raw = await this.client.send(["GET", this.sessionPrefix + id]);
    if (raw === null) return;
    const record = JSON.parse(raw as string) as SessionRecord;
    record.lastAccessAt = lastAccessAt;
    await this.client.send([
      "SET", this.sessionPrefix + id, JSON.stringify(record), "PX", idleTimeoutMs * GC_TTL_FACTOR,
    ]);
  }

  async destroy(id: string): Promise<void> {
    const record = await this.get(id);
    const userId = record?.userId ?? "";
    await this.client.send([
      "EVAL", DESTROY_LUA, "2",
      this.sessionPrefix + id,
      this.userPrefix + (userId || "-"),
      id,
      userId,
    ]);
  }

  async listByUser(userId: string): Promise<SessionRecord[]> {
    const ids = await this.client.send(["SMEMBERS", this.userPrefix + userId]);
    if (!Array.isArray(ids) || ids.length === 0) return [];
    const raws = await this.client.pipeline(
      ids.map((sid) => ["GET", this.sessionPrefix + String(sid)]),
    );
    const out: SessionRecord[] = [];
    for (let i = 0; i < raws.length; i++) {
      const raw = raws[i];
      if (raw === null) {
        // GC 已回收的残留索引：顺手清掉
        void this.client.send(["SREM", this.userPrefix + userId, String(ids[i])]);
        continue;
      }
      out.push(JSON.parse(raw as string) as SessionRecord);
    }
    return out;
  }

  async destroyByUser(userId: string): Promise<number> {
    const n = await this.client.send([
      "EVAL", DESTROY_USER_LUA, "1", this.userPrefix + userId, this.sessionPrefix,
    ]);
    return Number(n);
  }

  async close(): Promise<void> {
    if (this.ownsClient) await this.client.close();
  }
}
