# session-guard

框架无关的会话安全中间件，一份核心代码同时挂 **Express** 与 **Hono**。
针对老服务常见的会话固定、CSRF、无超时、无并发管控等问题，提供开箱即用的防护。

## 能力清单

| 能力 | 实现方式 |
| --- | --- |
| 防会话固定 | 登录即销毁旧会话、签发全新随机会话 ID（256 bit 熵），重置绝对超时 |
| Cookie 加固 | `__Host-` 前缀强制 + `Secure` + `HttpOnly` + `SameSite=Strict` + `Path=/` |
| CSRF 防护 | 两种模式可切换：同步令牌（sync-token）/ 双提交（double-submit），常量时间比较 |
| 空闲超时 | 按 `lastAccessAt` 计算，活动可续命 |
| 绝对超时 | 按 `authenticatedAt` 计算，**不随活动延长**，与空闲超时独立 |
| 并发会话上限 | 同账号会话数超限时淘汰最老会话，内存实现同步、Redis 实现走 Lua 原子执行 |
| 一键踢下线 | `kickOtherSessions()` 保留当前会话踢掉其余；`engine.kickUser()` 管理面全踢 |
| 可插拔存储 | 统一 `SessionStore` 接口，内置内存与 Redis（手写零依赖 RESP 客户端）两种实现 |

## 目录结构

```
src/
  core/
    types.ts      # SessionStore 接口、SessionRecord 数据模型
    config.ts     # 全部配置项与默认值
    random.ts     # 加密随机 ID/令牌、常量时间比较
    guard.ts      # 单请求守卫：login/logout/CSRF/踢下线
    engine.ts     # 无框架依赖的安全引擎：装载、超时判定、CSRF 编排
  http/
    context.ts    # WebContext 抽象 + cookie 解析/序列化
  adapters/
    express.ts    # Express 薄适配器
    hono.ts       # Hono 薄适配器
  stores/
    memory-store.ts
    redis-store.ts
    redis-client.ts   # 零依赖最小 RESP2 客户端
examples/
  vulnerable-app/         # 故意留漏洞的对照站（勿抄）
  secure-express/         # Express + sync-token
  secure-hono/            # Hono + double-submit
  secure-express-redis/   # Express + Redis 存储
tests/                    # 29 个测试：引擎单元、适配器集成、Redis 端到端
scripts/attack.ts         # 攻击脚本：对三个站跑会话固定 + CSRF 攻击对比
```

## 快速开始

```bash
npm install
npm run build
npm test          # 29 个测试（含真实 redis-server 端到端）
npm run attack    # 起三个站，跑攻击并打印对比报告
```

### Express（同步令牌模式）

```ts
import express from "express";
import { SessionEngine, MemoryStore, expressSession } from "session-guard";

const engine = new SessionEngine({
  store: new MemoryStore(),
  csrf: "sync-token",                 // 或 "double-submit" / "off"
  idleTimeoutMs: 15 * 60 * 1000,      // 空闲 15 分钟
  absoluteTimeoutMs: 2 * 60 * 60 * 1000, // 绝对 2 小时
  maxSessionsPerUser: 3,
  csrfExemptPrefixes: ["/login"],
  // 生产（https）删掉下面这行，引擎会强制 __Host cookie 校验
  allowInsecureLocal: true,
});

const app = express();
app.use(express.json());
app.use(expressSession(engine));

app.post("/login", async (req, res) => {
  await req.sessionGuard!.login(req.body.username); // 内部完成轮转
  res.json({ ok: true });
});

app.post("/transfer", (req, res) => {
  // CSRF 已在中间件层校验通过；这里直接处理业务
  req.sessionGuard!.set("lastTransfer", req.body);
  res.json({ ok: true });
});
```

前端从响应头 `x-csrf-token` 取令牌，之后所有不安全方法（POST/PUT/PATCH/DELETE）
通过 `x-csrf-token` 请求头、`?csrf_token=` 或 body 字段回传。

### Hono（双提交模式）

```ts
import { Hono } from "hono";
import { serve } from "@hono/node-server";
import { SessionEngine, MemoryStore, honoSession } from "session-guard";

const app = new Hono();
const engine = new SessionEngine({
  store: new MemoryStore(),
  csrf: "double-submit",
  maxSessionsPerUser: 3,
  allowInsecureLocal: true,
  csrfExemptPrefixes: ["/login"],
});
app.use("*", honoSession(engine));

app.post("/login", async (c) => {
  await c.get("sessionGuard").login((await c.req.json()).username);
  return c.json({ ok: true });
});
serve({ fetch: app.fetch, port: 3000 });
```

双提交模式下，引擎下发一个**无 HttpOnly** 的 `__Host-csrf.token` cookie，
前端 JS 读出后在请求头原样回传；服务端比对"服务端持有值 == cookie == 回传值"。

### 切换到 Redis 存储

引擎与适配器代码一行不改，只换 `store`：

```ts
import { RedisStore } from "session-guard";

const store = new RedisStore({
  clientOptions: { host: "127.0.0.1", port: 6379, password: process.env.REDIS_PASS },
  keyPrefix: "sg",          // 多系统共用 Redis 时的命名空间
});
await store.connect();
const engine = new SessionEngine({ store, /* ...其余配置不变 */ });
```

## 存储接口抽象

存储层只负责持久化与按用户索引，**不做安全判定**。接口刻意保持精简（6 个方法）：

```ts
interface SessionStore {
  readonly name: string;
  get(id: string): Promise<SessionRecord | null>;
  save(record: SessionRecord, idleTimeoutMs: number, maxSessions?: number): Promise<void>;
  touch(id: string, lastAccessAt: number, idleTimeoutMs: number): Promise<void>;
  destroy(id: string): Promise<void>;
  listByUser(userId: string): Promise<SessionRecord[]>;
  destroyByUser(userId: string): Promise<number>;
  close?(): Promise<void>;
}
```

关键设计约定：

- **超时判定权归引擎**。存储层 `get`/`listByUser` 不得因为"到点了"就删记录，
  否则引擎无法区分"会话超时"与"会话从不存在"，拿不到 idle/absolute 的细分原因。
- **存储 TTL 只做垃圾回收兜底**，取 `2 × idleTimeoutMs`：既保证引擎判活的会话
  一定还能读到，又能最终回收无人访问的僵尸记录。
- **并发上限原子性**。内存实现天然同步；Redis 实现把"写入 + 索引 + 超限淘汰"
  放进一个 Lua 脚本，避免"检查上限→淘汰→写入"之间被并发登录打穿。
- **淘汰按 `createdAt` 而非会话 ID**。随机 ID 的字典序与年龄无关，
  Lua 脚本从记录 JSON 解析 `createdAt` 排序，淘汰最老会话。

实现自己的存储（如 Memcached、DynamoDB、关系库）只需满足该接口，
引擎的全部安全能力自动获得。

## 两种超时如何分开算

- 空闲超时：每次请求 `finalize` 时 `touch` 刷新 `lastAccessAt`，持续活动可无限续命。
- 绝对超时：登录时写入 `authenticatedAt`，之后**任何活动都不修改它**；
  到点即销毁，强制用户重新认证。

判定在引擎 `engine.ts` 的 `checkTimeouts` 中先查绝对、再查空闲，
命中后销毁记录并在响应里通过 `sessionExpired: "idle" | "absolute"` 告知原因。

## 攻击演示说明

`npm run attack` 会自动启动三个站点并运行同一组攻击：

1. **会话固定**：攻击者预先指定/取得会话 ID，诱使受害者用它登录后，
   再用同一 ID 访问账户。
2. **CSRF**：模拟第三方站点只带 cookie、不带（或带伪造的）CSRF 令牌发起转账。

预期结果：漏洞站两种攻击均得手；两个加固站全部拦截（403 / 旧 ID 失效）。
脚本以退出码 0/1 表示全部断言是否符合预期，可直接接入 CI。

## 生产部署注意

- 部署在 HTTPS 之后，移除 `allowInsecureLocal`，引擎会强制 `__Host-` cookie
  （要求 Secure、无 Domain、Path=/），启动时配置错误会直接抛异常。
- 多实例部署必须用 `RedisStore`，内存存储各实例会话不共享。
- `csrfExemptPrefixes` 只放真正无浏览器会话语义的端点（典型如登录本身）；
  登录接口自身靠凭证鉴权，不依赖会话 cookie。
- 本库的 Redis 客户端是教学/轻量用途的最小 RESP 实现；生产环境也可在
  `RedisStore` 构造时传入自建的 ioredis/node-redis 适配（需满足 `RedisClient` 的
  `send`/`pipeline` 形态）。
