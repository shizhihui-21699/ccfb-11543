# session-secure

框架无关的会话安全中间件（TypeScript，零第三方运行时依赖，仅用 Node 内置 `crypto`），
同一套安全核心可挂 **Express** 与 **Hono**，存储可插拔（内存 / Redis 协议）。

针对老 Node 服务暴露的真实问题，提供：

| 安全能力 | 实现方式 |
| --- | --- |
| 防会话固定 | 登录时销毁旧会话 ID，签发全新 SID + 全新 CSRF token（regenerate） |
| Cookie 加固 | `__Host-` 前缀（强制 Secure / 无 Domain / Path=/）+ `HttpOnly` + `SameSite` |
| CSRF：同步令牌 | token 存服务端会话，恒定时间比对 |
| CSRF：双提交 | token 存 HMAC 签名 cookie，校验 cookie 与 header 一致且签名合法 |
| 并发会话上限 | 同账号按创建时间淘汰最旧会话 |
| 一键踢下线 | `kickUser(userId)` / `handle.kickOthers()` |
| 空闲超时 | 基于 `lastSeenAt`，每次请求惰性判定 + 续期 |
| 绝对超时 | 基于 `createdAt`，无论多活跃到点强制注销；与空闲超时独立计算 |
| 可插拔存储 | 统一 `SessionStore` 接口，内存版 + Redis 协议版 |

## 目录结构

```
src/
  types.ts            领域模型 + SessionStore 抽象（存储契约）
  crypto.ts           随机 ID / HMAC / 恒定时间比较（全 node:crypto）
  cookie.ts           cookie 解析与 __Host- 规则集中实现
  engine.ts           SessionEngine：全部安全语义，框架无关
  stores/
    memory.ts         进程内存储（惰性过期 + unref 清扫器）
    redis.ts          Redis 协议存储（依赖最小化的 RedisLike 接口）
  adapters/
    express.ts        Express 中间件（包装 res.end 保证 cookie 随响应下发）
    hono.ts           Hono 中间件
demo/
  vulnerable/         故意留 6 类漏洞的对照站（[VULN-n] 标注）
  secure/             安全站：Express(同步令牌) + Hono(双提交) 两版
tests/
  engine.test.ts           引擎安全属性（内存/Redis 矩阵，假时钟）
  store-contract.test.ts   存储契约（任何新存储都应跑通）
  adapters.test.ts         Express/Hono 真实 HTTP 端到端
  redis-live.test.ts       真 Redis 集成（默认 skip，给 REDIS_URL 才跑）
  attack/                  攻防对照 CLI + 7 个攻击场景
```

## 快速开始

```bash
npm install
npm test          # 53 个单元/集成测试
npm run attack    # 拉起漏洞站+两个安全站，跑 7 组对照攻击
npm run build     # 产出 dist/
```

### Express（同步令牌模式）

```ts
import express from 'express';
import { SessionEngine, MemorySessionStore } from 'session-secure';
import { sessionMiddleware } from 'session-secure/express';

const engine = new SessionEngine({
  store: new MemorySessionStore(),
  csrfMode: 'synchronizer',
  // idleTimeoutMs / absoluteTimeoutMs / maxSessionsPerUser ...
});
const app = express();
app.use(express.json());
app.use(sessionMiddleware(engine));

// 前端渲染时取 CSRF token
app.get('/csrf', (req, res) => res.json({ token: req.session.csrfToken }));

app.post('/login', async (req, res) => {
  await req.session.login(req.body.userId);   // 内部完成 SID 轮换
  res.json({ csrfToken: req.session.csrfToken });
});

// 状态变更接口：无有效 CSRF token 会被中间件直接 403
app.post('/transfer', (req, res) => res.json({ ok: true }));
```

前端对所有非安全方法（POST/PUT/PATCH/DELETE）带 `x-csrf-token` 头，
或在表单里放 `_csrf` 字段。

### Hono（双提交模式）

```ts
import { Hono } from 'hono';
import { SessionEngine, MemorySessionStore } from 'session-secure';
import { sessionMiddleware, SESSION_HANDLE_KEY } from 'session-secure/hono';

const engine = new SessionEngine({
  store: new MemorySessionStore(),
  csrfMode: 'double-submit',
  csrfSecret: process.env.CSRF_SECRET,   // ≥32 字节随机串，双提交模式必填
});
const app = new Hono();
app.use('*', sessionMiddleware(engine));
// 前端从非 HttpOnly 的 __Host-csrf_token cookie 读出 token，放进 x-csrf-token 回传
```

### Redis 存储

```ts
import { Redis } from 'ioredis';
import { RedisSessionStore } from 'session-secure';

const store = new RedisSessionStore({
  client: new Redis(process.env.REDIS_URL),  // 任何满足 RedisLike 的客户端
  keyPrefix: 'sessmw:',
});
```

## 存储接口是怎么抽象的

引擎不直接依赖任何具体存储，只依赖下面这个接口（见 `src/types.ts`）：

```ts
interface SessionStore {
  put(record: SessionRecord, ttlSeconds: number): Promise<void>;
  get(id: string): Promise<SessionRecord | null>;
  destroy(id: string): Promise<void>;
  touch(id: string, lastSeenAt: number, ttlSeconds: number): Promise<void>;
  listUserSessions(userId: string): Promise<SessionRecord[]>; // 按 createdAt 升序
  kickUser(userId: string, exceptId?: string): Promise<string[]>;
  ping?(): Promise<void>;
  close?(): Promise<void>;
}
```

设计要点：

1. **策略与机制分离**：所有安全判定（轮换、超时归因、并发上限、踢人）都在引擎里，
   存储只做 KV 持久化 + 用户索引。换存储不改变安全语义。
2. **用户索引允许含过期成员**：`listUserSessions` 返回的集合里可能有已被 TTL 淘汰的脏成员，
   引擎读回后按时间戳自行过滤并惰性清理。这让存储接口不需要后台对账，极简。
3. **超时是引擎的语义职责，存储 TTL 只做物理兜底**：
   - 存储 TTL 按「绝对寿命 + 60s 宽限」设置，保证死线后第一个请求仍能读到 record，
     由引擎归因成 `idle` 还是 `absolute` 并主动销毁；之后存储再兜底 GC，不泄漏。
   - cookie 的 `Max-Age` 取空闲/绝对死线的较小值，浏览器侧按最短寿命清理。
4. **`touch` 独立成方法**：让 Redis 版能用一次原子调用续期，避免 get→put 竞态。
5. **Redis 键布局**：`session:<id>` 为 hash（整条 record JSON），
   `user_sessions:<userId>` 为 ZSET（score=createdAt），并发淘汰时 `ZRANGE 0` 直接取最旧。
6. **最小客户端接口**：Redis 版只 import 一个 `RedisLike` 命令子集（hset/hgetall/del/expire/zadd/zrange/zrem/pipeline/ping）。
   ioredis 原生满足；测试用的 `FakeRedis` 实现同样的 RESP 语义，因此离线即可测试，
   换 node-redis 等库只需写薄适配。

### 实现自己的存储

实现 `SessionStore` 七个方法，然后让它跑通 `tests/store-contract.test.ts` 即可——
该文件对内存版和 Redis 版跑同一组契约用例，是新存储的验收标准。

## 安全语义细节

- **会话 ID**：256 位熵，`randomBytes(32).toString('base64url')`，不可枚举。
- **登录轮换**：`login()` 先 `put` 全新 record（新 ID/新 createdAt/新 CSRF token），
  再 `destroy` 旧 ID，旧 ID 立即失效，从根上消除会话固定。
- **CSRF 恒定时间比较**：同步令牌与 HMAC 签名校验都走 `timingSafeEqual`，先做长度判断防抛错。
- **双提交防伪造**：token = `随机payload.HMAC(payload)`，攻击者没有 secret 无法铸造；
  校验要求 cookie 与 header 一致 **且** 两者签名都合法。
- **安全方法豁免**：GET/HEAD/OPTIONS/TRACE 不做 CSRF 校验（不应有副作用）。
- **record 不可变流转**：引擎内部通过副本替换更新 record，避免与内存存储共享可变对象引用。

## 攻防对照

`npm run attack` 会在随机端口拉起三个服务并对同一套业务（迷你银行转账）发起 7 组攻击：

| 编号 | 攻击 | 漏洞站 | 安全站 |
| --- | --- | --- | --- |
| A1 | 会话固定（登录不换 SID） | 💥 被攻破 | 🛡️ SID 轮换，旧 ID 401 |
| A2 | CSRF 无令牌转账 | 💥 余额被改 | 🛡️ 403 csrf_rejected |
| A3 | 双提交自造/篡改 token | 💥 被攻破 | 🛡️ bad-signature / token-mismatch |
| A4 | Cookie 安全属性 | 💥 裸 cookie | 🛡️ HttpOnly+SameSite（生产加 __Host+Secure） |
| A5 | 空闲超时（静默 2.5s） | 💥 会话永生 | 🛡️ idle 过期 401 |
| A6 | 绝对超时（持续活动 6s） | 💥 会话永生 | 🛡️ absolute 强制注销 |
| A7 | 并发上限 / 踢下线 | 💥 无限堆积、不可吊销 | 🛡️ 上限 2 挤旧 + kick-user 全踢 |

漏洞站的每处缺陷都在 `demo/vulnerable/app.ts` 里以 `[VULN-n]` 标注，
与安全站的防护点、攻击场景一一对应。脚本以非零码退出可直接接入 CI。

> 演示为了在本地 http 下工作关闭了 `__Host` 前缀（`hostPrefix:false`）。
> 生产 HTTPS 环境保持默认 `hostPrefix:true`，cookie 名会自动变成 `__Host-sid` 并强制 Secure。

## 真实 Redis 测试

```bash
# 本机有 Redis 时（无 Redis 时该文件自动 skip）
REDIS_URL=redis://127.0.0.1:6379 npx vitest run tests/redis-live.test.ts
```
