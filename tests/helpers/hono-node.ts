import type { Hono } from 'hono';
import { serve } from '@hono/node-server';
import type { Server } from 'node:http';

/**
 * 只依赖 fetch 形状，兼容任意 Variables 泛型的 Hono 实例。
 * @hono/node-server 运行时在 Node 下返回 http.Server（联合类型里也含 http2.Server），
 * 这里断言为 http.Server 以满足 supertest 的入参类型。
 */
export function nodeServer(app: Pick<Hono, 'fetch'>): Server {
  return serve({ fetch: app.fetch, port: 0 }) as unknown as Server;
}
