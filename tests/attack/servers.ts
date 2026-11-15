/**
 * 在随机端口上拉起三个对照服务，攻击脚本跑完统一关闭。
 * - vulnerable：漏洞站（Express）
 * - secure-express：安全站 Express + 同步令牌
 * - secure-hono：安全站 Hono + 双提交
 */
import { serve } from '@hono/node-server';
import type { Server } from 'node:http';
import { createVulnerableApp } from '../../demo/vulnerable/app.js';
import { createSecureExpressApp } from '../../demo/secure/express-app.js';
import { createSecureHonoApp } from '../../demo/secure/hono-app.js';

export interface RunningServers {
  vulnerable: { base: string; close: () => Promise<void> };
  secureExpress: { base: string; close: () => Promise<void> };
  secureHono: { base: string; close: () => Promise<void> };
  closeAll: () => Promise<void>;
}

function portOf(server: { address(): unknown }): number {
  const addr = server.address();
  if (addr && typeof addr === 'object' && 'port' in addr) {
    return (addr as { port: number }).port;
  }
  throw new Error('无法获取临时端口');
}

export async function startAll(): Promise<RunningServers> {
  const closeFns: Array<() => Promise<void>> = [];

  // 漏洞站
  const vulnApp = createVulnerableApp();
  const vulnServer = vulnApp.app.listen(0, '127.0.0.1');
  await new Promise<void>((resolve, reject) => {
    vulnServer.once('listening', () => resolve());
    vulnServer.once('error', reject);
  });
  const vulnPort = portOf(vulnServer);
  closeFns.push(() => new Promise((r) => vulnServer.close(() => r())));

  // 安全站 Express
  const expressHandle = createSecureExpressApp();
  const expressServer = expressHandle.app.listen(0, '127.0.0.1');
  await new Promise<void>((resolve, reject) => {
    expressServer.once('listening', () => resolve());
    expressServer.once('error', reject);
  });
  const expressPort = portOf(expressServer);
  closeFns.push(() => new Promise((r) => expressServer.close(() => r())));

  // 安全站 Hono —— serve() 返回 server 但端口绑定是异步的，等 listening 事件
  const honoHandle = createSecureHonoApp();
  const honoServer = serve({
    fetch: honoHandle.app.fetch,
    port: 0,
    hostname: '127.0.0.1',
  }) as unknown as Server;
  await new Promise<void>((resolve, reject) => {
    honoServer.once('listening', () => resolve());
    honoServer.once('error', reject);
  });
  const honoPort = portOf(honoServer);
  closeFns.push(
    () =>
      new Promise((r) => {
        honoServer.close(() => r());
      }),
  );

  return {
    vulnerable: { base: `http://127.0.0.1:${vulnPort}`, close: closeFns[0]! },
    secureExpress: { base: `http://127.0.0.1:${expressPort}`, close: closeFns[1]! },
    secureHono: { base: `http://127.0.0.1:${honoPort}`, close: closeFns[2]! },
    closeAll: async () => {
      for (const fn of closeFns) await fn();
    },
  };
}
