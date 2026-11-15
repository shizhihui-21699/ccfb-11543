/**
 * 安全站独立启动：npm run demo:secure
 * 默认 Express + 同步令牌；设 FRAMEWORK=hono 启动 Hono + 双提交版本。
 */
import http from 'node:http';
import { serve } from '@hono/node-server';
import { createSecureExpressApp } from './express-app.js';
import { createSecureHonoApp } from './hono-app.js';

const port = Number(process.env.PORT ?? 4002);
const framework = process.env.FRAMEWORK ?? 'express';

if (framework === 'hono') {
  const { app } = createSecureHonoApp();
  serve({ fetch: app.fetch, port }, () => {
    // eslint-disable-next-line no-console
    console.log(`[SECURE demo · Hono + double-submit] http://127.0.0.1:${port}`);
  });
} else {
  const { app } = createSecureExpressApp();
  http.createServer(app).listen(port, () => {
    // eslint-disable-next-line no-console
    console.log(`[SECURE demo · Express + synchronizer] http://127.0.0.1:${port}`);
  });
}
