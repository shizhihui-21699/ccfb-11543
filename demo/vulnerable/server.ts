/**
 * 漏洞站独立启动：npm run demo:vuln
 */
import { createVulnerableApp } from './app.js';

const port = Number(process.env.PORT ?? 4001);
const { app } = createVulnerableApp();
app.listen(port, () => {
  // eslint-disable-next-line no-console
  console.log(`[VULNERABLE demo] http://127.0.0.1:${port}  (⚠️ 故意不安全，勿用于真实环境)`);
});
