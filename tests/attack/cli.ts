/**
 * 攻击测试入口：npm run attack
 * 拉起漏洞站 + 两个安全站，跑 7 组对照攻击，打印报告；
 * 任一安全站被攻破或任一漏洞站意外防住，则以非零码退出（可接 CI）。
 */
import { startAll } from './servers.js';
import { runScenarios } from './scenarios.js';
import { printReport } from './report.js';

async function main(): Promise<void> {
  const servers = await startAll();
  try {
    const results = await runScenarios(servers);
    printReport(results);
    const failed = results.filter((r) => !r.passed);
    console.log('');
    if (failed.length === 0) {
      console.log(`✅ 全部 ${results.length} 组对照符合预期：漏洞站均被攻破，安全站均防住。`);
      process.exitCode = 0;
    } else {
      console.log(`❌ ${failed.length} 组对照异常：`, failed.map((r) => r.id).join(', '));
      process.exitCode = 1;
    }
  } finally {
    await servers.closeAll();
  }
}

main().catch((err) => {
  console.error('攻击测试执行失败：', err);
  process.exit(2);
});
