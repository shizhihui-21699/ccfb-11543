/**
 * 攻击测试结果模型与控制台报告器。
 * 每个攻击场景对漏洞站和安全站各跑一次，结论用“漏洞站是否被攻破 / 安全站是否防住”双向断言。
 */
export type Verdict = 'blocked' | 'exploited' | 'n/a';

export interface ScenarioResult {
  id: string;
  title: string;
  vulnerable: {
    verdict: Verdict;
    detail: string;
  };
  secure: {
    verdict: Verdict;
    detail: string;
  };
  /** Hono + 双提交版本的结论（仅 CSRF 双提交等场景有值） */
  secureHono?: {
    verdict: Verdict;
    detail: string;
  };
  /** 整体是否符合预期：漏洞站 exploited 且安全站 blocked */
  passed: boolean;
}

const ICON: Record<Verdict, string> = {
  blocked: '🛡️ blocked',
  exploited: '💥 exploited',
  'n/a': '➖ n/a',
};

function pad(s: string, n: number): string {
  // 中文按两个宽度计，简单对齐
  let width = 0;
  for (const ch of s) width += ch.charCodeAt(0) > 255 ? 2 : 1;
  return s + ' '.repeat(Math.max(0, n - width));
}

export function printReport(results: ScenarioResult[]): void {
  const line = '─'.repeat(96);
  console.log(line);
  console.log(pad('攻击场景', 40) + pad('漏洞站', 18) + pad('安全站(Express)', 18) + '安全站(Hono)');
  console.log(line);
  for (const r of results) {
    const honoCell = r.secureHono ? ICON[r.secureHono.verdict as Verdict] : '';
    console.log(
      pad(`${r.id} ${r.title}`, 40) +
        pad(ICON[r.vulnerable.verdict], 18) +
        pad(ICON[r.secure.verdict], 18) +
        honoCell,
    );
  }
  console.log(line);

  console.log('\n详细证据：');
  for (const r of results) {
    console.log(`\n▸ ${r.id} ${r.title}  ${r.passed ? '✅ 符合预期' : '❌ 异常'}`);
    console.log(`    漏洞站   [${r.vulnerable.verdict}] ${r.vulnerable.detail}`);
    console.log(`    安全站   [${r.secure.verdict}] ${r.secure.detail}`);
    if (r.secureHono) {
      console.log(`    Hono 版  [${r.secureHono.verdict}] ${r.secureHono.detail}`);
    }
  }
}
