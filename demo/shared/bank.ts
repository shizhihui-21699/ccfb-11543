/**
 * 对照站共享的“业务逻辑”：一个极简银行账户 + 转账。
 * 漏洞站与安全站跑完全相同的业务代码，差别只在会话安全层，
 * 这样攻击结果的差异才能干净地归因于中间件。
 */
export class Bank {
  private readonly balances = new Map<string, number>();

  constructor(initial: Record<string, number> = { alice: 1000, bob: 100 }) {
    for (const [user, amount] of Object.entries(initial)) {
      this.balances.set(user, amount);
    }
  }

  balance(user: string): number {
    return this.balances.get(user) ?? 0;
  }

  /** 转账成功返回 true；余额不足或账户不存在返回 false */
  transfer(from: string, to: string, amount: number): boolean {
    const fromBal = this.balances.get(from);
    if (fromBal === undefined || !this.balances.has(to)) return false;
    if (!Number.isFinite(amount) || amount <= 0 || fromBal < amount) return false;
    this.balances.set(from, fromBal - amount);
    this.balances.set(to, (this.balances.get(to) ?? 0) + amount);
    return true;
  }
}

export const USERS: Record<string, string> = {
  alice: 'alice-pw',
  bob: 'bob-pw',
};
