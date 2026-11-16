import { spawn, type ChildProcess } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { AddressInfo } from "node:net";

let counter = 0;

export interface RedisFixture {
  port: number;
  dir: string;
  stop: () => Promise<void>;
}

/**
 * 让操作系统分配一个当前空闲的 TCP 端口，避免并行测试用硬编码公式撞号。
 * 监听后立即释放——存在理论上的微小竞态，但 redis bind 紧随其后，
 * 且端口取自临时区间，实测足够可靠。
 */
async function getFreePort(): Promise<number> {
  const net = await import("node:net");
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.unref();
    srv.on("error", reject);
    srv.listen(0, "127.0.0.1", () => {
      const { port } = srv.address() as AddressInfo;
      srv.close(() => resolve(port));
    });
  });
}

/**
 * 启动一个独立的临时 redis-server（不依赖系统上是否已有实例）。
 * 若本机没有 redis-server 二进制，返回 null，调用方 skip 测试。
 */
export async function startRedis(): Promise<RedisFixture | null> {
  const redisBin = "/opt/homebrew/bin/redis-server";
  if (!existsSync(redisBin)) return null;

  const port = await getFreePort();
  const dir = join(tmpdir(), `session-guard-redis-${process.pid}-${counter++}-${port}`);
  await mkdir(dir, { recursive: true });

  const proc: ChildProcess = spawn(
    redisBin,
    [
      "--port", String(port),
      "--bind", "127.0.0.1",
      "--dir", dir,
      "--dbfilename", "dump.rdb",
      "--save", "", // 关闭 RDB 持久化，测试完无需清理数据文件
      "--appendonly", "no",
      "--daemonize", "no",
      "--loglevel", "warning",
    ],
    { stdio: ["ignore", "pipe", "pipe"] },
  );

  // 若进程提前退出（例如端口竞态 bind 失败），reject 而不是无限等待
  const earlyExit = new Promise<never>((_, reject) => {
    proc.once("exit", (code) => {
      reject(new Error(`redis-server 启动即退出，code=${code}`));
    });
  });
  await Promise.race([waitForPort(port, 5000), earlyExit]);

  return {
    port,
    dir,
    stop: async () => {
      if (proc.exitCode === null) {
        proc.kill("SIGTERM");
        await new Promise((res) => proc.on("exit", res));
      }
      await rm(dir, { recursive: true, force: true });
    },
  };
}

async function waitForPort(port: number, timeoutMs: number): Promise<void> {
  const net = await import("node:net");
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const ok = await new Promise<boolean>((resolve) => {
      const sock = net.createConnection({ port, host: "127.0.0.1" });
      sock.once("connect", () => {
        sock.end();
        resolve(true);
      });
      sock.once("error", () => resolve(false));
    });
    if (ok) return;
    if (Date.now() > deadline) throw new Error(`redis 端口 ${port} 等待超时`);
    await new Promise((r) => setTimeout(r, 100));
  }
}
