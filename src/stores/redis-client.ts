import { Socket, createConnection } from "node:net";

/**
 * 最小 RESP2 Redis 客户端（零第三方依赖）。
 *
 * 只实现会话存储需要的命令族：GET / SET PX / DEL / EXISTS / EXPIRE /
 * SADD / SREM / SMEMBERS / EVAL / AUTH / SELECT / QUIT。
 * 生产环境也可以在这一层替换成 ioredis / node-redis —— RedisStore 只依赖本类的 send/pipeline。
 */
export class RedisProtocolError extends Error {}

export interface RedisClientOptions {
  host?: string;
  port?: number;
  password?: string;
  db?: number;
  connectTimeoutMs?: number;
}

type Reply = string | number | null | Reply[];

interface PendingCall {
  resolve: (value: Reply[]) => void;
  reject: (error: Error) => void;
  /** 一次 pipeline 中包含几条命令，用于拆分响应 */
  count: number;
}

class IncompleteReply extends Error {}

export class RedisClient {
  private socket: Socket | null = null;
  private buffer: Buffer = Buffer.alloc(0);
  private readonly queue: PendingCall[] = [];
  /** socket 建立即可写；AUTH/SELECT 期间也为 true */
  private writable = false;

  constructor(private readonly options: RedisClientOptions = {}) {}

  async connect(): Promise<void> {
    const host = this.options.host ?? "127.0.0.1";
    const port = this.options.port ?? 6379;
    const timeoutMs = this.options.connectTimeoutMs ?? 3000;

    await new Promise<void>((resolve, reject) => {
      const socket = createConnection({ host, port });
      const timer = setTimeout(() => {
        socket.destroy(new Error(`redis 连接超时 ${host}:${port}`));
      }, timeoutMs);
      socket.once("connect", () => {
        clearTimeout(timer);
        this.socket = socket;
        this.writable = true;
        this.attach(socket);
        resolve();
      });
      socket.once("error", (err) => {
        clearTimeout(timer);
        reject(err);
      });
    });

    if (this.options.password) {
      await this.send(["AUTH", this.options.password]);
    }
    if (this.options.db) {
      await this.send(["SELECT", this.options.db]);
    }
  }

  /** 发送单条命令 */
  async send(args: Array<string | number | Buffer>): Promise<Reply> {
    const replies = await this.writeCommands([args]);
    return replies[0] ?? null;
  }

  /** 流水线发送：一次写入、按序收全部响应，减少 RTT */
  async pipeline(commands: Array<Array<string | number | Buffer>>): Promise<Reply[]> {
    if (commands.length === 0) return [];
    return this.writeCommands(commands);
  }

  async close(): Promise<void> {
    if (!this.socket) return;
    try {
      await this.send(["QUIT"]);
    } catch {
      // 连接已断时直接销毁即可
    }
    this.socket.destroy();
    this.socket = null;
    this.writable = false;
  }

  private attach(socket: Socket): void {
    socket.on("data", (chunk: Buffer) => {
      const normalized: Buffer = Buffer.from(chunk);
      this.buffer = this.buffer.length === 0 ? normalized : Buffer.concat([this.buffer, normalized]);
      this.drain();
    });
    socket.on("error", (err) => {
      const pending = this.queue.splice(0);
      for (const call of pending) call.reject(err);
    });
    socket.on("close", () => {
      this.writable = false;
      const pending = this.queue.splice(0);
      for (const call of pending) call.reject(new Error("redis 连接已关闭"));
    });
  }

  private writeCommands(commands: Array<Array<string | number | Buffer>>): Promise<Reply[]> {
    return new Promise<Reply[]>((resolve, reject) => {
      if (!this.socket || !this.writable) {
        reject(new Error("redis 未连接"));
        return;
      }
      let payload = "";
      for (const args of commands) {
        payload += `*${args.length}\r\n`;
        for (const arg of args) {
          const buf = Buffer.isBuffer(arg) ? arg : Buffer.from(String(arg), "utf8");
          payload += `$${buf.length}\r\n`;
          payload += buf.toString("binary");
          payload += "\r\n";
        }
      }
      this.queue.push({ resolve, reject, count: commands.length });
      this.socket.write(Buffer.from(payload, "binary"));
    });
  }

  /** 尽可能多地从缓冲区解析完整响应，按调用配对 */
  private drain(): void {
    while (this.queue.length > 0) {
      let replies: Reply[];
      try {
        replies = this.readReplies(this.queue[0]!.count);
      } catch (err) {
        if (err instanceof IncompleteReply) return; // 等下一个 chunk，buffer 保持原样
        const call = this.queue.shift()!;
        this.buffer = Buffer.alloc(0);
        call.reject(err as Error);
        continue;
      }
      const call = this.queue.shift()!;
      call.resolve(replies);
    }
  }

  private readReplies(count: number): Reply[] {
    const out: Reply[] = [];
    for (let i = 0; i < count; i++) out.push(this.readValue());
    return out;
  }

  private readValue(): Reply {
    if (this.buffer.length < 4) throw new IncompleteReply();
    const type = String.fromCharCode(this.buffer[0]!);
    const lineEnd = this.buffer.indexOf("\r\n");
    if (lineEnd === -1) throw new IncompleteReply();
    const line = this.buffer.subarray(1, lineEnd).toString("utf8");

    switch (type) {
      case "+": {
        this.buffer = this.buffer.subarray(lineEnd + 2);
        return line;
      }
      case "-": {
        this.buffer = this.buffer.subarray(lineEnd + 2);
        throw new RedisProtocolError(`redis 错误: ${line}`);
      }
      case ":": {
        this.buffer = this.buffer.subarray(lineEnd + 2);
        return Number(line);
      }
      case "$": {
        const len = Number(line);
        if (len === -1) {
          this.buffer = this.buffer.subarray(lineEnd + 2);
          return null;
        }
        const dataStart = lineEnd + 2;
        if (this.buffer.length < dataStart + len + 2) throw new IncompleteReply();
        const value = this.buffer.subarray(dataStart, dataStart + len).toString("utf8");
        this.buffer = this.buffer.subarray(dataStart + len + 2);
        return value;
      }
      case "*": {
        const len = Number(line);
        this.buffer = this.buffer.subarray(lineEnd + 2);
        if (len === -1) return null;
        const arr: Reply[] = [];
        for (let i = 0; i < len; i++) arr.push(this.readValue());
        return arr;
      }
      default:
        throw new RedisProtocolError(`不支持的 RESP 类型: ${type}`);
    }
  }
}
