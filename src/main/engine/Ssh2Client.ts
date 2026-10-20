import { randomUUID } from "node:crypto";
import { Client, type ClientChannel, type ConnectConfig } from "ssh2";
import type {
  ExecOptions,
  PortForwarding,
  PortForwardingOptions,
  RemoteTerminal,
  ShellOptions,
  Sftp,
  SftpOptions,
  SshClient,
  SshMethodType,
  SshOptions,
} from "./types.js";
import { Ssh2Sftp } from "./Ssh2Sftp.js";

class NotImplemented extends Error {
  constructor(what: string) {
    super(`${what} is not implemented in this skeleton yet`);
    this.name = "NotImplemented";
  }
}

// ssh2's negotiated algorithm names, surfaced per SshMethodType (§4 getAgreedSshMethod).
type Negotiated = Record<string, unknown> | undefined;

function pickMethod(neg: Negotiated, type: SshMethodType): string | null {
  if (!neg) return null;
  const map: Record<SshMethodType, string> = {
    kex: "kex",
    hostkey: "serverHostKey",
    cipher_cs: "cs.cipher",
    cipher_sc: "sc.cipher",
    mac: "cs.mac",
    compress: "cs.compress",
  };
  const path = map[type].split(".");
  let cur: unknown = neg;
  for (const p of path) {
    if (cur && typeof cur === "object" && p in (cur as Record<string, unknown>)) {
      cur = (cur as Record<string, unknown>)[p];
    } else {
      return null;
    }
  }
  return typeof cur === "string" ? cur : null;
}

class ChannelTerminal implements RemoteTerminal {
  readonly id = randomUUID();
  constructor(
    private readonly chan: ClientChannel,
    private readonly onData: (id: string, chunk: Buffer) => void,
    private readonly onExit: (id: string) => void,
  ) {
    chan.on("data", (c: Buffer) => this.onData(this.id, c));
    chan.stderr?.on("data", (c: Buffer) => this.onData(this.id, c));
    chan.on("close", () => this.onExit(this.id));
  }
  sendData(data: string | Uint8Array): void {
    this.chan.write(typeof data === "string" ? data : Buffer.from(data));
  }
  sendSize(cols: number, rows: number): void {
    this.chan.setWindow(rows, cols, 0, 0);
  }
  close(): Promise<void> {
    return new Promise((resolve) => {
      this.chan.close();
      resolve();
    });
  }
}

/**
 * ssh2-backed implementation of the SshClient contract (§4 / §6).
 * connect → shell/exec are fully wired; SFTP is wired; port forwarding + method
 * introspection are partially wired. Everything else throws NotImplemented but is typed,
 * so the app can be built against the full boundary.
 */
export class Ssh2Client implements SshClient {
  private conn: Client | null = null;
  private negotiated: Negotiated;

  // verifyHostKey decides whether to trust the server's key blob (§6 CheckKnownhosts).
  // It is injected so the trust store + any user prompt live outside the engine.
  constructor(
    private readonly emitData: (id: string, chunk: Buffer) => void,
    private readonly emitExit: (id: string) => void,
    private readonly verifyHostKey: (host: string, port: number, keyBlob: Buffer) => Promise<boolean>,
  ) {}

  connect(options: SshOptions): Promise<void> {
    return new Promise((resolve, reject) => {
      const conn = new Client();
      const cfg: ConnectConfig = {
        host: options.host,
        port: options.port,
        username: options.username,
        keepaliveInterval: options.keepaliveIntervalMs ?? 0,
        // ssh2 supports an async verifier: call back true/false after the trust decision.
        hostVerifier: (key: Buffer, cb: (ok: boolean) => void): void => {
          this.verifyHostKey(options.host, options.port, key).then(cb).catch(() => cb(false));
        },
      };
      // SshAuth method deque (§10a): map our ordered auth list onto ssh2's config.
      for (const m of options.auth) {
        if (m.kind === "password") cfg.password = m.password;
        else if (m.kind === "publicKey") {
          cfg.privateKey = m.privateKey;
          if (m.passphrase) cfg.passphrase = m.passphrase;
        } else if (m.kind === "agent") {
          cfg.agent = process.env.SSH_AUTH_SOCK;
        } else if (m.kind === "keyboard-interactive") {
          cfg.tryKeyboard = true;
        }
      }
      conn
        .on("handshake", (neg) => {
          this.negotiated = neg as unknown as Negotiated;
        })
        .on("ready", () => {
          this.conn = conn;
          resolve();
        })
        .on("error", (err) => reject(err))
        .connect(cfg);
    });
  }

  private requireConn(): Client {
    if (!this.conn) throw new Error("SSH client is not connected");
    return this.conn;
  }

  shell(options: ShellOptions): Promise<RemoteTerminal> {
    const conn = this.requireConn();
    return new Promise((resolve, reject) => {
      conn.shell(
        {
          term: options.term ?? "xterm-256color",
          cols: options.cols ?? 80,
          rows: options.rows ?? 24,
        },
        { env: options.env },
        (err, chan) => {
          if (err) return reject(err);
          resolve(new ChannelTerminal(chan, this.emitData, this.emitExit));
        },
      );
    });
  }

  exec(options: ExecOptions): Promise<RemoteTerminal> {
    const conn = this.requireConn();
    return new Promise((resolve, reject) => {
      conn.exec(options.command, { pty: options.pty, env: options.env }, (err, chan) => {
        if (err) return reject(err);
        resolve(new ChannelTerminal(chan, this.emitData, this.emitExit));
      });
    });
  }

  interactiveExec(options: ExecOptions): Promise<RemoteTerminal> {
    return this.exec({ ...options, pty: true });
  }

  sftp(_options?: SftpOptions): Promise<Sftp> {
    const conn = this.requireConn();
    return new Promise((resolve, reject) => {
      conn.sftp((err, sftp) => {
        if (err) return reject(err);
        resolve(new Ssh2Sftp(sftp));
      });
    });
  }

  localPortForwarding(options: PortForwardingOptions): Promise<PortForwarding> {
    // TODO: net.createServer on bind*, conn.forwardOut to dest* per connection.
    throw new NotImplemented(`localPortForwarding(${options.bindPort})`);
  }
  remotePortForwarding(options: PortForwardingOptions): Promise<PortForwarding> {
    // TODO: conn.forwardIn(bindAddress, bindPort) + 'tcp connection' handler.
    throw new NotImplemented(`remotePortForwarding(${options.bindPort})`);
  }
  dynamicPortForwarding(options: PortForwardingOptions): Promise<PortForwarding> {
    // TODO: SOCKS5 server on bind*, conn.forwardOut to the SOCKS-requested target.
    throw new NotImplemented(`dynamicPortForwarding(${options.bindPort})`);
  }

  getClientSshMethods(_type: SshMethodType): string[] {
    // ssh2 exposes the agreed set via 'handshake'; the full client offer list is not surfaced.
    return [];
  }
  getServerSshMethods(_type: SshMethodType): string[] {
    return [];
  }
  getAgreedSshMethod(type: SshMethodType): string | null {
    return pickMethod(this.negotiated, type);
  }

  close(_reason?: string): Promise<void> {
    return new Promise((resolve) => {
      this.conn?.end();
      this.conn = null;
      resolve();
    });
  }
}
