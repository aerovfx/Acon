import { createServer, connect, type Socket } from "node:net";
import type { Client, ClientChannel } from "ssh2";
import type { PortForwarding, PortForwardingOptions } from "./types.js";

// §4 port forwarding, on ssh2. Local = listen locally, forwardOut per connection.
// Remote = ask the server to listen (forwardIn), pipe back. Dynamic = local SOCKS5 proxy.

function pipe(sock: Socket, chan: ClientChannel): void {
  sock.pipe(chan);
  chan.pipe(sock);
  const kill = (): void => {
    sock.destroy();
    chan.close();
  };
  sock.on("error", kill);
  chan.on("error", kill);
  sock.on("close", () => chan.close());
  chan.on("close", () => sock.destroy());
}

function makePF(bindAddress: string, bindPort: number, closeFn: () => Promise<void>): PortForwarding {
  return {
    getBindAddress: () => bindAddress,
    getBindPort: () => bindPort,
    close: closeFn,
  };
}

export function startLocalForward(
  conn: Client,
  o: PortForwardingOptions,
): Promise<PortForwarding> {
  if (!o.destHost || !o.destPort) {
    return Promise.reject(new Error("local forwarding requires destHost and destPort"));
  }
  return new Promise((resolve, reject) => {
    const server = createServer((sock) => {
      conn.forwardOut(
        sock.remoteAddress ?? "127.0.0.1",
        sock.remotePort ?? 0,
        o.destHost!,
        o.destPort!,
        (err, chan) => {
          if (err) {
            sock.destroy();
            return;
          }
          pipe(sock, chan);
        },
      );
    });
    server.on("error", reject);
    server.listen(o.bindPort, o.bindAddress, () => {
      const addr = server.address();
      const port = typeof addr === "object" && addr ? addr.port : o.bindPort;
      resolve(makePF(o.bindAddress, port, () => new Promise((res) => server.close(() => res()))));
    });
  });
}

export function startRemoteForward(
  conn: Client,
  o: PortForwardingOptions,
): Promise<PortForwarding> {
  if (!o.destHost || !o.destPort) {
    return Promise.reject(new Error("remote forwarding requires destHost and destPort"));
  }
  return new Promise((resolve, reject) => {
    conn.forwardIn(o.bindAddress, o.bindPort, (err, actualPort) => {
      if (err) return reject(err);
      const port = actualPort ?? o.bindPort;
      // Route only the 'tcp connection' events for this bind back to our destination.
      const onConn = (
        details: { destIP: string; destPort: number },
        accept: () => ClientChannel,
        rejectConn: () => void,
      ): void => {
        if (details.destPort !== port) return; // belongs to another forward
        const chan = accept();
        const sock = connect(o.destPort!, o.destHost!, () => pipe(sock, chan));
        sock.on("error", () => {
          chan.close();
          rejectConn();
        });
      };
      conn.on("tcp connection", onConn);
      resolve(
        makePF(
          o.bindAddress,
          port,
          () =>
            new Promise((res) => {
              conn.removeListener("tcp connection", onConn);
              conn.unforwardIn(o.bindAddress, port, () => res());
            }),
        ),
      );
    });
  });
}

type SocksStage = "greeting" | "request" | "connecting" | "piping";

// Minimal SOCKS5 CONNECT proxy: no-auth only, IPv4/domain/IPv6 targets.
function handleSocks(sock: Socket, conn: Client): void {
  let stage: SocksStage = "greeting";
  let buf = Buffer.alloc(0);

  const reply = (rep: number): void => {
    sock.write(Buffer.from([0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));
  };

  const process = (): void => {
    if (stage === "connecting" || stage === "piping") return;

    if (stage === "greeting") {
      if (buf.length < 2) return;
      if (buf[0] !== 0x05) {
        sock.end();
        return;
      }
      const n = buf[1];
      if (buf.length < 2 + n) return;
      buf = buf.subarray(2 + n);
      sock.write(Buffer.from([0x05, 0x00])); // choose no-auth
      stage = "request";
    }

    if (stage === "request") {
      if (buf.length < 4) return;
      const ver = buf[0];
      const cmd = buf[1];
      const atyp = buf[3];
      if (ver !== 0x05) {
        sock.end();
        return;
      }

      let host: string;
      let offset: number;
      if (atyp === 0x01) {
        if (buf.length < 10) return;
        host = `${buf[4]}.${buf[5]}.${buf[6]}.${buf[7]}`;
        offset = 8;
      } else if (atyp === 0x03) {
        const len = buf[4];
        if (buf.length < 5 + len + 2) return;
        host = buf.subarray(5, 5 + len).toString("utf8");
        offset = 5 + len;
      } else if (atyp === 0x04) {
        if (buf.length < 22) return;
        const parts: string[] = [];
        for (let i = 0; i < 16; i += 2) parts.push(buf.readUInt16BE(4 + i).toString(16));
        host = parts.join(":");
        offset = 20;
      } else {
        reply(0x08); // address type not supported
        sock.end();
        return;
      }

      const port = buf.readUInt16BE(offset);
      buf = buf.subarray(offset + 2);

      if (cmd !== 0x01) {
        reply(0x07); // command not supported (only CONNECT)
        sock.end();
        return;
      }

      stage = "connecting";
      conn.forwardOut(sock.remoteAddress ?? "127.0.0.1", sock.remotePort ?? 0, host, port, (err, chan) => {
        if (err) {
          reply(0x05); // connection refused
          sock.end();
          return;
        }
        reply(0x00); // succeeded
        stage = "piping";
        sock.removeListener("data", onData);
        if (buf.length) chan.write(buf); // flush any early bytes
        buf = Buffer.alloc(0);
        pipe(sock, chan);
      });
    }
  };

  const onData = (d: Buffer): void => {
    buf = Buffer.concat([buf, d]);
    process();
  };
  sock.on("data", onData);
  sock.on("error", () => sock.destroy());
}

export function startDynamicForward(
  conn: Client,
  o: PortForwardingOptions,
): Promise<PortForwarding> {
  return new Promise((resolve, reject) => {
    const server = createServer((sock) => handleSocks(sock, conn));
    server.on("error", reject);
    server.listen(o.bindPort, o.bindAddress, () => {
      const addr = server.address();
      const port = typeof addr === "object" && addr ? addr.port : o.bindPort;
      resolve(makePF(o.bindAddress, port, () => new Promise((res) => server.close(() => res()))));
    });
  });
}
