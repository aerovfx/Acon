import type { WebContents } from "electron";
import { Ssh2Client } from "./engine/Ssh2Client.js";
import type { RemoteTerminal } from "./engine/types.js";
import { IPC, type DataEvent, type ExitEvent } from "../../shared/api.js";

// One Ssh2Client per session id, plus its open terminals. Streams channel output to the renderer.
export class SessionManager {
  private clients = new Map<string, Ssh2Client>();
  private terminals = new Map<string, Map<string, RemoteTerminal>>();

  constructor(
    private readonly sender: () => WebContents | null,
    private readonly verifyHostKey: (host: string, port: number, keyBlob: Buffer) => Promise<boolean>,
  ) {}

  private emit<T>(channel: string, payload: T): void {
    this.sender()?.send(channel, payload);
  }

  getOrCreate(sessionId: string): Ssh2Client {
    let c = this.clients.get(sessionId);
    if (!c) {
      c = new Ssh2Client(
        (terminalId, chunk) => {
          const e: DataEvent = { sessionId, terminalId, chunkBase64: chunk.toString("base64") };
          this.emit(IPC.sshData, e);
        },
        (terminalId) => {
          const e: ExitEvent = { sessionId, terminalId };
          this.emit(IPC.sshExit, e);
          this.terminals.get(sessionId)?.delete(terminalId);
        },
        this.verifyHostKey,
      );
      this.clients.set(sessionId, c);
      this.terminals.set(sessionId, new Map());
    }
    return c;
  }

  track(sessionId: string, term: RemoteTerminal): void {
    this.terminals.get(sessionId)?.set(term.id, term);
  }
  terminal(sessionId: string, terminalId: string): RemoteTerminal | undefined {
    return this.terminals.get(sessionId)?.get(terminalId);
  }

  async close(sessionId: string): Promise<void> {
    await this.clients.get(sessionId)?.close();
    this.clients.delete(sessionId);
    this.terminals.delete(sessionId);
  }
}
