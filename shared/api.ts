// IPC contract shared between main and renderer (preload re-exposes it on window.api).
import type { SshOptions, ShellOptions } from "../src/main/engine/types.js";

export const IPC = {
  sshConnect: "ssh:connect",
  sshShell: "ssh:shell",
  sshSendData: "ssh:sendData",
  sshSendSize: "ssh:sendSize",
  sshClose: "ssh:close",
  // main -> renderer streaming
  sshData: "ssh:data",
  sshExit: "ssh:exit",
} as const;

export interface ConnectRequest {
  sessionId: string;
  options: SshOptions;
}
export interface ShellRequest {
  sessionId: string;
  options: ShellOptions;
}
export interface DataEvent {
  sessionId: string;
  terminalId: string;
  chunkBase64: string;
}
export interface ExitEvent {
  sessionId: string;
  terminalId: string;
}

// Shape exposed to the renderer via contextBridge.
export interface RendererApi {
  connect(req: ConnectRequest): Promise<{ ok: true } | { ok: false; error: string }>;
  shell(req: ShellRequest): Promise<{ ok: true; terminalId: string } | { ok: false; error: string }>;
  sendData(sessionId: string, terminalId: string, data: string): void;
  sendSize(sessionId: string, terminalId: string, cols: number, rows: number): void;
  close(sessionId: string): Promise<void>;
  onData(cb: (e: DataEvent) => void): void;
  onExit(cb: (e: ExitEvent) => void): void;
}
