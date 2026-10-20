import { contextBridge, ipcRenderer } from "electron";
import {
  IPC,
  type ConnectRequest,
  type DataEvent,
  type ExitEvent,
  type RendererApi,
  type ShellRequest,
} from "../../shared/api.js";

const api: RendererApi = {
  connect: (req: ConnectRequest) => ipcRenderer.invoke(IPC.sshConnect, req),
  shell: (req: ShellRequest) => ipcRenderer.invoke(IPC.sshShell, req),
  sendData: (sessionId, terminalId, data) =>
    ipcRenderer.send(IPC.sshSendData, sessionId, terminalId, data),
  sendSize: (sessionId, terminalId, cols, rows) =>
    ipcRenderer.send(IPC.sshSendSize, sessionId, terminalId, cols, rows),
  close: (sessionId) => ipcRenderer.invoke(IPC.sshClose, sessionId),
  onData: (cb) => ipcRenderer.on(IPC.sshData, (_e, p: DataEvent) => cb(p)),
  onExit: (cb) => ipcRenderer.on(IPC.sshExit, (_e, p: ExitEvent) => cb(p)),
};

contextBridge.exposeInMainWorld("api", api);
