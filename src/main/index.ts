import { join } from "node:path";
import { app, BrowserWindow, ipcMain } from "electron";
import { SessionManager } from "./sessions.js";
import { IPC, type ConnectRequest, type ShellRequest } from "../../shared/api.js";

let win: BrowserWindow | null = null;

function createWindow(): void {
  win = new BrowserWindow({
    width: 1000,
    height: 680,
    show: false,
    webPreferences: {
      preload: join(__dirname, "../preload/index.mjs"),
      sandbox: false, // preload needs Node to require the bridge; keep contextIsolation on
      contextIsolation: true,
      nodeIntegration: false,
    },
  });
  win.on("ready-to-show", () => win?.show());

  if (process.env.ELECTRON_RENDERER_URL) {
    void win.loadURL(process.env.ELECTRON_RENDERER_URL);
  } else {
    void win.loadFile(join(__dirname, "../renderer/index.html"));
  }
}

const sessions = new SessionManager(() => win?.webContents ?? null);

function registerIpc(): void {
  ipcMain.handle(IPC.sshConnect, async (_e, req: ConnectRequest) => {
    try {
      await sessions.getOrCreate(req.sessionId).connect(req.options);
      return { ok: true as const };
    } catch (err) {
      return { ok: false as const, error: err instanceof Error ? err.message : String(err) };
    }
  });

  ipcMain.handle(IPC.sshShell, async (_e, req: ShellRequest) => {
    try {
      const term = await sessions.getOrCreate(req.sessionId).shell(req.options);
      sessions.track(req.sessionId, term);
      return { ok: true as const, terminalId: term.id };
    } catch (err) {
      return { ok: false as const, error: err instanceof Error ? err.message : String(err) };
    }
  });

  ipcMain.on(IPC.sshSendData, (_e, sessionId: string, terminalId: string, data: string) => {
    sessions.terminal(sessionId, terminalId)?.sendData(data);
  });

  ipcMain.on(
    IPC.sshSendSize,
    (_e, sessionId: string, terminalId: string, cols: number, rows: number) => {
      sessions.terminal(sessionId, terminalId)?.sendSize(cols, rows);
    },
  );

  ipcMain.handle(IPC.sshClose, async (_e, sessionId: string) => {
    await sessions.close(sessionId);
  });
}

app.whenReady().then(() => {
  registerIpc();
  createWindow();
  app.on("activate", () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on("window-all-closed", () => {
  if (process.platform !== "darwin") app.quit();
});
