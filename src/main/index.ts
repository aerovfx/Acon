import { join } from "node:path";
import { app, BrowserWindow, dialog, ipcMain } from "electron";
import { SessionManager } from "./sessions.js";
import { KnownHosts } from "./engine/KnownHosts.js";
import { IPC, type ConnectRequest, type ShellRequest } from "../../shared/api.js";

let win: BrowserWindow | null = null;
let knownHosts: KnownHosts | null = null;

// §6: host-key trust. match → accept; changed → refuse (possible MITM); unknown → TOFU prompt.
// The prompt is a native modal in the main process so page content cannot spoof it.
async function verifyHostKey(host: string, port: number, keyBlob: Buffer): Promise<boolean> {
  const kh = knownHosts!;
  const r = kh.check(host, port, keyBlob);
  if (r.status === "match") return true;

  if (r.status === "changed") {
    await dialog.showMessageBox(win!, {
      type: "error",
      buttons: ["Abort connection"],
      defaultId: 0,
      title: "Host key changed",
      message: `WARNING: host key for ${host}:${port} has changed`,
      detail:
        `Offered (${r.keyType}): ${r.fingerprint}\n` +
        `Known:             ${r.knownFingerprint}\n\n` +
        "This could be a man-in-the-middle attack. Connection aborted. " +
        "If the change is expected, remove the stored key and reconnect.",
    });
    return false;
  }

  const { response } = await dialog.showMessageBox(win!, {
    type: "warning",
    buttons: ["Trust & continue", "Cancel"],
    defaultId: 1,
    cancelId: 1,
    title: "Unknown host",
    message: `The authenticity of host ${host}:${port} can't be established`,
    detail: `${r.keyType} key fingerprint:\n${r.fingerprint}\n\nTrust this host and remember it?`,
  });
  if (response === 0) {
    kh.add(host, port, keyBlob);
    return true;
  }
  return false;
}

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

const sessions = new SessionManager(() => win?.webContents ?? null, verifyHostKey);

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
  knownHosts = new KnownHosts(join(app.getPath("userData"), "known_hosts.json"));
  registerIpc();
  createWindow();
  app.on("activate", () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on("window-all-closed", () => {
  if (process.platform !== "darwin") app.quit();
});
