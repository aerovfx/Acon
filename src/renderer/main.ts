import { Terminal } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import "@xterm/xterm/css/xterm.css";
import type { RendererApi } from "../../shared/api.js";

declare global {
  interface Window {
    api: RendererApi;
  }
}

const $ = <T extends HTMLElement>(id: string): T => document.getElementById(id) as T;
const statusEl = $("status");
function setStatus(msg: string, kind: "" | "ok" | "error" = ""): void {
  statusEl.textContent = msg;
  statusEl.className = kind;
}

const term = new Terminal({
  fontFamily: "Menlo, monospace",
  fontSize: 13,
  cursorBlink: true,
  theme: { background: "#1e1e1e" },
});
const fit = new FitAddon();
term.loadAddon(fit);
term.open($("terminal"));
fit.fit();

const sessionId = crypto.randomUUID();
let terminalId: string | null = null;

function b64ToText(b64: string): string {
  const bin = atob(b64);
  const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
  return new TextDecoder().decode(bytes);
}

window.api.onData((e) => {
  if (e.sessionId === sessionId) term.write(b64ToText(e.chunkBase64));
});
window.api.onExit((e) => {
  if (e.sessionId === sessionId) {
    setStatus("session closed");
    terminalId = null;
  }
});

// xterm -> remote
term.onData((data) => {
  if (terminalId) window.api.sendData(sessionId, terminalId, data);
});
term.onResize(({ cols, rows }) => {
  if (terminalId) window.api.sendSize(sessionId, terminalId, cols, rows);
});
window.addEventListener("resize", () => fit.fit());

$("connect").addEventListener("click", async () => {
  const host = ($("host") as HTMLInputElement).value.trim();
  const port = parseInt(($("port") as HTMLInputElement).value, 10) || 22;
  const username = ($("user") as HTMLInputElement).value.trim();
  const password = ($("pass") as HTMLInputElement).value;
  if (!host || !username) return setStatus("host and username required", "error");

  setStatus("connecting…");
  const conn = await window.api.connect({
    sessionId,
    options: { host, port, username, auth: [{ kind: "password", password }] },
  });
  if (!conn.ok) return setStatus(conn.error, "error");

  const shell = await window.api.shell({
    sessionId,
    options: { term: "xterm-256color", cols: term.cols, rows: term.rows },
  });
  if (!shell.ok) return setStatus(shell.error, "error");
  terminalId = shell.terminalId;
  setStatus(`connected to ${host}`, "ok");
  term.focus();
});
