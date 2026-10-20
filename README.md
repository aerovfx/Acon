# Acon

SSH client skeleton — **Electron + xterm.js + ssh2** — built against the native API contract
recovered from Termius `libtermius` (§4 of the clone blueprint). The goal is a faithful **boundary**:
the engine layer exposes the same module/method surface as the original native add-on, implemented
on open-source libraries (`ssh2`, `node:crypto`).

> This is an independent re-implementation for interoperability/learning. It contains no Termius
> source or assets. Respect Termius' trademark and terms of service.

## Status

| Area | State |
|------|-------|
| SSH connect + interactive shell (xterm) | ✅ working end-to-end (`ssh2`) |
| `exec` / `interactiveExec` | ✅ wired |
| SFTP (list/stat/chmod/rename/mkdir/remove/symlink/read/write) | ✅ wired (`Ssh2Sftp`) |
| Host key verification (SHA256) | ✅ persistent known_hosts (JSON) + TOFU native prompt; changed key is refused |
| Port forwarding (local/remote/dynamic) | ✅ local (net+forwardOut), remote (forwardIn), dynamic (SOCKS5 proxy) |
| SSH method introspection (agreed/server/client) | ⚠️ agreed only |
| Keygen (rsa/ecdsa/ed25519) | ✅ keys generate with OpenSSH pubkey + SHA256 fingerprint (verified vs `ssh-keygen -l`); dsa/ML-DSA/PuTTY TODO |
| Vault crypto (`VaultCrypto`) | ⚠️ node:crypto stand-in (AES-256-GCM + scrypt); swap for libsodium + Argon2id to be wire-compatible |
| SSH agent (store + messaging bus + forwarding) | ⛔ memory store stub only |

## Architecture

```
src/
  main/                 Electron main process (Node — runs the SSH engine)
    index.ts            app lifecycle, BrowserWindow, IPC handler registration
    sessions.ts         one engine client per session id; streams channel output
    engine/
      types.ts          THE CONTRACT (§4): SshClient, Sftp, Keygen, SshAgentStorage, VaultCrypto
      Ssh2Client.ts     SshClient on ssh2 (connect/shell/exec/sftp wired; forwarding stubbed)
      Ssh2Sftp.ts       Sftp on ssh2's SFTPWrapper (§11a)
      Keygen.ts         Keygen on node:crypto (§10b)
      VaultCrypto.ts    vault crypto, version-byte ciphertext (§9)
      AgentStorage.ts   in-process agent key store (§11b)
  preload/index.ts      contextBridge → window.api (typed, contextIsolation on)
  renderer/             UI (no Node): xterm.js terminal + connect form
shared/api.ts           IPC channel names + payload types (main ⇄ renderer)
```

The **engine layer is the point**: `src/main/engine/types.ts` encodes the recovered native contract,
so the UI and app logic can be built against a stable boundary and the SSH backend swapped
(ssh2 → a libssh2 N-API binding) without touching callers.

## Run

```bash
cd /Users/dangvietchung/acon
npm install
npm run dev
```

Then enter host / port / username / password and click Connect. Key-based auth is modeled in
`SshOptions.auth` (an ordered list, like the native `SshAuth` method deque, §10a) — the form only
wires password for now.

```bash
npm run typecheck   # strict TS check, no emit
npm run build       # electron-vite production build
```

## Roadmap toward parity

1. ~~OpenSSH public-key wire encoding in `Keygen`~~ ✅ done (`openssh.ts`; ed25519/ecdsa/rsa, fingerprints verified against `ssh-keygen -l`).
2. ~~Persistent known_hosts store with TOFU prompt~~ ✅ done (`KnownHosts.ts` + native modal in `index.ts`; `userData/known_hosts.json`, mode 0600).
3. ~~Port forwarding: local / remote / dynamic~~ ✅ done (`forwarding.ts`; SOCKS5 CONNECT for dynamic — no-auth, IPv4/domain/IPv6). Live multi-host integration test still TODO.
4. Vault: replace node:crypto with libsodium (XChaCha20-Poly1305) + Argon2id to match v4 ciphertext.
5. SSH agent: messaging bus + `auth-agent@openssh.com` forwarding with per-sign user prompt (§11b).
6. Sync/data model + backend (`/api/v4.x`, socket.io/gRPC) — the renderer app logic (not recoverable
   from the original; design your own).
