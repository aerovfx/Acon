import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { opensshFingerprintSha256, readOpenSshKeyType } from "./openssh.js";

// §6 CheckKnownhosts: a persistent trust store. Entries are keyed by host:port and hold the
// server's public-key blob. Verification is TOFU — unknown hosts are offered to the user,
// a changed key is a hard failure (possible MITM).

export type HostCheck =
  | { status: "match" }
  | { status: "unknown"; fingerprint: string; keyType: string }
  | { status: "changed"; fingerprint: string; knownFingerprint: string; keyType: string };

interface Entry {
  keyType: string;
  keyBase64: string;
  fingerprint: string;
  addedAt: string;
}

function hostKey(host: string, port: number): string {
  return port === 22 ? host : `[${host}]:${port}`;
}

export class KnownHosts {
  private map: Record<string, Entry> = {};

  constructor(private readonly filePath: string) {
    try {
      this.map = JSON.parse(readFileSync(filePath, "utf8")) as Record<string, Entry>;
    } catch {
      this.map = {}; // missing/corrupt file → start empty
    }
  }

  check(host: string, port: number, keyBlob: Buffer): HostCheck {
    const entry = this.map[hostKey(host, port)];
    const keyType = readOpenSshKeyType(keyBlob);
    const fingerprint = opensshFingerprintSha256(keyBlob);
    if (!entry) return { status: "unknown", fingerprint, keyType };
    if (entry.keyBase64 === keyBlob.toString("base64")) return { status: "match" };
    return { status: "changed", fingerprint, knownFingerprint: entry.fingerprint, keyType };
  }

  add(host: string, port: number, keyBlob: Buffer): void {
    this.map[hostKey(host, port)] = {
      keyType: readOpenSshKeyType(keyBlob),
      keyBase64: keyBlob.toString("base64"),
      fingerprint: opensshFingerprintSha256(keyBlob),
      addedAt: new Date().toISOString(),
    };
    this.save();
  }

  remove(host: string, port: number): void {
    delete this.map[hostKey(host, port)];
    this.save();
  }

  private save(): void {
    mkdirSync(dirname(this.filePath), { recursive: true });
    writeFileSync(this.filePath, JSON.stringify(this.map, null, 2), { mode: 0o600 });
  }
}
