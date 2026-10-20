import type { AgentKey, SshAgentStorage } from "./types.js";

// §11b: in-process SSH agent key store. A full clone also needs the AgentMessaging client/server
// bus and the auth-agent@openssh.com forwarding handler with a per-sign user prompt.
export class MemoryAgentStorage implements SshAgentStorage {
  private keys = new Map<string, { privateKey: string; passphrase?: string; comment: string }>();

  async addKey(privateKey: string, comment: string, passphrase?: string): Promise<void> {
    // TODO: derive the OpenSSH public key as the stable map id (see Keygen).
    const id = `key-${this.keys.size}`;
    this.keys.set(id, { privateKey, passphrase, comment });
  }
  async removeKey(publicKeyOpenSsh: string): Promise<void> {
    this.keys.delete(publicKeyOpenSsh);
  }
  async getKeys(): Promise<AgentKey[]> {
    return [...this.keys.entries()].map(([id, v]) => ({ publicKeyOpenSsh: id, comment: v.comment }));
  }
}
