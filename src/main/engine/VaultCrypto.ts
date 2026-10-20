import { createCipheriv, createDecipheriv, randomBytes, scryptSync } from "node:crypto";
import type { VaultCrypto } from "./types.js";

// §9: vault crypto. Ciphertext layout = version_byte(1) || payload.
// Termius v4 uses libsodium XChaCha20-Poly1305 + Argon2id. This skeleton implements a
// node:crypto equivalent (version 4 => AES-256-GCM, scrypt KDF) so the boundary is exercised;
// swap in libsodium + Argon2id to be wire-compatible with the original vault.

const VERSION = 4;
const NONCE_LEN = 12; // GCM nonce
const TAG_LEN = 16;
const SALT_LEN = 16;

export class NodeVaultCrypto implements VaultCrypto {
  private key: Uint8Array | null = null;

  async createPasswordHash(password: string, salt: Uint8Array): Promise<Uint8Array> {
    // TODO: replace scrypt with Argon2id ($argon2id$v=19$...) to match the original.
    return scryptSync(password, Buffer.from(salt), 32);
  }

  async generateEncryptionKey(): Promise<Uint8Array> {
    this.key = randomBytes(32);
    return this.key;
  }

  setKey(key: Uint8Array): void {
    this.key = key;
  }

  getVersionFromCiphertext(ciphertext: Uint8Array): number {
    if (ciphertext.length === 0) return 0;
    const v = ciphertext[0];
    return v >= 1 && v <= 4 ? v : 0;
  }

  async encrypt(plaintext: Uint8Array): Promise<Uint8Array> {
    if (!this.key) throw new Error("vault key not set");
    const salt = randomBytes(SALT_LEN); // bound for context / future KDF rekey
    const nonce = randomBytes(NONCE_LEN);
    const cipher = createCipheriv("aes-256-gcm", Buffer.from(this.key), nonce);
    const body = Buffer.concat([cipher.update(Buffer.from(plaintext)), cipher.final()]);
    const tag = cipher.getAuthTag();
    // version || salt || nonce || tag || body
    return Buffer.concat([Buffer.from([VERSION]), salt, nonce, tag, body]);
  }

  async decrypt(ciphertext: Uint8Array): Promise<Uint8Array> {
    if (!this.key) throw new Error("vault key not set");
    if (this.getVersionFromCiphertext(ciphertext) !== VERSION) {
      throw new Error("unsupported ciphertext version");
    }
    const buf = Buffer.from(ciphertext);
    let o = 1 + SALT_LEN;
    const nonce = buf.subarray(o, o + NONCE_LEN);
    o += NONCE_LEN;
    const tag = buf.subarray(o, o + TAG_LEN);
    o += TAG_LEN;
    const body = buf.subarray(o);
    const decipher = createDecipheriv("aes-256-gcm", Buffer.from(this.key), nonce);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(body), decipher.final()]);
  }
}
