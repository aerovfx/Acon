import { createRequire } from "node:module";
import type { VaultCrypto } from "./types.js";

// The ESM build of libsodium-wrappers-sumo@0.7.x is broken (its .mjs imports a file that is
// not shipped), so load the working CommonJS build explicitly via createRequire.
const sodium = createRequire(import.meta.url)(
  "libsodium-wrappers-sumo",
) as typeof import("libsodium-wrappers-sumo");

// §9 vault crypto on libsodium: Argon2id password KDF + XChaCha20-Poly1305 IETF AEAD.
// Ciphertext layout: version_byte(1) || nonce(24) || aead_ciphertext(+16-byte tag).
// This matches Termius' v4 primitive choices; exact KDF params / associated-data of the
// original vault are not known from static analysis, so wire-compatibility is not guaranteed.

const VERSION = 4;

async function ready(): Promise<typeof sodium> {
  await sodium.ready;
  return sodium;
}

export class SodiumVaultCrypto implements VaultCrypto {
  private key: Uint8Array | null = null;

  // Argon2id. Salt is normalized to crypto_pwhash_SALTBYTES deterministically.
  async createPasswordHash(password: string, salt: Uint8Array): Promise<Uint8Array> {
    const s = await ready();
    const salt16 =
      salt.length === s.crypto_pwhash_SALTBYTES
        ? salt
        : s.crypto_generichash(s.crypto_pwhash_SALTBYTES, salt);
    return s.crypto_pwhash(
      s.crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
      password,
      salt16,
      s.crypto_pwhash_OPSLIMIT_INTERACTIVE,
      s.crypto_pwhash_MEMLIMIT_INTERACTIVE,
      s.crypto_pwhash_ALG_ARGON2ID13,
    );
  }

  async generateEncryptionKey(): Promise<Uint8Array> {
    const s = await ready();
    this.key = s.randombytes_buf(s.crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
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
    const s = await ready();
    if (!this.key) throw new Error("vault key not set");
    const nonce = s.randombytes_buf(s.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    const ct = s.crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, null, null, nonce, this.key);
    const out = new Uint8Array(1 + nonce.length + ct.length);
    out[0] = VERSION;
    out.set(nonce, 1);
    out.set(ct, 1 + nonce.length);
    return out;
  }

  async decrypt(ciphertext: Uint8Array): Promise<Uint8Array> {
    const s = await ready();
    if (!this.key) throw new Error("vault key not set");
    if (this.getVersionFromCiphertext(ciphertext) !== VERSION) {
      throw new Error("unsupported ciphertext version");
    }
    const nbytes = s.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
    const nonce = ciphertext.subarray(1, 1 + nbytes);
    const ct = ciphertext.subarray(1 + nbytes);
    return s.crypto_aead_xchacha20poly1305_ietf_decrypt(null, ct, null, nonce, this.key);
  }
}
