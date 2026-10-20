import { generateKeyPairSync, createPublicKey, createPrivateKey, createHash } from "node:crypto";
import type { Keygen, KeygenOptions, SshKeyPair, SshKeyType } from "./types.js";

// §10b: Keygen contract. node:crypto covers rsa/ecdsa/ed25519 in OpenSSH format.
// PuTTY import and ML-DSA are left as TODO (ML-DSA needs a PQC provider; .ppk needs a parser).

function opensshFingerprintSha256(publicKeyOpenSsh: string): string {
  // OpenSSH pubkey: "<type> <base64 blob> [comment]"
  const b64 = publicKeyOpenSsh.trim().split(/\s+/)[1] ?? "";
  const blob = Buffer.from(b64, "base64");
  return "SHA256:" + createHash("sha256").update(blob).digest("base64").replace(/=+$/, "");
}

export class NodeKeygen implements Keygen {
  async generateSshKey(options: KeygenOptions): Promise<SshKeyPair> {
    const privEnc = {
      type: "pkcs8" as const,
      format: "pem" as const,
      ...(options.passphrase
        ? { cipher: "aes-256-cbc" as const, passphrase: options.passphrase }
        : {}),
    };
    let privPem: string;
    let pubKeyObj;
    switch (options.type) {
      case "rsa": {
        const { privateKey, publicKey } = generateKeyPairSync("rsa", {
          modulusLength: options.bits ?? 3072,
          privateKeyEncoding: privEnc,
          publicKeyEncoding: { type: "spki", format: "pem" },
        });
        privPem = privateKey;
        pubKeyObj = createPublicKey(publicKey);
        break;
      }
      case "ecdsa": {
        const curveMap = { nistp256: "prime256v1", nistp384: "secp384r1", nistp521: "secp521r1" };
        const { privateKey, publicKey } = generateKeyPairSync("ec", {
          namedCurve: curveMap[options.curve ?? "nistp256"],
          privateKeyEncoding: privEnc,
          publicKeyEncoding: { type: "spki", format: "pem" },
        });
        privPem = privateKey;
        pubKeyObj = createPublicKey(publicKey);
        break;
      }
      case "ed25519": {
        const { privateKey, publicKey } = generateKeyPairSync("ed25519", {
          privateKeyEncoding: privEnc,
          publicKeyEncoding: { type: "spki", format: "pem" },
        });
        privPem = privateKey;
        pubKeyObj = createPublicKey(publicKey);
        break;
      }
      default:
        throw new Error(`generateSshKey: type '${options.type}' not implemented (dsa/mldsa TODO)`);
    }
    // TODO: convert SPKI public key to the OpenSSH wire format ("ssh-ed25519 AAAA...").
    // node:crypto has no built-in OpenSSH exporter; a small encoder is needed here.
    const publicKeyOpenSsh = pubKeyObj
      .export({ type: "spki", format: "pem" })
      .toString()
      .trim();
    return {
      privateKeyOpenSsh: privPem,
      publicKeyOpenSsh,
      fingerprintSha256: "", // filled once OpenSSH pubkey encoding is implemented
      type: options.type,
    };
  }

  async generatePublicKeyFromPrivateKey(privateKey: string, passphrase?: string): Promise<string> {
    const priv = createPrivateKey({ key: privateKey, format: "pem", passphrase });
    const pub = createPublicKey(priv);
    return pub.export({ type: "spki", format: "pem" }).toString().trim();
  }

  async generateSshKeyFromPuttyKey(_ppk: string, _passphrase?: string): Promise<SshKeyPair> {
    throw new Error("generateSshKeyFromPuttyKey: .ppk parser not implemented yet");
  }

  async getKeyTypeFromPrivateKey(privateKey: string): Promise<SshKeyType> {
    const t = createPublicKey(privateKey).asymmetricKeyType;
    if (t === "rsa") return "rsa";
    if (t === "ec") return "ecdsa";
    if (t === "ed25519") return "ed25519";
    throw new Error(`unknown key type: ${t}`);
  }

  async checkPrivateKeyEncrypted(privateKey: string): Promise<boolean> {
    return /ENCRYPTED/.test(privateKey) || /aes-\d+-cbc/i.test(privateKey);
  }
  async checkPrivateKeyEncryptedWithPassword(privateKey: string, password: string): Promise<boolean> {
    try {
      createPrivateKey({ key: privateKey, format: "pem", passphrase: password });
      return true;
    } catch {
      return false;
    }
  }
  async validatePublicKeyFormat(publicKey: string): Promise<boolean> {
    try {
      createPublicKey(publicKey);
      return true;
    } catch {
      return false;
    }
  }
  async validatePrivateKeyFormat(privateKey: string): Promise<boolean> {
    try {
      createPublicKey(privateKey);
      return true;
    } catch {
      return false;
    }
  }

  // exported for reuse once OpenSSH encoding lands
  static fingerprint = opensshFingerprintSha256;
}
