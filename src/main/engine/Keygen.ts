import { generateKeyPairSync, createPublicKey, createPrivateKey } from "node:crypto";
import type { Keygen, KeygenOptions, SshKeyPair, SshKeyType } from "./types.js";
import {
  encodeOpenSshPublicKey,
  opensshFingerprintSha256,
  opensshPublicKeyLine,
} from "./openssh.js";

// §10b: Keygen contract. node:crypto covers rsa/ecdsa/ed25519 in OpenSSH format.
// PuTTY import and ML-DSA are left as TODO (ML-DSA needs a PQC provider; .ppk needs a parser).

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
    const publicKeyOpenSsh = opensshPublicKeyLine(pubKeyObj, options.comment);
    const { blob } = encodeOpenSshPublicKey(pubKeyObj);
    return {
      privateKeyOpenSsh: privPem,
      publicKeyOpenSsh,
      fingerprintSha256: opensshFingerprintSha256(blob),
      type: options.type,
    };
  }

  async generatePublicKeyFromPrivateKey(privateKey: string, passphrase?: string): Promise<string> {
    const priv = createPrivateKey({ key: privateKey, format: "pem", passphrase });
    const pub = createPublicKey(priv);
    return opensshPublicKeyLine(pub);
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
}
