import { createHash, type KeyObject } from "node:crypto";

// OpenSSH public-key wire encoding (RFC 4253 §6.6 + RFC 8709 for ed25519).
// Each field is a 32-bit big-endian length followed by its bytes; mpints are
// big-endian two's-complement (a leading 0x00 is added when the MSB is set).

function sshString(buf: Buffer): Buffer {
  const len = Buffer.allocUnsafe(4);
  len.writeUInt32BE(buf.length, 0);
  return Buffer.concat([len, buf]);
}

function mpint(buf: Buffer): Buffer {
  let b = buf;
  let i = 0;
  while (i < b.length - 1 && b[i] === 0) i++; // drop leading zero bytes
  b = b.subarray(i);
  if (b.length > 0 && (b[0] & 0x80) !== 0) b = Buffer.concat([Buffer.from([0]), b]);
  return sshString(b);
}

function b64urlToBuf(s: string): Buffer {
  return Buffer.from(s, "base64url");
}

function leftPad(buf: Buffer, size: number): Buffer {
  if (buf.length >= size) return buf.subarray(buf.length - size);
  return Buffer.concat([Buffer.alloc(size - buf.length), buf]);
}

const EC_CURVE: Record<string, { name: string; size: number }> = {
  "P-256": { name: "nistp256", size: 32 },
  "P-384": { name: "nistp384", size: 48 },
  "P-521": { name: "nistp521", size: 66 },
};

export interface OpenSshPublicKey {
  type: string; // e.g. "ssh-ed25519"
  blob: Buffer; // the wire-format key blob
}

// Build the OpenSSH wire blob from a public (or private) KeyObject.
export function encodeOpenSshPublicKey(key: KeyObject): OpenSshPublicKey {
  const jwk = key.export({ format: "jwk" }) as Record<string, string>;
  switch (key.asymmetricKeyType) {
    case "ed25519": {
      const type = "ssh-ed25519";
      const pub = b64urlToBuf(jwk.x);
      return { type, blob: Buffer.concat([sshString(Buffer.from(type)), sshString(pub)]) };
    }
    case "ec": {
      const curve = EC_CURVE[jwk.crv];
      if (!curve) throw new Error(`unsupported EC curve: ${jwk.crv}`);
      const type = `ecdsa-sha2-${curve.name}`;
      const x = leftPad(b64urlToBuf(jwk.x), curve.size);
      const y = leftPad(b64urlToBuf(jwk.y), curve.size);
      const q = Buffer.concat([Buffer.from([0x04]), x, y]); // uncompressed point
      return {
        type,
        blob: Buffer.concat([
          sshString(Buffer.from(type)),
          sshString(Buffer.from(curve.name)),
          sshString(q),
        ]),
      };
    }
    case "rsa": {
      const type = "ssh-rsa";
      const e = b64urlToBuf(jwk.e);
      const n = b64urlToBuf(jwk.n);
      return {
        type,
        blob: Buffer.concat([sshString(Buffer.from(type)), mpint(e), mpint(n)]),
      };
    }
    default:
      throw new Error(`cannot encode OpenSSH public key for ${key.asymmetricKeyType}`);
  }
}

// "ssh-ed25519 AAAA… [comment]"
export function opensshPublicKeyLine(key: KeyObject, comment?: string): string {
  const { type, blob } = encodeOpenSshPublicKey(key);
  const line = `${type} ${blob.toString("base64")}`;
  return comment ? `${line} ${comment}` : line;
}

// "SHA256:…" fingerprint over the wire blob (matches `ssh-keygen -l`).
export function opensshFingerprintSha256(blob: Buffer): string {
  return "SHA256:" + createHash("sha256").update(blob).digest("base64").replace(/=+$/, "");
}
