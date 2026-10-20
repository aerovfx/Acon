// Engine contract — mirrors the libtermius native API surface (§4 of CLONE_BLUEPRINT.md).
// This is the interoperability spec recovered by static analysis; the implementations here are
// our own, built on OSS (ssh2 / node:crypto). Method names intentionally match the native modules
// so the rest of the app can be ported against a stable boundary.

// ---- SshClient (§4 SshClient) ----

export type SshAuthMethod =
  | { kind: "password"; password: string }
  | { kind: "publicKey"; privateKey: string; passphrase?: string }
  | { kind: "agent" } // publicKey-with-sign, served by the SSH agent
  | { kind: "keyboard-interactive" };

export interface SshOptions {
  host: string;
  port: number;
  username: string;
  auth: SshAuthMethod[]; // tried in order, like SshAuth's method deque (§10a)
  // Known-hosts verification is the caller's responsibility (see §6 CheckKnownhosts).
  hostFingerprintSha256?: string;
  keepaliveIntervalMs?: number;
}

export type SshMethodType = "kex" | "hostkey" | "cipher_cs" | "cipher_sc" | "mac" | "compress";

export interface ExecOptions {
  command: string;
  pty?: boolean;
  env?: Record<string, string>;
}

export interface ShellOptions {
  term?: string; // e.g. "xterm-256color"
  cols?: number;
  rows?: number;
  env?: Record<string, string>;
}

export interface PortForwardingOptions {
  // local: listen on (bindAddress:bindPort), forward to (destHost:destPort)
  // remote: ask server to listen on (bindAddress:bindPort), forward back to (destHost:destPort)
  // dynamic: SOCKS proxy on (bindAddress:bindPort)
  bindAddress: string;
  bindPort: number;
  destHost?: string;
  destPort?: number;
}

export interface PortForwarding {
  getBindAddress(): string;
  getBindPort(): number;
  close(): Promise<void>;
}

// A live shell/exec channel (§4 RemoteTerminal).
export interface RemoteTerminal {
  readonly id: string;
  sendData(data: string | Uint8Array): void;
  sendSize(cols: number, rows: number): void;
  close(): Promise<void>;
}

export interface SshClient {
  connect(options: SshOptions): Promise<void>;
  exec(options: ExecOptions): Promise<RemoteTerminal>;
  interactiveExec(options: ExecOptions): Promise<RemoteTerminal>;
  shell(options: ShellOptions): Promise<RemoteTerminal>;
  sftp(options?: SftpOptions): Promise<Sftp>;
  localPortForwarding(options: PortForwardingOptions): Promise<PortForwarding>;
  remotePortForwarding(options: PortForwardingOptions): Promise<PortForwarding>;
  dynamicPortForwarding(options: PortForwardingOptions): Promise<PortForwarding>;
  getClientSshMethods(type: SshMethodType): string[];
  getServerSshMethods(type: SshMethodType): string[];
  getAgreedSshMethod(type: SshMethodType): string | null;
  close(reason?: string): Promise<void>;
}

// ---- FileSystem / SFTP (§4 FileSystem, §11a) ----

export interface SftpOptions {
  cwd?: string;
}

export interface FileAttributes {
  size: number;
  mode: number;
  uid: number;
  gid: number;
  atime: number;
  mtime: number;
  isDirectory: boolean;
  isSymlink: boolean;
}

export interface DirEntry {
  filename: string;
  longname: string;
  attrs: FileAttributes;
}

export interface Sftp {
  listDir(path: string): Promise<DirEntry[]>;
  stat(path: string): Promise<FileAttributes>;
  lstat(path: string): Promise<FileAttributes>;
  makeDir(path: string, mode?: number): Promise<void>;
  removeDir(path: string): Promise<void>;
  removeFile(path: string): Promise<void>;
  rename(from: string, to: string): Promise<void>;
  chmod(path: string, mode: number): Promise<void>;
  symlink(target: string, path: string): Promise<void>;
  readLink(path: string): Promise<string>;
  realPath(path: string): Promise<string>;
  getReader(path: string): NodeJS.ReadableStream;
  getWriter(path: string, mode?: number): NodeJS.WritableStream;
  close(): Promise<void>;
}

// ---- Keygen (§4 Keygen, §10b) ----

export type SshKeyType = "rsa" | "dsa" | "ecdsa" | "ed25519" | "mldsa";

export interface KeygenOptions {
  type: SshKeyType;
  bits?: number; // rsa/dsa
  curve?: "nistp256" | "nistp384" | "nistp521"; // ecdsa
  comment?: string;
  passphrase?: string;
}

export interface SshKeyPair {
  privateKeyOpenSsh: string;
  publicKeyOpenSsh: string;
  fingerprintSha256: string;
  type: SshKeyType;
}

export interface Keygen {
  generateSshKey(options: KeygenOptions): Promise<SshKeyPair>;
  generatePublicKeyFromPrivateKey(privateKey: string, passphrase?: string): Promise<string>;
  generateSshKeyFromPuttyKey(ppk: string, passphrase?: string): Promise<SshKeyPair>;
  getKeyTypeFromPrivateKey(privateKey: string): Promise<SshKeyType>;
  checkPrivateKeyEncrypted(privateKey: string): Promise<boolean>;
  checkPrivateKeyEncryptedWithPassword(privateKey: string, password: string): Promise<boolean>;
  validatePublicKeyFormat(publicKey: string): Promise<boolean>;
  validatePrivateKeyFormat(privateKey: string): Promise<boolean>;
}

// ---- SSH agent (§4 SshAgentStorage, §11b) ----

export interface AgentKey {
  publicKeyOpenSsh: string;
  comment: string;
}

export interface SshAgentStorage {
  addKey(privateKey: string, comment: string, passphrase?: string): Promise<void>;
  removeKey(publicKeyOpenSsh: string): Promise<void>;
  getKeys(): Promise<AgentKey[]>;
}

// ---- Vault crypto (§4 Crypto / CryptoModule, §9) ----
// Ciphertext layout: version_byte(1) || payload. v4 engine = libsodium-style AEAD + Argon2id KDF.

export interface VaultCrypto {
  createPasswordHash(password: string, salt: Uint8Array): Promise<Uint8Array>;
  generateEncryptionKey(): Promise<Uint8Array>;
  encrypt(plaintext: Uint8Array): Promise<Uint8Array>;
  decrypt(ciphertext: Uint8Array): Promise<Uint8Array>;
  getVersionFromCiphertext(ciphertext: Uint8Array): number;
}
