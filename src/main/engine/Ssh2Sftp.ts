import type { SFTPWrapper, Stats } from "ssh2";
import type { DirEntry, FileAttributes, Sftp } from "./types.js";

function toAttrs(s: Stats): FileAttributes {
  return {
    size: s.size,
    mode: s.mode,
    uid: s.uid,
    gid: s.gid,
    atime: s.atime,
    mtime: s.mtime,
    isDirectory: s.isDirectory(),
    isSymlink: s.isSymbolicLink(),
  };
}

// §11a: each operation maps to a libssh2 sftp primitive, exposed here via ssh2's SFTPWrapper.
export class Ssh2Sftp implements Sftp {
  constructor(private readonly sftp: SFTPWrapper) {}

  listDir(path: string): Promise<DirEntry[]> {
    return new Promise((resolve, reject) => {
      this.sftp.readdir(path, (err, list) => {
        if (err) return reject(err);
        resolve(
          list.map((e) => ({ filename: e.filename, longname: e.longname, attrs: toAttrs(e.attrs) })),
        );
      });
    });
  }
  stat(path: string): Promise<FileAttributes> {
    return new Promise((resolve, reject) =>
      this.sftp.stat(path, (err, s) => (err ? reject(err) : resolve(toAttrs(s)))),
    );
  }
  lstat(path: string): Promise<FileAttributes> {
    return new Promise((resolve, reject) =>
      this.sftp.lstat(path, (err, s) => (err ? reject(err) : resolve(toAttrs(s)))),
    );
  }
  makeDir(path: string, mode?: number): Promise<void> {
    return new Promise((resolve, reject) =>
      this.sftp.mkdir(path, { mode }, (err) => (err ? reject(err) : resolve())),
    );
  }
  removeDir(path: string): Promise<void> {
    return new Promise((resolve, reject) =>
      this.sftp.rmdir(path, (err) => (err ? reject(err) : resolve())),
    );
  }
  removeFile(path: string): Promise<void> {
    return new Promise((resolve, reject) =>
      this.sftp.unlink(path, (err) => (err ? reject(err) : resolve())),
    );
  }
  rename(from: string, to: string): Promise<void> {
    return new Promise((resolve, reject) =>
      this.sftp.rename(from, to, (err) => (err ? reject(err) : resolve())),
    );
  }
  chmod(path: string, mode: number): Promise<void> {
    return new Promise((resolve, reject) =>
      this.sftp.chmod(path, mode, (err) => (err ? reject(err) : resolve())),
    );
  }
  symlink(target: string, path: string): Promise<void> {
    return new Promise((resolve, reject) =>
      this.sftp.symlink(target, path, (err) => (err ? reject(err) : resolve())),
    );
  }
  readLink(path: string): Promise<string> {
    return new Promise((resolve, reject) =>
      this.sftp.readlink(path, (err, t) => (err ? reject(err) : resolve(t))),
    );
  }
  realPath(path: string): Promise<string> {
    return new Promise((resolve, reject) =>
      this.sftp.realpath(path, (err, t) => (err ? reject(err) : resolve(t))),
    );
  }
  getReader(path: string): NodeJS.ReadableStream {
    return this.sftp.createReadStream(path);
  }
  getWriter(path: string, mode?: number): NodeJS.WritableStream {
    return this.sftp.createWriteStream(path, { mode });
  }
  close(): Promise<void> {
    return new Promise((resolve) => {
      this.sftp.end();
      resolve();
    });
  }
}
