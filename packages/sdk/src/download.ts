import { createHash } from "node:crypto";
import { chmod, mkdir, mkdtemp, readFile, rename, rm, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { isAbsolute, join } from "node:path";
import { gunzipSync, inflateRawSync } from "node:zlib";
import { SendScoreError } from "./error.js";
import { HASHES } from "./hashes.js";

export const RELEASES = "https://github.com/sendscore/sendscore/releases/download";

const MAX_DOWNLOAD = 100 * 1024 * 1024;
const DOWNLOAD_TIMEOUT_MS = 120_000;

const OS: Record<string, string> = { linux: "linux", darwin: "darwin", win32: "windows" };
const ARCH: Record<string, string> = { x64: "amd64", arm64: "arm64" };

export interface Platform {
  os: string;
  arch: string;
}

/** The SHA-256 of a release archive and of the binary inside it. */
export interface Pin {
  archive: string;
  binary: string;
}

export function currentPlatform(): Platform {
  const os = OS[process.platform];
  const arch = ARCH[process.arch];
  if (!os || !arch) {
    throw new SendScoreError(`no SendScore build for ${process.platform} on ${process.arch}`, 0);
  }
  return { os, arch };
}

export function cacheRoot(): string {
  if (process.platform === "darwin") return join(homedir(), "Library", "Caches");
  if (process.platform === "win32") return process.env["LOCALAPPDATA"] || join(homedir(), "AppData", "Local");
  const xdg = process.env["XDG_CACHE_HOME"];
  return xdg && isAbsolute(xdg) ? xdg : join(homedir(), ".cache");
}

/** The pin for a platform. With none, nothing may be downloaded or trusted from the cache. */
export function pinFor(p: Platform, pins: Record<string, Pin> = HASHES): Pin {
  const pin = pins[`${p.os}_${p.arch}`];
  if (!pin) {
    throw new SendScoreError(
      `this package has no pinned hash for ${p.os}_${p.arch}, so it will not download a CLI. Install the matching sendscore on PATH, or set SENDSCORE_BIN.`,
      0,
    );
  }
  return pin;
}

function sha256(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

/** Whether a file exists and is exactly the pinned binary. */
export async function matchesPin(path: string, pin: Pin): Promise<boolean> {
  try {
    return sha256(await readFile(path)) === pin.binary;
  } catch {
    return false;
  }
}

/** The name of the release archive for a version and platform. */
export function archiveName(version: string, p: Platform): string {
  return `sendscore_${version}_${p.os}_${p.arch}.${p.os === "windows" ? "zip" : "tar.gz"}`;
}

async function fetchBytes(url: string): Promise<Buffer> {
  try {
    const res = await fetch(url, { redirect: "follow", signal: AbortSignal.timeout(DOWNLOAD_TIMEOUT_MS) });
    if (!res.ok || !res.body) throw new SendScoreError(`download of ${url} answered ${res.status}`, 0);
    const parts: Uint8Array[] = [];
    let size = 0;
    for await (const part of res.body as unknown as AsyncIterable<Uint8Array>) {
      size += part.length;
      if (size > MAX_DOWNLOAD) throw new SendScoreError(`download of ${url} is too large`, 0);
      parts.push(part);
    }
    return Buffer.concat(parts);
  } catch (e) {
    if (e instanceof SendScoreError) throw e;
    throw new SendScoreError(`download of ${url} failed: ${(e as Error).message}`, 0);
  }
}

/** Reads one file, by its exact name, from a tar archive. Nothing else is touched. */
export function fromTar(tar: Buffer, name: string): Buffer | undefined {
  for (let at = 0; at + 512 <= tar.length; ) {
    const header = tar.subarray(at, at + 512);
    if (header.every((b) => b === 0)) return undefined;
    const end = header.indexOf(0);
    const entry = header.subarray(0, end < 0 || end > 100 ? 100 : end).toString();
    const size = parseInt(header.subarray(124, 136).toString().replace(/\0.*$/, "").trim() || "0", 8);
    const type = header[156];
    at += 512;
    if (entry === name && (type === 0 || type === 48)) return tar.subarray(at, at + size);
    at += Math.ceil(size / 512) * 512;
  }
  return undefined;
}

/** Reads one file, by its exact name, from a zip archive. Nothing else is touched. */
export function fromZip(zip: Buffer, name: string): Buffer | undefined {
  let end = zip.length - 22;
  while (end >= 0 && zip.readUInt32LE(end) !== 0x06054b50) end--;
  if (end < 0) return undefined;
  const count = zip.readUInt16LE(end + 10);
  let at = zip.readUInt32LE(end + 16);
  for (let i = 0; i < count; i++) {
    const method = zip.readUInt16LE(at + 10);
    const packed = zip.readUInt32LE(at + 20);
    const nameLen = zip.readUInt16LE(at + 28);
    const extraLen = zip.readUInt16LE(at + 30);
    const commentLen = zip.readUInt16LE(at + 32);
    const local = zip.readUInt32LE(at + 42);
    if (zip.subarray(at + 46, at + 46 + nameLen).toString() === name) {
      const start = local + 30 + zip.readUInt16LE(local + 26) + zip.readUInt16LE(local + 28);
      const data = zip.subarray(start, start + packed);
      return method === 0 ? data : inflateRawSync(data);
    }
    at += 46 + nameLen + extraLen + commentLen;
  }
  return undefined;
}

/**
 * Downloads a release into dir, and returns the binary's path. The archive
 * must match its pin before anything is extracted, and the binary must match
 * its pin before it reaches the disk.
 */
export async function download(version: string, base: string, dir: string, pin: Pin, p: Platform = currentPlatform()): Promise<string> {
  const binName = p.os === "windows" ? "sendscore.exe" : "sendscore";
  const target = join(dir, binName);
  const name = archiveName(version, p);
  const archive = await fetchBytes(`${base}/${name}`);
  if (sha256(archive) !== pin.archive) {
    throw new SendScoreError(`${name} does not match its pinned hash`, 0);
  }
  const binary = p.os === "windows" ? fromZip(archive, binName) : fromTar(gunzipSync(archive), binName);
  if (!binary) throw new SendScoreError(`${name} has no ${binName}`, 0);
  if (sha256(binary) !== pin.binary) {
    throw new SendScoreError(`the binary in ${name} does not match its pinned hash`, 0);
  }
  try {
    await mkdir(dir, { recursive: true, mode: 0o700 });
    const temp = await mkdtemp(join(dir, ".download-"));
    try {
      const path = join(temp, binName);
      await writeFile(path, binary, { mode: 0o755 });
      await chmod(path, 0o755);
      await rename(path, target);
    } finally {
      await rm(temp, { recursive: true, force: true });
    }
  } catch (e) {
    throw new SendScoreError(`could not write to ${dir}: ${(e as Error).message}`, 0);
  }
  return target;
}
