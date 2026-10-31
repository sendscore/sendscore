import { spawn } from "node:child_process";
import { access, constants } from "node:fs/promises";
import { delimiter, join } from "node:path";
import { RELEASES, cacheRoot, download } from "./download.js";
import { SendScoreError } from "./error.js";
import type { CheckOptions, DiffResult, Verdict } from "./types.js";

export * from "./types.js";
export { SendScoreError } from "./error.js";

/** The CLI release this package downloads when none is installed. */
export const ENGINE_VERSION = "0.2.0";

const exe = process.platform === "win32" ? "sendscore.exe" : "sendscore";

async function executable(path: string): Promise<boolean> {
  try {
    await access(path, constants.X_OK);
    return true;
  } catch {
    return false;
  }
}

/** Finds the CLI: SENDSCORE_BIN, then PATH, then the cache, then a download. */
export async function binary(): Promise<string> {
  const fromEnv = process.env["SENDSCORE_BIN"];
  if (fromEnv) return fromEnv;
  for (const dir of (process.env["PATH"] ?? "").split(delimiter)) {
    if (dir && (await executable(join(dir, exe)))) return join(dir, exe);
  }
  const dir = join(cacheRoot(), "sendscore", ENGINE_VERSION);
  if (await executable(join(dir, exe))) return join(dir, exe);
  return download(ENGINE_VERSION, `${RELEASES}/v${ENGINE_VERSION}`, dir);
}

interface Result {
  code: number;
  stdout: string;
  stderr: string;
}

function run(bin: string, args: string[], stdin?: Uint8Array): Promise<Result> {
  return new Promise((resolve, reject) => {
    const child = spawn(bin, args, { stdio: [stdin ? "pipe" : "ignore", "pipe", "pipe"] });
    const out: Buffer[] = [];
    const err: Buffer[] = [];
    child.stdout!.on("data", (b: Buffer) => out.push(b));
    child.stderr!.on("data", (b: Buffer) => err.push(b));
    child.on("error", (e) => reject(new SendScoreError(`could not run ${bin}: ${e.message}`, 0)));
    child.on("close", (code) =>
      resolve({ code: code ?? -1, stdout: Buffer.concat(out).toString(), stderr: Buffer.concat(err).toString() }),
    );
    if (stdin) {
      child.stdin!.on("error", () => {});
      child.stdin!.end(stdin);
    }
  });
}

function parse<T>(r: Result, verdictCodes: number[]): T {
  if (!verdictCodes.includes(r.code)) {
    throw new SendScoreError(r.stderr.trim() || `sendscore exited ${r.code}`, r.code);
  }
  try {
    return JSON.parse(r.stdout) as T;
  } catch {
    throw new SendScoreError("sendscore printed something that is not JSON", r.code);
  }
}

/**
 * Checks one message, given as a path or as its bytes. A message that fails
 * checks is still a report: this throws only when no report could be made.
 */
export async function check(message: string | Uint8Array, options: CheckOptions = {}): Promise<Verdict> {
  const args = ["check", "--json"];
  if (options.offline) args.push("--offline");
  if (options.links) args.push("--links");
  if (options.ip !== undefined) args.push("--ip", options.ip);
  if (options.mailFrom !== undefined) args.push("--mail-from", options.mailFrom);
  if (options.helo !== undefined) args.push("--helo", options.helo);
  if (options.tls !== undefined) args.push("--tls", options.tls ? "yes" : "no");
  if (options.previous !== undefined) args.push("--previous", options.previous);
  const stdin = typeof message === "string" ? undefined : message;
  args.push("--", typeof message === "string" ? message : "-");
  return parse<Verdict>(await run(await binary(), args, stdin), [0, 1, 2]);
}

/** Compares two saved messages, given as paths. */
export async function diff(before: string, after: string): Promise<DiffResult> {
  const result = parse<DiffResult>(await run(await binary(), ["diff", "--json", "--", before, after]), [0, 1]);
  return { ...result, changes: result.changes ?? [] };
}
