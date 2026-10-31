import { spawn } from "node:child_process";
import { access, constants, stat } from "node:fs/promises";
import { delimiter, isAbsolute, join } from "node:path";
import { RELEASES, cacheRoot, currentPlatform, download, matchesPin, pinFor } from "./download.js";
import { KILLED, SendScoreError } from "./error.js";
import type { CheckOptions, DiffOptions, DiffResult, Verdict } from "./types.js";

export * from "./types.js";
export { KILLED, SendScoreError } from "./error.js";

/** The CLI release this package downloads when none is installed. */
export const ENGINE_VERSION = "0.2.0";

const exe = process.platform === "win32" ? "sendscore.exe" : "sendscore";
const VERSION_TIMEOUT_MS = 10_000;

async function executable(path: string): Promise<boolean> {
  try {
    if (!(await stat(path)).isFile()) return false;
    await access(path, constants.X_OK);
    return true;
  } catch {
    return false;
  }
}

/** Whether a CLI reports the version this package was tested against. */
async function rightVersion(path: string): Promise<boolean> {
  try {
    const r = await run(path, ["--version"], undefined, VERSION_TIMEOUT_MS);
    const version = r.stdout.trim().split(/\s+/).pop() ?? "";
    return r.code === 0 && version.replace(/^v/, "") === ENGINE_VERSION;
  } catch {
    return false;
  }
}

/**
 * Finds the CLI: SENDSCORE_BIN, then the pinned version on PATH, then the
 * cache, then a download. A cached binary is checked against its pinned hash
 * every time, so a file planted in the cache is replaced and never run.
 */
export async function binary(): Promise<string> {
  const fromEnv = process.env["SENDSCORE_BIN"];
  if (fromEnv) return fromEnv;
  try {
    for (const dir of (process.env["PATH"] ?? "").split(delimiter)) {
      if (!isAbsolute(dir)) continue;
      const path = join(dir, exe);
      if ((await executable(path)) && (await rightVersion(path))) return path;
    }
    const platform = currentPlatform();
    const pin = pinFor(platform);
    const dir = join(cacheRoot(), "sendscore", ENGINE_VERSION);
    if (await matchesPin(join(dir, exe), pin)) return join(dir, exe);
    return await download(ENGINE_VERSION, `${RELEASES}/v${ENGINE_VERSION}`, dir, pin, platform);
  } catch (e) {
    if (e instanceof SendScoreError) throw e;
    throw new SendScoreError(`could not find or install the CLI: ${(e as Error).message}`, 0);
  }
}

interface Result {
  code: number;
  stdout: string;
  stderr: string;
}

function run(bin: string, args: string[], stdin?: Uint8Array, timeout?: number): Promise<Result> {
  return new Promise((resolve, reject) => {
    const child = spawn(bin, args, { stdio: [stdin ? "pipe" : "ignore", "pipe", "pipe"] });
    const out: Buffer[] = [];
    const err: Buffer[] = [];
    let timedOut = false;
    const timer =
      timeout === undefined
        ? undefined
        : setTimeout(() => {
            timedOut = true;
            child.kill("SIGKILL");
          }, timeout);
    child.stdout!.on("data", (b: Buffer) => out.push(b));
    child.stderr!.on("data", (b: Buffer) => err.push(b));
    child.on("error", (e) => {
      clearTimeout(timer);
      reject(new SendScoreError(`could not run ${bin}: ${e.message}`, 0));
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      if (timedOut) {
        reject(new SendScoreError(`sendscore did not finish within ${timeout} ms`, KILLED));
        return;
      }
      resolve({
        code: code === null || code < 0 || code >= 128 ? KILLED : code,
        stdout: Buffer.concat(out).toString(),
        stderr: Buffer.concat(err).toString(),
      });
    });
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

/** A lone `-` would mean standard input to the CLI, so a file of that name gets a path. */
function pathArg(path: string): string {
  return path === "-" ? "./-" : path;
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
  if (options.previous !== undefined) args.push("--previous", pathArg(options.previous));
  const stdin = typeof message === "string" ? undefined : message;
  args.push("--", typeof message === "string" ? pathArg(message) : "-");
  const verdict = parse<Verdict>(await run(await binary(), args, stdin, options.timeout), [0, 1, 2]);
  if (typeof verdict?.schema !== "string" || !verdict.schema.startsWith("sendscore.verdict/")) {
    throw new SendScoreError("sendscore printed something that is not a verdict", 0);
  }
  return verdict;
}

/** Compares two saved messages, given as paths. */
export async function diff(before: string, after: string, options: DiffOptions = {}): Promise<DiffResult> {
  const args = ["diff", "--json", "--", pathArg(before), pathArg(after)];
  const result = parse<DiffResult>(await run(await binary(), args, undefined, options.timeout), [0, 1]);
  if (result === null || typeof result !== "object" || !("changes" in result)) {
    throw new SendScoreError("sendscore printed something that is not a comparison", 0);
  }
  return { ...result, changes: result.changes ?? [] };
}
