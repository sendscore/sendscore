#!/usr/bin/env node
// The sendscore command: finds the CLI the same way the library does, then
// runs it with this process's arguments, streams, and exit code.
import { spawn } from "node:child_process";
import { constants } from "node:os";
import { binary } from "./index.js";

// EX_SOFTWARE, as the CLI uses for an internal error.
const INTERNAL = 70;

// The PATH search may find this launcher and run it to read its version. The
// mark makes that run fail at once, so the search moves on instead of looping.
const MARK = "SENDSCORE_LAUNCHED";

function fail(message: string): never {
  process.stderr.write(`sendscore: ${message}\n`);
  process.exit(INTERNAL);
}

if (process.env[MARK]) fail("found itself instead of the CLI");
process.env[MARK] = "1";

let path: string;
try {
  path = await binary();
} catch (e) {
  fail((e as Error).message);
}

const child = spawn(path, process.argv.slice(2), { stdio: "inherit", shell: false, windowsHide: false });
for (const signal of ["SIGINT", "SIGTERM", "SIGHUP"] as const) {
  process.on(signal, () => child.kill(signal));
}
child.on("error", (e) => fail(`could not run ${path}: ${e.message}`));
child.on("exit", (code, signal) => {
  // A shell reports a process killed by a signal as 128 plus its number.
  process.exit(code ?? 128 + (signal ? constants.signals[signal] : 0));
});
