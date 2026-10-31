import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import { after, before, test } from "node:test";
import { fileURLToPath } from "node:url";
import { ENGINE_VERSION, KILLED, SendScoreError, binary, check, diff } from "../dist/index.js";

const repo = fileURLToPath(new URL("../../../", import.meta.url));
const windows = process.platform === "win32";
const exe = windows ? "sendscore.exe" : "sendscore";
const sample = join(repo, "conformance/messages/clean.eml");
const saved = { bin: process.env.SENDSCORE_BIN, path: process.env.PATH, xdg: process.env.XDG_CACHE_HOME, home: process.env.HOME };
let tmp, built;

function fake(mode) {
  const dir = join(tmp, mode);
  mkdirSync(dir, { recursive: true });
  copyFileSync(built, join(dir, exe));
  return join(dir, exe);
}

before(() => {
  tmp = mkdtempSync(join(tmpdir(), "sendscore-cli-"));
  built = join(tmp, "built", exe);
  execFileSync("go", ["build", "-o", built, "./conformance/fakecli"], { cwd: repo });
});

after(() => {
  for (const [key, value] of [["SENDSCORE_BIN", saved.bin], ["PATH", saved.path], ["XDG_CACHE_HOME", saved.xdg], ["HOME", saved.home]]) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
  rmSync(tmp, { recursive: true, force: true });
});

function using(path) {
  process.env.SENDSCORE_BIN = path;
}

function onlyPath(path) {
  delete process.env.SENDSCORE_BIN;
  process.env.PATH = path;
  process.env.XDG_CACHE_HOME = join(tmp, "cache");
  process.env.HOME = join(tmp, "home");
}

test("a timeout kills the CLI", async () => {
  using(fake("hang"));
  const started = Date.now();
  await assert.rejects(check(sample, { timeout: 200 }), (e) => e instanceof SendScoreError && e.exitCode === KILLED);
  await assert.rejects(diff(sample, sample, { timeout: 200 }), (e) => e instanceof SendScoreError && e.exitCode === KILLED);
  assert.ok(Date.now() - started < 20_000);
});

test("a killed CLI has one exit code", { skip: windows }, async () => {
  using(fake("killed"));
  await assert.rejects(check(sample), (e) => e instanceof SendScoreError && e.exitCode === KILLED);
});

test("output that is not a verdict is refused", async () => {
  using(fake("planted"));
  await assert.rejects(check(sample), SendScoreError);
  await assert.rejects(diff(sample, sample), SendScoreError);
});

test("unknown fields, statuses, and stderr noise are tolerated", async () => {
  using(fake("noisy"));
  const got = await check(sample);
  assert.equal(got.verdict, "pass");
  assert.equal(got.checks[0].status, "brand_new");
});

test("a CLI of the wrong version on PATH is not run", async () => {
  onlyPath(join(tmp, "version-9.9.9"));
  fake("version-9.9.9");
  await assert.rejects(binary(), /no pinned hash/);
});

test("the pinned version on PATH is used", async () => {
  const path = fake(`version-${ENGINE_VERSION}`);
  onlyPath(join(tmp, `version-${ENGINE_VERSION}`));
  assert.equal(await binary(), path);
});

test("a relative PATH entry is skipped", async () => {
  const dir = `version-${ENGINE_VERSION}`;
  mkdirSync(dir, { recursive: true });
  copyFileSync(fake(dir), join(dir, exe));
  try {
    onlyPath(["", dir].join(delimiter));
    await assert.rejects(binary(), /no pinned hash/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a directory named sendscore on PATH does not stop the search", async () => {
  const path = fake(`version-${ENGINE_VERSION}`);
  mkdirSync(join(tmp, "dir", exe), { recursive: true });
  onlyPath([join(tmp, "dir"), join(tmp, `version-${ENGINE_VERSION}`)].join(delimiter));
  assert.equal(await binary(), path);
});

test("paths that look like flags or standard input are files", async () => {
  using(saved.bin ?? join(repo, "bin", exe));
  for (const name of ["-", "-dash.eml"]) {
    copyFileSync(sample, name);
    try {
      const got = await check(name, { offline: true });
      assert.equal(got.message.subject.length > 0, true);
    } finally {
      rmSync(name);
    }
  }
  assert.ok(readFileSync(sample).length > 0);
});
