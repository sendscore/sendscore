import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import { after, before, test } from "node:test";
import { fileURLToPath } from "node:url";
import { SendScoreError } from "../dist/error.js";
import { download, matchesPin, pinFor } from "../dist/download.js";

const fixtures = fileURLToPath(new URL("../../../conformance/release/", import.meta.url));
const pins = JSON.parse(readFileSync(join(fixtures, "pins.json"), "utf8"));
let server, base;

before(async () => {
  server = createServer((req, res) => {
    const path = join(fixtures, req.url);
    if (!path.startsWith(fixtures) || !existsSync(path)) return res.writeHead(404).end();
    res.end(readFileSync(path));
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  base = `http://127.0.0.1:${server.address().port}`;
});
after(() => server.close());

const platforms = [
  { os: "linux", arch: "amd64" },
  { os: "darwin", arch: "arm64" },
  { os: "windows", arch: "amd64" },
];
const pin = (p) => pins[`${p.os}_${p.arch}`];

for (const p of platforms) {
  test(`installs the ${p.os} binary and nothing else`, async () => {
    const dir = mkdtempSync(join(tmpdir(), "sendscore-"));
    const path = await download("0.0.0-test", `${base}/good`, join(dir, "cache"), pin(p), p);
    assert.match(readFileSync(path, "utf8"), /fake sendscore/);
    if (process.platform !== "win32") assert.ok(statSync(path).mode & 0o100);
    assert.deepEqual(readdirSync(join(dir, "cache")), [basename(path)]);
    assert.ok(!existsSync(join(dir, "evil")));
  });
}

test("refuses an archive that does not match its pin, whatever checksums.txt says", async () => {
  const dir = mkdtempSync(join(tmpdir(), "sendscore-"));
  await assert.rejects(download("0.0.0-test", `${base}/altered`, join(dir, "cache"), pin(platforms[0]), platforms[0]), SendScoreError);
  assert.ok(!existsSync(join(dir, "cache")));
});

test("refuses a binary that does not match its pin", async () => {
  const dir = mkdtempSync(join(tmpdir(), "sendscore-"));
  const wrong = { ...pin(platforms[0]), binary: "0".repeat(64) };
  await assert.rejects(download("0.0.0-test", `${base}/good`, join(dir, "cache"), wrong, platforms[0]), SendScoreError);
  assert.ok(!existsSync(join(dir, "cache")));
});

test("fails on a missing release", async () => {
  const dir = mkdtempSync(join(tmpdir(), "sendscore-"));
  await assert.rejects(download("0.0.0-test", `${base}/nothing`, join(dir, "cache"), pin(platforms[0]), platforms[0]), SendScoreError);
});

test("a cached binary is trusted only while it matches its pin", async () => {
  const dir = mkdtempSync(join(tmpdir(), "sendscore-"));
  const path = await download("0.0.0-test", `${base}/good`, join(dir, "cache"), pin(platforms[0]), platforms[0]);
  assert.ok(await matchesPin(path, pin(platforms[0])));
  writeFileSync(path, "planted");
  assert.ok(!(await matchesPin(path, pin(platforms[0]))));
});

test("no pin means no download, not an unverified one", () => {
  assert.throws(() => pinFor(platforms[0], {}), SendScoreError);
});
