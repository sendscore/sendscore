import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, readdirSync, statSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, test } from "node:test";
import { fileURLToPath } from "node:url";
import { SendScoreError } from "../dist/error.js";
import { download } from "../dist/download.js";

const fixtures = fileURLToPath(new URL("../../../conformance/release/", import.meta.url));
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

for (const p of platforms) {
  test(`installs the ${p.os} binary and nothing else`, async () => {
    const dir = mkdtempSync(join(tmpdir(), "sendscore-"));
    const path = await download("0.0.0-test", `${base}/good`, join(dir, "cache"), p);
    assert.match(readFileSync(path, "utf8"), /fake sendscore/);
    if (process.platform !== "win32") assert.ok(statSync(path).mode & 0o100);
    assert.deepEqual(readdirSync(join(dir, "cache")), [path.split("/").pop()]);
    assert.ok(!existsSync(join(dir, "evil")));
  });
}

test("refuses an archive that does not match checksums.txt", async () => {
  const dir = mkdtempSync(join(tmpdir(), "sendscore-"));
  await assert.rejects(download("0.0.0-test", `${base}/tampered`, join(dir, "cache"), platforms[0]), SendScoreError);
  assert.ok(!existsSync(join(dir, "cache")));
});

test("fails on a missing release", async () => {
  const dir = mkdtempSync(join(tmpdir(), "sendscore-"));
  await assert.rejects(download("0.0.0-test", `${base}/nothing`, join(dir, "cache"), platforms[0]), SendScoreError);
});
