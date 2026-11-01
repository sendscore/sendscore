import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

// SENDSCORE_PACKAGE tests an installed copy instead of this checkout.
const { SendScoreError, check, diff } = await import(process.env.SENDSCORE_PACKAGE ?? "../dist/index.js");

const root = fileURLToPath(new URL("../../../conformance/", import.meta.url));
const { cases } = JSON.parse(readFileSync(`${root}cases.json`, "utf8"));
const p = (rel) => root + rel;

function options(c) {
  const o = { offline: true };
  const given = c.options ?? {};
  if (given.links !== undefined) o.links = given.links;
  if (given.ip !== undefined) o.ip = given.ip;
  if (given.mail_from !== undefined) o.mailFrom = given.mail_from;
  if (given.helo !== undefined) o.helo = given.helo;
  if (given.tls !== undefined) o.tls = given.tls;
  if (given.previous !== undefined) o.previous = p(given.previous);
  return o;
}

function run(c) {
  if (c.command === "diff") return diff(p(c.before), p(c.after));
  return check(c.via === "stdin" ? readFileSync(p(c.message)) : p(c.message), options(c));
}

for (const c of cases) {
  test(c.name, async () => {
    if (c.exit > 2) {
      await assert.rejects(run(c), (e) => e instanceof SendScoreError && e.exitCode === c.exit);
      return;
    }
    const got = await run(c);
    assert.deepEqual((got.changes ?? []).map((x) => x.field), c.changes ?? []);
    assert.deepEqual((got.changes ?? []).filter((x) => x.worsened).map((x) => x.worsened), c.worsened ?? []);
    if (c.command === "diff") return;
    assert.equal(got.verdict, c.verdict);
    assert.equal(got.ready_to_send, c.ready_to_send);
    assert.deepEqual(Object.fromEntries(got.checks.map((x) => [x.id, x.status])), c.checks);
  });
}
