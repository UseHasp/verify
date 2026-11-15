/**
 * A timestamp token proves its entries existed BY the token's time. It says
 * nothing about when they were actually written. An entry dated in March and
 * first anchored in November verifies exactly like one anchored the day it
 * was written — and that is the shape a rewritten history has: signed with a
 * valid key, dated in the past, anchored whenever the rewrite happened.
 *
 * The verifier cannot prove which it is looking at, so it reports the lag
 * instead of passing it silently, and lets a caller who knows the anchoring
 * cadence turn the report into a failure.
 *
 * Fixture: valid-v2.json, four entries created 2026-07-20T00:00:00..03Z, with
 * a fake openssl that reports whatever genTime the test asks for.
 */
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import { verifyExport } from "../src/verify.js";

const here = dirname(fileURLToPath(import.meta.url));
const FAKE_OPENSSL = resolve(here, "fixtures", "fake-openssl.mjs");
const KEYS = resolve(here, "fixtures", "published-keys-v2.json");

function headOnlyFixture() {
  const data = JSON.parse(readFileSync(resolve(here, "fixtures", "valid-v2.json"), "utf8"));
  data.verification.tsa_anchor_chain = [data.verification.tsa_anchor_chain[1]];
  return data;
}

const verify = (opts = {}) =>
  verifyExport(headOnlyFixture(), { keysFile: KEYS, opensslPath: FAKE_OPENSSL, ...opts });

afterEach(() => {
  delete process.env.FAKE_GEN_TIME;
});

describe("late anchoring", () => {
  it("is not reported when entries were anchored within the normal cadence", async () => {
    process.env.FAKE_GEN_TIME = "Jul 20 12:00:00 2026 GMT"; // 12 hours later
    const r = await verify();
    expect(r.ok).toBe(true);
    expect(r.late_anchoring).toBeNull();
  });

  it("is reported, without failing, when the only anchor is months after the entries", async () => {
    process.env.FAKE_GEN_TIME = "Nov 14 00:00:00 2026 GMT";
    const r = await verify();
    expect(r.ok).toBe(true);
    expect(r.late_anchoring).toMatchObject({ threshold_hours: 48, entries: 4, first_seq: 1 });
    expect(r.late_anchoring.max_lag_hours).toBeGreaterThan(24 * 100);
  });

  it("fails when the caller sets a limit and the lag exceeds it", async () => {
    process.env.FAKE_GEN_TIME = "Jul 23 00:00:00 2026 GMT"; // 72 hours later
    const r = await verify({ maxAnchorLagHours: 24 });
    expect(r.ok).toBe(false);
    expect(r.checks.tsa.ok).toBe(false);
    expect(r.checks.tsa.error).toMatch(/exceeds the allowed anchor lag/);
  });

  it("passes under a limit the lag stays inside", async () => {
    process.env.FAKE_GEN_TIME = "Jul 23 00:00:00 2026 GMT";
    const r = await verify({ maxAnchorLagHours: 96 });
    expect(r.ok).toBe(true);
    expect(r.late_anchoring).toBeNull();
  });

  it("is not evaluated when the TSA check is skipped — there is no token time to compare", async () => {
    const r = await verify({ skipTsa: true });
    expect(r.late_anchoring).toBeNull();
  });

  it("fails closed when a limit is set but the TSA check is skipped", async () => {
    const r = await verify({ skipTsa: true, maxAnchorLagHours: 24 });
    expect(r.ok).toBe(false);
    expect(r.checks.tsa.error).toMatch(/cannot be enforced/);
  });
});
