/**
 * The genTime backdating check (verify.js's findBackdatedAnchor,
 * exercised through the full verifyExport pipeline).
 *
 * Backdating is pure date arithmetic — comparing a token's parsed genTime
 * against its bound entry's created_at — not a cryptographic property, so
 * unlike test/forged-tsa.test.js (which needs a genuinely forged TSA chain
 * to test trust), this suite drives it with test/fixtures/fake-openssl.mjs:
 * a stub that always reports a successful `ts -verify` and lets the test
 * control the reported genTime via the FAKE_GEN_TIME env var. That isolates
 * the comparison logic from TSA signature verification, which is already
 * covered by tsa.test.js and forged-tsa.test.js.
 *
 * Fixture: valid-v2.json's head anchor only (dropping its interior anchor,
 * whose own placeholder TSR the real anchoring math doesn't touch, avoids
 * two anchors sharing one fake genTime and produces a single, unambiguous
 * bound entry to reason about).
 */
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import { verifyExport } from "../src/verify.js";

const here = dirname(fileURLToPath(import.meta.url));
const FAKE_OPENSSL = resolve(here, "fixtures", "fake-openssl.mjs");
const KEYS_V2 = resolve(here, "fixtures", "published-keys-v2.json");

function headOnlyFixture() {
  const validV2 = JSON.parse(readFileSync(resolve(here, "fixtures", "valid-v2.json"), "utf8"));
  validV2.verification.tsa_anchor_chain = [validV2.verification.tsa_anchor_chain[1]];
  return validV2;
}

// The bound entry (seq 4) has created_at "2026-07-20T00:00:03+00:00".
const BOUND_ENTRY_CREATED_AT = "2026-07-20T00:00:03+00:00";

afterEach(() => {
  delete process.env.FAKE_GEN_TIME;
});

describe("genTime backdating check", () => {
  it("FAILS when genTime predates the bound entry's created_at beyond the skew allowance", async () => {
    process.env.FAKE_GEN_TIME = "Jan  1 00:00:00 2000 GMT"; // wildly before the entry
    const r = await verifyExport(headOnlyFixture(), {
      keysFile: KEYS_V2,
      opensslPath: FAKE_OPENSSL,
    });
    expect(r.ok).toBe(false);
    expect(r.checks.anchoring.ok).toBe(true); // binding itself is untouched
    expect(r.checks.tsa.ok).toBe(false);
    expect(r.checks.tsa.error).toMatch(/backdated timestamp/);
    expect(r.checks.tsa.error).toMatch(/seq=4/);
    expect(r.checks.tsa.error).toMatch(new RegExp(BOUND_ENTRY_CREATED_AT.replace(/[+.]/g, "\\$&")));
  });

  it("PASSES when genTime is at (or after) the bound entry's created_at", async () => {
    process.env.FAKE_GEN_TIME = "Jul 20 00:00:03 2026 GMT"; // exactly the entry's created_at
    const r = await verifyExport(headOnlyFixture(), {
      keysFile: KEYS_V2,
      opensslPath: FAKE_OPENSSL,
    });
    expect(r.ok).toBe(true);
    expect(r.checks.tsa.ok).toBe(true);
  });

  it("PASSES within the small clock-skew allowance (a few seconds early)", async () => {
    process.env.FAKE_GEN_TIME = "Jul 20 00:00:00 2026 GMT"; // 3s before, well under the skew
    const r = await verifyExport(headOnlyFixture(), {
      keysFile: KEYS_V2,
      opensslPath: FAKE_OPENSSL,
    });
    expect(r.ok).toBe(true);
  });

  it("genTime is surfaced on a passing result even when not backdated", async () => {
    process.env.FAKE_GEN_TIME = "Aug  2 12:00:00 2026 GMT";
    const r = await verifyExport(headOnlyFixture(), {
      keysFile: KEYS_V2,
      opensslPath: FAKE_OPENSSL,
    });
    expect(r.ok).toBe(true);
    expect(r.checks.tsa.anchors[0].genTime).toBe("2026-08-02T12:00:00.000Z");
  });
});
