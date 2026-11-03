/**
 * Signing-key revocation (verify.js's checkKeyRevocation,
 * exercised through the full verifyExport pipeline).
 *
 * Mirrors test/backdating.test.js's approach: revocation-vs-anchor timing is
 * pure date arithmetic once the published-key status is resolved, so this
 * suite drives it with test/fixtures/fake-openssl.mjs (always reports a
 * successful `ts -verify`, lets the test control the reported `genTime` via
 * FAKE_GEN_TIME) plus a `--keys-file` fixture whose key is published as
 * `revoked`. The signature cryptography itself is unaffected by revocation
 * (a revoked key's signature is still mathematically valid) and is already
 * covered by signature.test.js / published-key.test.js.
 */
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import { checkKeyRevocation } from "../src/checks/key-revocation.js";
import { verifyExport } from "../src/verify.js";

const here = dirname(fileURLToPath(import.meta.url));
const FAKE_OPENSSL = resolve(here, "fixtures", "fake-openssl.mjs");
const KEYS_ACTIVE = resolve(here, "fixtures", "published-keys-v2.json");
const KEYS_REVOKED = resolve(here, "fixtures", "published-keys-v2-revoked.json");
// published-keys-v2-revoked.json's key is revoked at 2026-07-25T00:00:00+00:00.

function headOnlyFixture() {
  const validV2 = JSON.parse(readFileSync(resolve(here, "fixtures", "valid-v2.json"), "utf8"));
  validV2.verification.tsa_anchor_chain = [validV2.verification.tsa_anchor_chain[1]];
  return validV2;
}

afterEach(() => {
  delete process.env.FAKE_GEN_TIME;
});

describe("signing-key revocation — full pipeline (valid-v2.json fixture, key revoked at 2026-07-25)", () => {
  it("PASSES with a signed_under_later_revoked_key notice when the covering anchor's genTime precedes revoked_at", async () => {
    process.env.FAKE_GEN_TIME = "Jul 20 00:00:04 2026 GMT"; // before REVOKED_AT
    const r = await verifyExport(headOnlyFixture(), {
      keysFile: KEYS_REVOKED,
      opensslPath: FAKE_OPENSSL,
    });

    expect(r.ok).toBe(true);
    expect(r.checks.keyRevocation.ran).toBe(true);
    expect(r.checks.keyRevocation.ok).toBe(true);
    expect(r.checks.keyRevocation.notices).toEqual(
      expect.arrayContaining([expect.objectContaining({ type: "signed_under_later_revoked_key" })]),
    );
  });

  it("FAILS when the covering anchor's genTime does not precede revoked_at", async () => {
    process.env.FAKE_GEN_TIME = "Jul 30 00:00:00 2026 GMT"; // after REVOKED_AT
    const r = await verifyExport(headOnlyFixture(), {
      keysFile: KEYS_REVOKED,
      opensslPath: FAKE_OPENSSL,
    });

    expect(r.ok).toBe(false);
    expect(r.checks.keyRevocation.ran).toBe(true);
    expect(r.checks.keyRevocation.ok).toBe(false);
    expect(r.checks.keyRevocation.error).toMatch(/revoked at/);
    expect(r.checks.keyRevocation.error).toMatch(/does not precede the revocation/);
  });

  it("FAILS closed with --skip-tsa (no genTime available to prove pre-dating)", async () => {
    const r = await verifyExport(headOnlyFixture(), {
      keysFile: KEYS_REVOKED,
      opensslPath: FAKE_OPENSSL,
      skipTsa: true,
    });

    expect(r.ok).toBe(false);
    expect(r.checks.tsa.ran).toBe(false);
    expect(r.checks.keyRevocation.ok).toBe(false);
    expect(r.checks.keyRevocation.error).toMatch(/no TSA anchor covers it/);
  });

  it("does not run the revocation check's fail path for a key published as active (regression)", async () => {
    process.env.FAKE_GEN_TIME = "Jul 20 00:00:04 2026 GMT";
    const r = await verifyExport(headOnlyFixture(), {
      keysFile: KEYS_ACTIVE,
      opensslPath: FAKE_OPENSSL,
    });

    expect(r.ok).toBe(true);
    expect(r.checks.keyRevocation).toEqual({ ran: true, ok: true, notices: [] });
  });
});

describe("checkKeyRevocation (unit)", () => {
  const entries = [
    { seq: 1, key_id: "key-a" },
    { seq: 2, key_id: "key-b" },
  ];
  const bindings = [{ index: 0, algo: "sha256-fold-v2", bound_seq: 2 }];
  const tsaAnchors = [{ genTime: "2026-07-20T00:00:00.000Z" }];

  it("passes non-revoked entries straight through with no notice", () => {
    const r = checkKeyRevocation(
      { entries, verification: {} },
      {
        keyStatuses: { "key-a": { status: "active" }, "key-b": { status: "retired" } },
        bindings,
        tsaAnchors,
      },
    );
    expect(r).toEqual({ ok: true, notices: [] });
  });

  it("fails an entry whose key has no covering anchor at all", () => {
    const r = checkKeyRevocation(
      { entries: [{ seq: 5, key_id: "key-a" }], verification: {} },
      {
        keyStatuses: { "key-a": { status: "revoked", revoked_at: "2026-07-25T00:00:00Z" } },
        bindings, // bound_seq: 2 — does not cover seq 5
        tsaAnchors,
      },
    );
    expect(r.ok).toBe(false);
  });

  it("picks the EARLIEST covering anchor when several cover the same entry", () => {
    const multiBindings = [
      { index: 0, algo: "sha256-fold-v2", bound_seq: 2 },
      { index: 1, algo: "sha256-fold-v2", bound_seq: 2 },
    ];
    const multiAnchors = [
      { genTime: "2026-07-28T00:00:00.000Z" }, // AFTER revocation
      { genTime: "2026-07-20T00:00:00.000Z" }, // BEFORE revocation — should win
    ];
    const r = checkKeyRevocation(
      { entries: [{ seq: 2, key_id: "key-a" }], verification: {} },
      {
        keyStatuses: { "key-a": { status: "revoked", revoked_at: "2026-07-25T00:00:00Z" } },
        bindings: multiBindings,
        tsaAnchors: multiAnchors,
      },
    );
    expect(r.ok).toBe(true);
    expect(r.notices[0].anchor_gen_time).toBe("2026-07-20T00:00:00.000Z");
  });

  it("a row-hash-v1 anchor only covers its own exact seq, not later entries", () => {
    const r = checkKeyRevocation(
      { entries: [{ seq: 3, key_id: "key-a" }], verification: {} },
      {
        keyStatuses: { "key-a": { status: "revoked", revoked_at: "2026-07-25T00:00:00Z" } },
        bindings: [{ index: 0, algo: "row-hash-v1", bound_seq: 2 }], // attests seq 2 only
        tsaAnchors: [{ genTime: "2026-07-20T00:00:00.000Z" }],
      },
    );
    expect(r.ok).toBe(false);
  });
});
