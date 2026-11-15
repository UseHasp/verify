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
    expect(r.checks.keyRevocation).toEqual({
      ran: true,
      ok: true,
      notices: [],
      unchecked_keys: [],
    });
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
    expect(r).toEqual({ ok: true, notices: [], unchecked_keys: [] });
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

/**
 * The status that governs an entry must be the status of the key its
 * signature was verified under. Revocation exists for one case — the signing
 * key leaked — and in that case the attacker writes the export. If the check
 * trusts a label inside that export to decide which key's status to look up,
 * the holder of a revoked key simply labels their forgeries with some other
 * key_id and revocation never applies.
 */
describe("revocation cannot be dodged by relabelling entries", () => {
  it("FAILS a single-key export signed under a revoked key even when every entry names a different key_id", async () => {
    process.env.FAKE_GEN_TIME = "Jul 30 00:00:00 2026 GMT"; // after REVOKED_AT
    const forged = headOnlyFixture();
    for (const entry of forged.entries) {
      entry.key_id = "01v2fixture00000000000key99"; // not the revoked key
    }

    const r = await verifyExport(forged, { keysFile: KEYS_REVOKED, opensslPath: FAKE_OPENSSL });

    // The signatures are genuine (made with the revoked key), so every
    // earlier check passes; revocation is the only thing standing.
    expect(r.checks.signatures.ok).toBe(true);
    expect(r.checks.keyRevocation.ok).toBe(false);
    expect(r.checks.keyRevocation.error).toMatch(/revoked at/);
    expect(r.ok).toBe(false);
  });

  it("uses verification.key_id, not the entry's own key_id, in a single-key export (unit)", () => {
    const r = checkKeyRevocation(
      { entries: [{ seq: 1, key_id: "decoy" }], verification: { key_id: "key-a" } },
      {
        keyStatuses: { "key-a": { status: "revoked", revoked_at: "2026-07-25T00:00:00Z" } },
        bindings: [],
        tsaAnchors: [],
      },
    );
    expect(r.ok).toBe(false);
  });

  it("fails closed when an entry's key has no published status at all", () => {
    const r = checkKeyRevocation(
      { entries: [{ seq: 1, key_id: "key-z" }], verification: { keys: [{}, {}] } },
      { keyStatuses: { "key-a": { status: "active" } }, bindings: [], tsaAnchors: [] },
    );
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/status is unknown/);
  });

  it("does not treat an inherited object property as a published key", () => {
    const r = checkKeyRevocation(
      { entries: [{ seq: 1, key_id: "constructor" }], verification: { keys: [{}, {}] } },
      { keyStatuses: {}, bindings: [], tsaAnchors: [] },
    );
    expect(r.ok).toBe(false);
  });
});

describe("a key published as revoked without a usable revoked_at", () => {
  // Revoked means "do not trust this key". Without a time there is no
  // moment before which its signatures were good, so none of them pass —
  // treating the missing time as "not revoked" would turn a malformed
  // revocation into no revocation.
  it.each([
    ["missing", undefined],
    ["null", null],
    ["unparseable", "not-a-date"],
  ])("FAILS when revoked_at is %s", (_label, revokedAt) => {
    const r = checkKeyRevocation(
      { entries: [{ seq: 1 }], verification: { key_id: "key-a" } },
      {
        keyStatuses: { "key-a": { status: "revoked", revoked_at: revokedAt } },
        bindings: [{ index: 0, algo: "sha256-fold-v2", bound_seq: 1 }],
        tsaAnchors: [{ genTime: "2026-07-20T00:00:00.000Z" }],
      },
    );
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/without a valid revoked_at/);
  });
});

describe("a trust root that carries no revocation status", () => {
  // A bare PEM, or a keys document saved before statuses were published,
  // says which key to trust and nothing about whether it was later revoked.
  // The signatures are still genuine, so this is not a failure — but a
  // verifier that stays silent lets "verified" be read as "and not revoked".
  it("names the key whose revocation could not be checked", () => {
    const r = checkKeyRevocation(
      { entries: [{ seq: 1 }, { seq: 2 }], verification: { key_id: "key-a" } },
      {
        keyStatuses: { "key-a": { status: undefined, revoked_at: null } },
        bindings: [],
        tsaAnchors: [],
      },
    );
    expect(r).toEqual({ ok: true, notices: [], unchecked_keys: ["key-a"] });
  });

  it("is reported through the full pipeline when the trust root is a bare PEM", async () => {
    const data = headOnlyFixture();
    const r = await verifyExport(data, {
      expectedKey: data.verification.public_key_pem,
      opensslPath: FAKE_OPENSSL,
    });
    expect(r.ok).toBe(true);
    expect(r.checks.keyRevocation.unchecked_keys).toEqual([data.verification.key_id]);
  });

  it("is empty when the keys document publishes a status", async () => {
    const r = await verifyExport(headOnlyFixture(), {
      keysFile: KEYS_ACTIVE,
      opensslPath: FAKE_OPENSSL,
    });
    expect(r.checks.keyRevocation.unchecked_keys).toEqual([]);
  });
});
