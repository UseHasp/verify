import { generateKeyPairSync } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { canonicalizeForHash } from "../src/canonical.js";
import { VERSION, verifyExport } from "../src/verify.js";

const here = dirname(fileURLToPath(import.meta.url));
const load = (name) => JSON.parse(readFileSync(resolve(here, "fixtures", name), "utf8"));
// Offline trust root for the published-key check: the co-published keys doc for
// the throwaway sample tenant (no live /trust/keys endpoint exists for it).
const KEYS = resolve(here, "fixtures", "published-keys.json");

describe("VERSION", () => {
  it("matches package.json version (single source of truth)", () => {
    const pkg = JSON.parse(readFileSync(resolve(here, "..", "package.json"), "utf8"));
    expect(VERSION).toBe(pkg.version);
  });
});

describe("canonicalizeForHash", () => {
  it("sorts object keys at every depth", () => {
    expect(JSON.stringify(canonicalizeForHash({ b: 1, a: { z: 1, y: 2 } }))).toBe(
      '{"a":{"y":2,"z":1},"b":1}',
    );
  });
  it("keeps array order and recurses into elements", () => {
    expect(JSON.stringify(canonicalizeForHash([3, { b: 1, a: 2 }, 1]))).toBe('[3,{"a":2,"b":1},1]');
  });
  it("leaves scalars and null unchanged", () => {
    expect(canonicalizeForHash(null)).toBe(null);
    expect(canonicalizeForHash("x")).toBe("x");
    expect(canonicalizeForHash(42)).toBe(42);
  });
  it("keeps an empty array as []", () => {
    expect(JSON.stringify(canonicalizeForHash([]))).toBe("[]");
  });
  it("does not pollute Object.prototype via __proto__ key", () => {
    const malicious = JSON.parse('{"__proto__":{"polluted":true},"a":1}');
    const out = canonicalizeForHash(malicious);
    // The __proto__ key survives as an own property (JSON.stringify emits it),
    // matching PHP ksort + json_encode — but Object.prototype is untouched.
    expect(JSON.stringify(out)).toContain('"a":1');
    // @ts-expect-error — probing for prototype pollution
    expect({}.polluted).toBeUndefined();
    expect(Object.hasOwn(Object.prototype, "polluted")).toBe(false);
  });
});

describe("verifyExport (offline checks)", () => {
  it("passes schema, chain, published-key, signatures on the real-crypto sample with --skip-tsa", async () => {
    const data = load("valid.json");
    const r = await verifyExport(data, { skipTsa: true, keysFile: KEYS });
    expect(r.checks.schema.ok).toBe(true);
    expect(r.checks.chain.ok).toBe(true);
    expect(r.checks.publishedKey.ok).toBe(true);
    expect(r.checks.signatures.ok).toBe(true);
    expect(r.checks.tsa.skipped).toBe(true);
    expect(r.ok).toBe(true);
  });

  it("fails when the embedded key does not match the published key (forged export)", async () => {
    const data = load("valid.json");
    // A genuine but DIFFERENT Ed25519 public key as the trust root.
    const wrongKey = generateKeyPairSync("ed25519")
      .publicKey.export({ type: "spki", format: "pem" })
      .toString();
    const r = await verifyExport(data, { skipTsa: true, expectedKey: wrongKey });
    expect(r.ok).toBe(false);
    expect(r.checks.chain.ok).toBe(true);
    expect(r.checks.publishedKey.ok).toBe(false);
    expect(r.checks.publishedKey.error).toMatch(/does not match the published key/);
    // Signatures never run once the trust root is rejected.
    expect(r.checks.signatures.ran).toBe(false);
  });

  it("fails on broken-schema", async () => {
    const r = await verifyExport(load("broken-schema.json"), { skipTsa: true });
    expect(r.ok).toBe(false);
    expect(r.checks.schema.ok).toBe(false);
    expect(r.checks.schema.error).toMatch(/schema_version/);
  });

  it("fails on broken-chain", async () => {
    const r = await verifyExport(load("broken-chain.json"), { skipTsa: true });
    expect(r.ok).toBe(false);
    expect(r.checks.chain.ok).toBe(false);
    expect(r.checks.chain.error).toMatch(/chain (broken|head)|prev_hash/i);
  });

  it("fails on broken-signature (sig mutation doesn't break the chain)", async () => {
    const r = await verifyExport(load("broken-signature.json"), { skipTsa: true, keysFile: KEYS });
    expect(r.ok).toBe(false);
    // Signature mutation does not break the hash chain (the chain hashes the
    // canonical columns, not the signature), so chain and published-key pass
    // and signatures fails.
    expect(r.checks.chain.ok).toBe(true);
    expect(r.checks.publishedKey.ok).toBe(true);
    expect(r.checks.signatures.ok).toBe(false);
    expect(r.checks.signatures.error).toMatch(/signature/);
  });

  it("propagates TSA failure when skipTsa is false", async () => {
    // The default TSA path trusts the bundled FreeTSA root and never touches
    // the network — allowUntrustedTsa forces the (now opt-in) fetch path so
    // this test can exercise a failing fetch and assert it propagates.
    const r = await verifyExport(load("valid.json"), {
      keysFile: KEYS,
      allowUntrustedTsa: true,
      fetcher: async () => ({
        ok: false,
        status: 500,
        arrayBuffer: async () => new ArrayBuffer(0),
      }),
    });
    expect(r.ok).toBe(false);
    expect(r.checks.publishedKey.ok).toBe(true);
    expect(r.checks.tsa.ran).toBe(true);
    expect(r.checks.tsa.ok).toBe(false);
  });

  it("verifies fully offline by default — no fetcher call reaches the TSA path", async () => {
    // With a real committed sample, no --ca-file, and no --allow-untrusted-tsa,
    // the TSA check must trust the bundled FreeTSA root and never call fetch.
    const r = await verifyExport(load("valid.json"), {
      keysFile: KEYS,
      fetcher: async () => {
        throw new Error("default TSA path must not touch the network");
      },
    });
    expect(r.ok).toBe(true);
    expect(r.checks.tsa.ok).toBe(true);
    expect(r.checks.tsa.anchors[0].genTime).toBeTypeOf("string");
  });
});

// Offline trust root for the anchor-v2 fixture family's throwaway tenant
// (test/fixtures/build-v2.js). The real-crypto valid.json sample also carries
// a sha256-fold-v2 anchor, but only the happy path; these synthetic fixtures
// exercise the failure modes (insider rewrite, unbindable anchor, empty
// chain, range-bounded) that a genuine minted sample cannot. Run with
// skipTsa: true throughout — the anchoring check is pure computation and runs
// regardless of that flag; TSA fields in these fixtures are placeholder base64.
const KEYS_V2 = resolve(here, "fixtures", "published-keys-v2.json");

describe("verifyExport — anchor-v2 pipeline integration", () => {
  it("passes end-to-end on valid-v2 (two v2 anchors, full coverage)", async () => {
    const r = await verifyExport(load("valid-v2.json"), { skipTsa: true, keysFile: KEYS_V2 });
    expect(r.ok).toBe(true);
    expect(r.checks.anchoring.ok).toBe(true);
    expect(r.checks.anchoring.coverage.attested_through_seq).toBe(4);
  });

  it("insider-rewrite: chain + signatures pass, anchoring fails — the gap v2 anchoring closes", async () => {
    const r = await verifyExport(load("insider-rewrite.json"), {
      skipTsa: true,
      keysFile: KEYS_V2,
    });
    // The three outcomes that prove the insider-rewrite gap is closed: a
    // rewritten-and-re-signed interior entry still satisfies the row hash
    // chain and per-entry signatures (an attacker with signing-key access
    // could produce this), but the anchored history fold no longer matches.
    expect(r.checks.chain.ok).toBe(true);
    expect(r.checks.signatures.ok).toBe(true);
    expect(r.checks.anchoring.ok).toBe(false);
    expect(r.checks.anchoring.error).toMatch(/fold mismatch/);
    expect(r.ok).toBe(false);
    // TSA never runs — anchoring failed first, short-circuiting the pipeline.
    expect(r.checks.tsa.ran).toBe(false);
  });

  it("no-anchors fails closed without --allow-unanchored, passes-with-warning with it", async () => {
    const withoutFlag = await verifyExport(load("no-anchors.json"), {
      skipTsa: true,
      keysFile: KEYS_V2,
    });
    expect(withoutFlag.ok).toBe(false);
    expect(withoutFlag.checks.anchoring.error).toMatch(/not time-attested/);

    const withFlag = await verifyExport(load("no-anchors.json"), {
      skipTsa: true,
      keysFile: KEYS_V2,
      allowUnanchored: true,
    });
    expect(withFlag.ok).toBe(true);
    expect(withFlag.checks.anchoring.attested).toBe("none");
  });

  it("unbindable-anchor fails anchoring (anchored_entry_id not among exported entries)", async () => {
    const r = await verifyExport(load("unbindable-anchor.json"), {
      skipTsa: true,
      keysFile: KEYS_V2,
    });
    expect(r.ok).toBe(false);
    expect(r.checks.chain.ok).toBe(true);
    expect(r.checks.signatures.ok).toBe(true);
    expect(r.checks.anchoring.ok).toBe(false);
  });

  it("range-bounded-v2 fails anchoring (v2 anchor requires a genesis-rooted export)", async () => {
    const r = await verifyExport(load("range-bounded-v2.json"), {
      skipTsa: true,
      keysFile: KEYS_V2,
    });
    expect(r.ok).toBe(false);
    expect(r.checks.anchoring.error).toMatch(/not genesis-rooted/);
  });

  it("purge-rebased-v2 passes end-to-end: a pre-purge anchor binds via fold_base after a retention purge", async () => {
    const r = await verifyExport(load("purge-rebased-v2.json"), {
      skipTsa: true,
      keysFile: KEYS_V2,
    });
    expect(r.ok).toBe(true);
    // Chain check passes because the retained chain is re-rooted (first
    // entry's prev_hash is null); anchoring binds the pre-purge head anchor
    // by folding the retained entries from verification.fold_base.
    expect(r.checks.chain.ok).toBe(true);
    expect(r.checks.signatures.ok).toBe(true);
    expect(r.checks.anchoring.ok).toBe(true);
    expect(r.checks.anchoring.coverage.attested_through_seq).toBe(2);
    expect(r.checks.anchoring.coverage.total_entries).toBe(2);
    // A rebased-but-not-reset export carries no lineage_reset_at.
    expect(r.lineage_reset_at).toBeNull();
  });

  it("lineage-reset-v2 verifies green but surfaces lineage_reset_at (repaired export is not pristine)", async () => {
    const r = await verifyExport(load("lineage-reset-v2.json"), {
      skipTsa: true,
      keysFile: KEYS_V2,
    });
    // The retained rows are fully valid.
    expect(r.ok).toBe(true);
    expect(r.checks.chain.ok).toBe(true);
    expect(r.checks.anchoring.ok).toBe(true);
    // But the reset is surfaced as a first-class notice — a consumer can never
    // mistake this for an untouched full history.
    expect(r.lineage_reset_at).toBe("2026-07-19T12:00:00+00:00");
  });

  it("a normal export reports lineage_reset_at as null", async () => {
    const r = await verifyExport(load("valid-v2.json"), { skipTsa: true, keysFile: KEYS_V2 });
    expect(r.ok).toBe(true);
    expect(r.lineage_reset_at).toBeNull();
  });
});
