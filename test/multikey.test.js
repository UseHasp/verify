/**
 * Multi-key envelopes (a rotation occurred inside the export
 * window) + the caller_attribution/user_agent extension slots (15/16), end
 * to end through the real verifyExport pipeline. Fixtures built by
 * test/fixtures/build-multikey.js — a synthetic, deterministic export signed
 * by two throwaway Ed25519 test keys, exercising exactly what the platform's
 * AuditExportEnvelopeBuilder now emits when key_version count > 1.
 */
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { checkChain } from "../src/checks/chain.js";
import { checkPublishedKey } from "../src/checks/published-key.js";
import { checkSchema } from "../src/checks/schema.js";
import { checkSignatures } from "../src/checks/signature.js";
import { verifyExport } from "../src/verify.js";

const here = dirname(fileURLToPath(import.meta.url));
const load = (name) => JSON.parse(readFileSync(resolve(here, "fixtures", name), "utf8"));
const KEYS = resolve(here, "fixtures", "published-keys-multikey.json");

describe("multi-key envelope — end-to-end verifyExport", () => {
  it("verifies green: schema, chain (incl. extension slots), published-key (both), signatures (per entry)", async () => {
    const data = load("valid-multikey.json");
    const r = await verifyExport(data, { skipTsa: true, keysFile: KEYS });

    expect(r.checks.schema.ok).toBe(true);
    expect(r.checks.chain.ok).toBe(true);
    expect(r.checks.publishedKey.ok).toBe(true);
    expect(r.checks.publishedKey.key_ids).toEqual(
      expect.arrayContaining(["01mkfixture000000000000key1", "01mkfixture000000000000key2"]),
    );
    expect(r.checks.signatures.ok).toBe(true);
    expect(r.checks.tsa.skipped).toBe(true);
    expect(r.ok).toBe(true);
  });

  it("schema check requires verification.keys to have at least 2 entries when present", () => {
    const data = load("valid-multikey.json");
    const broken = {
      ...data,
      verification: { ...data.verification, keys: [data.verification.keys[0]] },
    };
    const r = checkSchema(broken);
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/verification\.keys must be an array of at least 2/);
  });

  it("schema check requires every entry to carry key_id when the export is multi-key", () => {
    const data = load("valid-multikey.json");
    const broken = JSON.parse(JSON.stringify(data));
    delete broken.entries[0].key_id;
    const r = checkSchema(broken);
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/key_id is required/);
  });

  it("recomputes the caller_attribution/user_agent-carrying entry's digest byte-for-byte", () => {
    const data = load("valid-multikey.json");
    const r = checkChain(data);
    expect(r.ok).toBe(true);
    expect(r.count).toBe(3);
  });
});

describe("multi-key envelope — tampered attribution fails closed", () => {
  it("fails the chain check when caller_attribution is tampered (delegated agent swapped)", async () => {
    const data = load("tampered-attribution.json");
    const r = await verifyExport(data, { skipTsa: true, keysFile: KEYS });
    expect(r.checks.chain.ok).toBe(false);
    expect(r.checks.chain.error).toMatch(/chain broken/);
    expect(r.ok).toBe(false);
  });
});

describe("multi-key envelope — wrong per-entry key fails closed", () => {
  it("fails the signature check when an entry's key_id points at a key that did not sign it", async () => {
    const data = load("wrong-entry-key.json");
    const r = await verifyExport(data, { skipTsa: true, keysFile: KEYS });
    // Schema + chain + published-key all pass (the hash itself is untouched
    // and both keys are legitimately published) — only the per-entry
    // signature verification catches the substitution.
    expect(r.checks.schema.ok).toBe(true);
    expect(r.checks.chain.ok).toBe(true);
    expect(r.checks.publishedKey.ok).toBe(true);
    expect(r.checks.signatures.ok).toBe(false);
    expect(r.checks.signatures.error).toMatch(/signature invalid/);
    expect(r.ok).toBe(false);
  });

  it("checkSignatures fails closed when an entry references a key_id absent from the trusted map", () => {
    const data = load("valid-multikey.json");
    const broken = JSON.parse(JSON.stringify(data));
    broken.entries[0].key_id = "01mkfixture-does-not-exist";
    const r = checkSignatures(broken, {
      publicKeys: { "01mkfixture000000000000key1": {}, "01mkfixture000000000000key2": {} },
    });
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/not among this export's trusted keys/);
  });
});

describe("multi-key published-key resolution", () => {
  it("resolves and matches every key against the published document", async () => {
    const data = load("valid-multikey.json");
    const r = await checkPublishedKey(data, { keysFile: KEYS });
    expect(r.ok).toBe(true);
    expect(Object.keys(r.publicKeys).sort()).toEqual(
      ["01mkfixture000000000000key1", "01mkfixture000000000000key2"].sort(),
    );
  });

  it("fails closed when one of the embedded keys does not match the published document", async () => {
    const data = load("valid-multikey.json");
    const tampered = JSON.parse(JSON.stringify(data));
    // Swap in a PEM that is well-formed Ed25519 but not the published key B.
    tampered.verification.keys[1].public_key_pem = data.verification.keys[0].public_key_pem;
    const r = await checkPublishedKey(tampered, { keysFile: KEYS });
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/does not match the published key/);
  });
});
