/**
 * Negative tests for checkChain: prev_hash mismatch (incl. non-null first
 * entry), hash mismatch, chain head mismatch.
 */
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { checkChain } from "../src/checks/chain.js";

const here = dirname(fileURLToPath(import.meta.url));
const VALID = JSON.parse(readFileSync(resolve(here, "fixtures", "valid.json"), "utf8"));
const clone = () => JSON.parse(JSON.stringify(VALID));

describe("checkChain", () => {
  it("passes on valid fixture", () => {
    const r = checkChain(VALID);
    expect(r.ok).toBe(true);
    expect(r.count).toBe(VALID.entries.length);
  });

  it("first entry's prev_hash is null", () => {
    expect(VALID.entries[0].prev_hash).toBeNull();
  });

  it("fails when the first entry's prev_hash is not null", () => {
    const d = clone();
    d.entries[0].prev_hash = "0".repeat(64);
    const r = checkChain(d);
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/prev_hash mismatch/);
    expect(r.error).toMatch(/expected null/);
  });

  it("fails when a later entry.prev_hash is wrong", () => {
    const d = clone();
    d.entries[1].prev_hash = "0".repeat(64);
    const r = checkChain(d);
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/prev_hash mismatch/);
  });

  it("fails when entry payload is mutated (hash no longer matches)", () => {
    const d = clone();
    d.entries[0].action = "tampered";
    const r = checkChain(d);
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/chain broken/);
  });

  it("fails when a nested metadata value is mutated (canonicalization is load-bearing)", () => {
    const d = clone();
    d.entries[0].metadata.phi_scan.redaction_count = 99;
    const r = checkChain(d);
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/chain broken/);
  });

  it("fails when chain_head_hash is wrong", () => {
    const d = clone();
    d.verification.chain_head_hash = "f".repeat(64);
    const r = checkChain(d);
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/chain head mismatch/);
  });
});

/**
 * ADR-PEQ4XT presence-conditional asserted-actor binding: an entry carrying
 * `asserted_actor_hmac` hashes over a 13-element canonical array; entries
 * without it keep the original 12-element form byte-identically. Stripping or
 * grafting the field must break the chain check.
 */
import { createHash } from "node:crypto";
import { canonicalizeForHash } from "../src/canonical.js";

// Mirrors checkChain's full cascade (base 12 + asserted_actor_hmac[13] +
// customer_id[14] + caller_attribution[15] + user_agent[16]) — not
// just the asserted slot — because the real sample fixture this file mutates
// may already carry a later slot (e.g. every sealed row's user_agent), and
// the injectivity rule forces every earlier absent slot to an explicit null
// whenever a later one is present.
const recomputeHash = (entry) => {
  const fields = [
    entry.user_id,
    entry.org_id,
    entry.project_id ?? null,
    entry.action,
    entry.entity_type,
    entry.entity_id,
    canonicalizeForHash(entry.metadata),
    entry.ip_address,
    entry.created_at,
    entry.phi_disposition ?? null,
    entry.subject_type ?? null,
    entry.subject_id_hmac ?? null,
  ];
  const asserted = entry.asserted_actor_hmac ?? null;
  const customer = entry.customer_id ?? null;
  const callerAttribution = entry.caller_attribution ?? null;
  const userAgent = entry.user_agent ?? null;
  const callerAttributionPresent = callerAttribution !== null;
  const userAgentPresent = userAgent !== null;
  if (asserted !== null || customer !== null || callerAttributionPresent || userAgentPresent) {
    fields.push(asserted);
  }
  if (customer !== null || callerAttributionPresent || userAgentPresent) {
    fields.push(customer);
  }
  if (callerAttributionPresent || userAgentPresent) {
    fields.push(canonicalizeForHash(callerAttribution));
  }
  if (userAgentPresent) {
    fields.push(userAgent);
  }
  return createHash("sha256").update(JSON.stringify(fields)).digest("hex");
};

const withAssertedLastEntry = () => {
  const d = JSON.parse(JSON.stringify(VALID));
  const last = d.entries[d.entries.length - 1];
  last.asserted_actor_hmac = "a".repeat(64);
  last.hash = recomputeHash(last);
  d.verification.chain_head_hash = last.hash;
  return d;
};

describe("checkChain asserted_actor_hmac (ADR-PEQ4XT)", () => {
  it("verifies an entry whose digest includes the presence-conditional 13th element", () => {
    const d = withAssertedLastEntry();
    const r = checkChain(d);
    expect(r.ok).toBe(true);
  });

  it("fails when the asserted_actor_hmac is stripped from an entry that carried one", () => {
    const d = withAssertedLastEntry();
    delete d.entries[d.entries.length - 1].asserted_actor_hmac;
    const r = checkChain(d);
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/chain broken/);
  });

  it("fails when an asserted_actor_hmac is grafted onto an entry that had none", () => {
    const d = JSON.parse(JSON.stringify(VALID));
    d.entries[0].asserted_actor_hmac = "b".repeat(64);
    const r = checkChain(d);
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/chain broken/);
  });

  it("fails when the asserted value itself is tampered", () => {
    const d = withAssertedLastEntry();
    d.entries[d.entries.length - 1].asserted_actor_hmac = "c".repeat(64);
    const r = checkChain(d);
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/chain broken/);
  });
});
