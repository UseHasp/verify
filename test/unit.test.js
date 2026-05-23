import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { canonicalSorted } from "../src/canonical.js";
import { verifyExport } from "../src/verify.js";

const here = dirname(fileURLToPath(import.meta.url));
const load = (name) => JSON.parse(readFileSync(resolve(here, "fixtures", name), "utf8"));

describe("canonicalSorted", () => {
  it("sorts object keys at every depth", () => {
    expect(canonicalSorted({ b: 1, a: { z: 1, y: 2 } })).toBe('{"a":{"y":2,"z":1},"b":1}');
  });
  it("keeps array order", () => {
    expect(canonicalSorted([3, 1, 2])).toBe("[3,1,2]");
  });
  it("does not pollute Object.prototype via __proto__ key", () => {
    const malicious = JSON.parse('{"__proto__":{"polluted":true},"a":1}');
    const out = canonicalSorted(malicious);
    // The serialized form should be deterministic; pollution check below is the real assertion.
    expect(out).toContain('"a":1');
    // @ts-expect-error — probing for prototype pollution
    expect({}.polluted).toBeUndefined();
    expect(Object.hasOwn(Object.prototype, "polluted")).toBe(false);
  });
});

describe("verifyExport (offline checks)", () => {
  it("passes schema, chain, signatures on the valid sample with --skip-tsa", async () => {
    const data = load("valid.json");
    const r = await verifyExport(data, { skipTsa: true });
    expect(r.checks.schema.ok).toBe(true);
    expect(r.checks.chain.ok).toBe(true);
    expect(r.checks.signatures.ok).toBe(true);
    expect(r.checks.tsa.skipped).toBe(true);
    expect(r.ok).toBe(true);
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

  it("fails on broken-signature (chain may also fail because mutating sig doesn't break chain, but byte flip in sig is what we want here)", async () => {
    const r = await verifyExport(load("broken-signature.json"), { skipTsa: true });
    expect(r.ok).toBe(false);
    // Signature mutation does not break the hash chain (chain hashes payload sans signature),
    // so chain passes and signatures fails.
    expect(r.checks.chain.ok).toBe(true);
    expect(r.checks.signatures.ok).toBe(false);
    expect(r.checks.signatures.error).toMatch(/signature/);
  });

  it("propagates TSA failure when skipTsa is false", async () => {
    const r = await verifyExport(load("valid.json"), {
      fetcher: async () => ({
        ok: false,
        status: 500,
        arrayBuffer: async () => new ArrayBuffer(0),
      }),
    });
    expect(r.ok).toBe(false);
    expect(r.checks.tsa.ran).toBe(true);
    expect(r.checks.tsa.ok).toBe(false);
  });
});
