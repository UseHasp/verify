/**
 * Unit tests for the canonicalization + integrity-hash core (src/canonical.js,
 * src/hash.js) — the single source of truth shared by the verifier and the
 * fixture generator.
 */
import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { canonicalize, encodeForHash } from "../src/canonical.js";
import { computeIntegrityHash, INTEGRITY_FIELDS, integrityArray } from "../src/hash.js";

describe("canonicalize", () => {
  it("recursively key-sorts objects at every depth", () => {
    expect(encodeForHash(canonicalize({ b: 1, a: { z: 1, y: 2 } }))).toBe(
      '{"a":{"y":2,"z":1},"b":1}',
    );
  });

  it("preserves array order (lists are not sorted)", () => {
    expect(encodeForHash(canonicalize([3, 1, 2]))).toBe("[3,1,2]");
    expect(encodeForHash(canonicalize({ k: ["c", "a", "b"] }))).toBe('{"k":["c","a","b"]}');
  });

  it("does not pollute Object.prototype via a __proto__ key", () => {
    const malicious = JSON.parse('{"__proto__":{"polluted":true},"a":1}');
    const out = encodeForHash(canonicalize(malicious));
    expect(out).toContain('"a":1');
    // @ts-expect-error — probing for prototype pollution
    expect({}.polluted).toBeUndefined();
    expect(Object.hasOwn(Object.prototype, "polluted")).toBe(false);
  });

  it("leaves primitives and null unchanged", () => {
    expect(canonicalize(null)).toBe(null);
    expect(canonicalize(42)).toBe(42);
    expect(canonicalize("x")).toBe("x");
  });
});

describe("integrityArray", () => {
  it("emits the integrity fields in the fixed contract order", () => {
    const entry = Object.fromEntries(INTEGRITY_FIELDS.map((f, i) => [f, i]));
    expect(integrityArray(entry)).toEqual(INTEGRITY_FIELDS.map((_, i) => i));
  });

  it("encodes a missing field as null", () => {
    const arr = integrityArray({ action: "x", created_at: "t" });
    expect(arr[INTEGRITY_FIELDS.indexOf("user_id")]).toBe(null);
    expect(arr[INTEGRITY_FIELDS.indexOf("action")]).toBe("x");
  });

  it("only canonicalizes the metadata element", () => {
    const arr = integrityArray({ metadata: { b: 1, a: 2 } });
    expect(arr[INTEGRITY_FIELDS.indexOf("metadata")]).toEqual({ a: 2, b: 1 });
  });

  it("encodes a present-but-undefined field as null", () => {
    const arr = integrityArray({ user_id: undefined, action: "a", created_at: "t" });
    expect(arr[INTEGRITY_FIELDS.indexOf("user_id")]).toBe(null);
  });
});

describe("computeIntegrityHash", () => {
  it("matches a hand-rolled sha256 over the canonical field array", () => {
    const entry = {
      user_id: 7,
      org_id: 1,
      project_id: null,
      action: "user.login",
      entity_type: "Session",
      entity_id: "s_1",
      metadata: { b: 2, a: 1 },
      ip_address: "203.0.113.1",
      created_at: "2026-01-01T00:00:00+00:00",
      phi_disposition: "none",
      subject_type: null,
      subject_id_hmac: null,
    };
    const expected = createHash("sha256")
      .update(
        '[7,1,null,"user.login","Session","s_1",{"a":1,"b":2},"203.0.113.1","2026-01-01T00:00:00+00:00","none",null,null]',
        "utf8",
      )
      .digest("hex");
    expect(computeIntegrityHash(entry)).toBe(expected);
  });

  it("is sensitive to metadata key VALUES but not key ORDER", () => {
    const base = { action: "a", created_at: "t", metadata: { x: 1, y: 2 } };
    const reordered = { action: "a", created_at: "t", metadata: { y: 2, x: 1 } };
    const changed = { action: "a", created_at: "t", metadata: { x: 1, y: 3 } };
    expect(computeIntegrityHash(base)).toBe(computeIntegrityHash(reordered));
    expect(computeIntegrityHash(base)).not.toBe(computeIntegrityHash(changed));
  });

  it("does not escape forward slashes (JSON_UNESCAPED_SLASHES)", () => {
    const h1 = computeIntegrityHash({ action: "a", created_at: "t", metadata: { u: "a/b" } });
    const h2 = computeIntegrityHash({ action: "a", created_at: "t", metadata: { u: "a\\/b" } });
    expect(h1).not.toBe(h2);
  });
});
