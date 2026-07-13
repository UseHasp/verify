import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { canonicalEntryPayload, canonicalizeMetadata } from "../src/canonical.js";
import { VERSION, verifyExport } from "../src/verify.js";
import { loadFixture, offlineFetcher, offlineOpts, PUBLISHED_KEY_PEM } from "./helpers.js";

const here = dirname(fileURLToPath(import.meta.url));

describe("VERSION", () => {
  it("matches package.json version (single source of truth)", () => {
    const pkg = JSON.parse(readFileSync(resolve(here, "..", "package.json"), "utf8"));
    expect(VERSION).toBe(pkg.version);
  });
});

describe("canonicalizeMetadata", () => {
  it("sorts object keys at every depth", () => {
    const sorted = canonicalizeMetadata({ b: 1, a: { z: 1, y: 2 } });
    expect(JSON.stringify(sorted)).toBe('{"a":{"y":2,"z":1},"b":1}');
  });
  it("keeps array order but canonicalizes elements", () => {
    const sorted = canonicalizeMetadata([{ b: 1, a: 2 }, 3]);
    expect(JSON.stringify(sorted)).toBe('[{"a":2,"b":1},3]');
  });
  it("does not pollute Object.prototype via __proto__ key", () => {
    const malicious = JSON.parse('{"__proto__":{"polluted":true},"a":1}');
    const out = canonicalizeMetadata(malicious);
    expect(JSON.stringify(out)).toContain('"a":1');
    // @ts-expect-error — probing for prototype pollution
    expect({}.polluted).toBeUndefined();
    expect(Object.hasOwn(Object.prototype, "polluted")).toBe(false);
  });
});

describe("canonicalEntryPayload", () => {
  it("emits the fixed twelve-field array in order, metadata canonicalized", () => {
    const entry = {
      user_id: "u",
      org_id: "o",
      project_id: null,
      action: "a",
      entity_type: "t",
      entity_id: "e",
      metadata: { b: 1, a: 2 },
      ip_address: "1.2.3.4",
      created_at: "2026-01-01T00:00:00+00:00",
      phi_disposition: "not_present",
      subject_type: null,
      subject_id_hmac: null,
      // fields below are NOT part of the payload:
      prev_hash: null,
      hash: "x",
      signature: "ed25519:x",
    };
    expect(canonicalEntryPayload(entry)).toBe(
      '["u","o",null,"a","t","e",{"a":2,"b":1},"1.2.3.4","2026-01-01T00:00:00+00:00","not_present",null,null]',
    );
  });

  it("byte-parity with PHP JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE", () => {
    // Slashes stay unescaped and multibyte stays as UTF-8 (not \uXXXX) — exactly
    // what PHP json_encode emits with those flags. The payload string here is
    // the reference PHP output for the same input.
    const entry = {
      user_id: null,
      org_id: "o",
      project_id: null,
      action: "http.request",
      entity_type: null,
      entity_id: null,
      metadata: { url: "https://ex.com/a/b", name: "café/naïve é" },
      ip_address: null,
      created_at: "2026-01-01T00:00:00+00:00",
      phi_disposition: null,
      subject_type: null,
      subject_id_hmac: null,
    };
    const payload = canonicalEntryPayload(entry);
    // No backslash-escaped slashes anywhere.
    expect(payload).not.toContain("\\/");
    expect(payload).toContain("https://ex.com/a/b");
    // Multibyte characters are literal UTF-8, not \u escapes.
    expect(payload).toContain("café/naïve é");
    expect(payload).not.toMatch(/\\u00e9/);
    // Exact reference bytes.
    expect(payload).toBe(
      '[null,"o",null,"http.request",null,null,{"name":"café/naïve é","url":"https://ex.com/a/b"},null,"2026-01-01T00:00:00+00:00",null,null,null]',
    );
  });

  it("treats absent hashed fields as null", () => {
    const payload = canonicalEntryPayload({ org_id: "o", action: "a", created_at: "t" });
    expect(payload).toBe('[null,"o",null,"a",null,null,null,null,"t",null,null,null]');
  });
});

describe("verifyExport", () => {
  it("VERIFIED on the golden sample (offline key + local CA)", async () => {
    const r = await verifyExport(loadFixture("valid.json"), offlineOpts());
    expect(r.checks.schema.ok).toBe(true);
    expect(r.checks.chain.ok).toBe(true);
    expect(r.checks.publishedKey.ok).toBe(true);
    expect(r.checks.signatures.ok).toBe(true);
    expect(r.checks.tsa.ok).toBe(true);
    expect(r.ok).toBe(true);
  });

  it("VERIFIED over the network (mocked fetch for both key + CA)", async () => {
    const r = await verifyExport(loadFixture("valid.json"), { fetcher: offlineFetcher() });
    expect(r.ok).toBe(true);
    expect(r.checks.publishedKey.ok).toBe(true);
  });

  it("passes offline checks with --skip-tsa + key file", async () => {
    const r = await verifyExport(loadFixture("valid.json"), {
      skipTsa: true,
      expectedKey: PUBLISHED_KEY_PEM,
    });
    expect(r.checks.tsa.skipped).toBe(true);
    expect(r.ok).toBe(true);
  });

  it("fails on broken-hash (chain check)", async () => {
    const r = await verifyExport(loadFixture("broken-hash.json"), offlineOpts({ skipTsa: true }));
    expect(r.ok).toBe(false);
    expect(r.checks.chain.ok).toBe(false);
    expect(r.checks.chain.error).toMatch(/chain broken/);
  });

  it("fails on broken-chain (prev_hash linkage)", async () => {
    const r = await verifyExport(loadFixture("broken-chain.json"), offlineOpts({ skipTsa: true }));
    expect(r.ok).toBe(false);
    expect(r.checks.chain.ok).toBe(false);
    expect(r.checks.chain.error).toMatch(/prev_hash mismatch/);
  });

  it("fails on broken-signature (signature check, chain still intact)", async () => {
    const r = await verifyExport(
      loadFixture("broken-signature.json"),
      offlineOpts({ skipTsa: true }),
    );
    expect(r.ok).toBe(false);
    expect(r.checks.chain.ok).toBe(true);
    expect(r.checks.publishedKey.ok).toBe(true);
    expect(r.checks.signatures.ok).toBe(false);
    expect(r.checks.signatures.error).toMatch(/signature/);
  });

  it("fails on forged-chain (published-key check) — the forgery gap", async () => {
    // Whole chain re-signed by an attacker key whose public key is embedded.
    // schema + chain pass (self-consistent), but the published-key match fails.
    const r = await verifyExport(loadFixture("forged-chain.json"), offlineOpts({ skipTsa: true }));
    expect(r.ok).toBe(false);
    expect(r.checks.schema.ok).toBe(true);
    expect(r.checks.chain.ok).toBe(true);
    expect(r.checks.publishedKey.ok).toBe(false);
    expect(r.checks.publishedKey.error).toMatch(/does not match the published key/);
    // signatures must not even run once trust can't be established.
    expect(r.checks.signatures.ran).toBe(false);
  });

  it("propagates TSA failure when skipTsa is false", async () => {
    const keys = loadFixture("trust-keys.json");
    const r = await verifyExport(loadFixture("valid.json"), {
      fetcher: async (url) => {
        if (String(url).includes("/trust/keys/")) {
          return {
            ok: true,
            status: 200,
            arrayBuffer: async () => Buffer.from(JSON.stringify(keys)),
          };
        }
        return { ok: false, status: 500, arrayBuffer: async () => new ArrayBuffer(0) };
      },
    });
    expect(r.ok).toBe(false);
    expect(r.checks.tsa.ran).toBe(true);
    expect(r.checks.tsa.ok).toBe(false);
  });

  it("fails closed when no trust root is available (no key, no fetch)", async () => {
    const r = await verifyExport(loadFixture("valid.json"), {
      skipTsa: true,
      fetcher: async () => {
        throw new Error("no network");
      },
    });
    expect(r.ok).toBe(false);
    expect(r.checks.publishedKey.ok).toBe(false);
  });
});
