/**
 * Tests for checkPublishedKey — the trust-root check that closes the forgery
 * gap. It resolves the tenant's independently-published key (via fetch,
 * --key-file, or expectedKey) and requires the embedded public_key_pem to match.
 */
import { describe, expect, it } from "vitest";
import { checkPublishedKey } from "../src/checks/published-key.js";
import {
  loadFixture,
  offlineFetcher,
  PUBLISHED_KEY_FILE,
  PUBLISHED_KEY_PEM,
  TRUST_KEYS,
} from "./helpers.js";

const VALID = loadFixture("valid.json");
const FORGED = loadFixture("forged-chain.json");
const clone = (x) => JSON.parse(JSON.stringify(x));

describe("checkPublishedKey — fetch path", () => {
  it("resolves and matches the published key over the network", async () => {
    const r = await checkPublishedKey(VALID, { fetcher: offlineFetcher() });
    expect(r.ok).toBe(true);
    expect(r.key_id).toBe(VALID.verification.key_id);
    expect(r.source).toMatch(/\/trust\/keys\//);
  });

  it("uses tenant_id and the default keys base URL", async () => {
    let seenUrl = null;
    const fetcher = async (url) => {
      seenUrl = String(url);
      return {
        ok: true,
        status: 200,
        arrayBuffer: async () => Buffer.from(JSON.stringify(TRUST_KEYS)),
      };
    };
    await checkPublishedKey(VALID, { fetcher });
    expect(seenUrl).toBe(
      `https://app.usehasp.com/trust/keys/${encodeURIComponent(VALID.export.tenant_id)}`,
    );
  });

  it("honours a custom keysBaseUrl", async () => {
    let seenUrl = null;
    const fetcher = async (url) => {
      seenUrl = String(url);
      return {
        ok: true,
        status: 200,
        arrayBuffer: async () => Buffer.from(JSON.stringify(TRUST_KEYS)),
      };
    };
    await checkPublishedKey(VALID, { fetcher, keysBaseUrl: "https://mirror.example.com/" });
    expect(seenUrl).toBe(
      `https://mirror.example.com/trust/keys/${encodeURIComponent(VALID.export.tenant_id)}`,
    );
  });

  it("FAILS CLOSED on a whole-chain forgery whose attacker key is embedded", async () => {
    // The published key document still serves the legitimate key; the forged
    // export embeds the attacker's key. The match must fail.
    const r = await checkPublishedKey(FORGED, { fetcher: offlineFetcher() });
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/does not match the published key/);
  });

  it("fails when no published key has the export's key_id", async () => {
    const otherKeys = clone(TRUST_KEYS);
    otherKeys.keys[0].key_id = "key_SOMETHING_ELSE";
    const r = await checkPublishedKey(VALID, { fetcher: offlineFetcher(otherKeys) });
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/no published key with key_id/);
  });

  it("fails when the keys document has no keys array", async () => {
    const r = await checkPublishedKey(VALID, { fetcher: offlineFetcher({ tenant_id: "x" }) });
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/no "keys" array/);
  });

  it("fails closed on HTTP error from the keys endpoint", async () => {
    const fetcher = async () => ({
      ok: false,
      status: 503,
      arrayBuffer: async () => new ArrayBuffer(0),
    });
    const r = await checkPublishedKey(VALID, { fetcher });
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/HTTP 503/);
  });

  it("fails closed when the fetch throws (network down)", async () => {
    const fetcher = async () => {
      throw new Error("network down");
    };
    const r = await checkPublishedKey(VALID, { fetcher });
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/network down/);
  });

  it("fails on a non-JSON keys document", async () => {
    const fetcher = async () => ({
      ok: true,
      status: 200,
      arrayBuffer: async () => Buffer.from("not json"),
    });
    const r = await checkPublishedKey(VALID, { fetcher });
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/not valid JSON/);
  });

  it("passes an AbortSignal to the fetcher (timeout can fire)", async () => {
    let signal = null;
    const fetcher = async (_url, init) => {
      signal = init?.signal ?? null;
      return {
        ok: true,
        status: 200,
        arrayBuffer: async () => Buffer.from(JSON.stringify(TRUST_KEYS)),
      };
    };
    await checkPublishedKey(VALID, { fetcher });
    expect(signal).not.toBeNull();
    expect(typeof signal.aborted).toBe("boolean");
  });

  it("rejects an oversized keys document", async () => {
    const huge = Buffer.alloc(1024 * 1024 + 1, 0x41);
    const fetcher = async () => ({
      ok: true,
      status: 200,
      arrayBuffer: async () =>
        huge.buffer.slice(huge.byteOffset, huge.byteOffset + huge.byteLength),
    });
    const r = await checkPublishedKey(VALID, { fetcher });
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/exceeds .*byte cap/);
  });

  it("fails when the matched published key has no public_key_pem", async () => {
    const bad = clone(TRUST_KEYS);
    delete bad.keys[0].public_key_pem;
    const r = await checkPublishedKey(VALID, { fetcher: offlineFetcher(bad) });
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/has no public_key_pem/);
  });

  it("fails when the matched published key is not a valid PEM", async () => {
    const bad = clone(TRUST_KEYS);
    bad.keys[0].public_key_pem = "-----BEGIN PUBLIC KEY-----\nNOPE\n-----END PUBLIC KEY-----\n";
    const r = await checkPublishedKey(VALID, { fetcher: offlineFetcher(bad) });
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/is invalid/);
  });

  it("rejects an invalid embedded public_key_pem before fetching", async () => {
    const d = clone(VALID);
    d.verification.public_key_pem = "-----BEGIN PUBLIC KEY-----\nNOPE\n-----END PUBLIC KEY-----\n";
    let called = false;
    const fetcher = async () => {
      called = true;
      return {
        ok: true,
        status: 200,
        arrayBuffer: async () => Buffer.from(JSON.stringify(TRUST_KEYS)),
      };
    };
    const r = await checkPublishedKey(d, { fetcher });
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/invalid .verification.public_key_pem/);
    expect(called).toBe(false);
  });
});

describe("checkPublishedKey — offline path", () => {
  it("matches against expectedKey (PEM string) without fetching", async () => {
    let called = false;
    const fetcher = async () => {
      called = true;
      throw new Error("should not fetch");
    };
    const r = await checkPublishedKey(VALID, { fetcher, expectedKey: PUBLISHED_KEY_PEM });
    expect(r.ok).toBe(true);
    expect(r.source).toMatch(/expectedKey/);
    expect(called).toBe(false);
  });

  it("matches against --key-file without fetching", async () => {
    const r = await checkPublishedKey(VALID, { keyFile: PUBLISHED_KEY_FILE });
    expect(r.ok).toBe(true);
    expect(r.source).toMatch(/--key-file/);
  });

  it("fails closed when the forged key is checked against a local published key", async () => {
    const r = await checkPublishedKey(FORGED, { keyFile: PUBLISHED_KEY_FILE });
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/does not match the published key/);
  });

  it("returns a clear error when --key-file is missing", async () => {
    const r = await checkPublishedKey(VALID, { keyFile: "/nonexistent/key-xyz.pem" });
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/failed to read --key-file/);
  });

  it("rejects an invalid expectedKey PEM", async () => {
    const r = await checkPublishedKey(VALID, {
      expectedKey: "-----BEGIN PUBLIC KEY-----\nNOPE\n-----END PUBLIC KEY-----\n",
    });
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/invalid published key from expectedKey/);
  });
});
