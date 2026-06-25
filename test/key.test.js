/**
 * Tests for checkPublishedKey: matching the export's key_id against the
 * published-keys document, comparing key material, and the fetch/keysFile
 * sourcing paths.
 */
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { checkPublishedKey } from "../src/checks/key.js";

const here = dirname(fileURLToPath(import.meta.url));
const FIXTURES = resolve(here, "fixtures");
const KEYS_FILE = resolve(FIXTURES, "published-keys.json");
const VALID = JSON.parse(readFileSync(resolve(FIXTURES, "valid.json"), "utf8"));
const KEYS = JSON.parse(readFileSync(KEYS_FILE, "utf8"));
const clone = () => JSON.parse(JSON.stringify(VALID));

/** A fetcher that returns the given object as a JSON body. */
function jsonFetcher(obj, { ok = true, status = 200 } = {}) {
  const body = Buffer.from(JSON.stringify(obj), "utf8");
  return async () => ({
    ok,
    status,
    arrayBuffer: async () => body.buffer.slice(body.byteOffset, body.byteOffset + body.byteLength),
  });
}

describe("checkPublishedKey — keysFile path", () => {
  it("matches the published key and returns it as trusted", async () => {
    const r = await checkPublishedKey(VALID, { keysFile: KEYS_FILE });
    expect(r.ok).toBe(true);
    expect(r.key_id).toBe(VALID.verification.key_id);
    expect(r.trustedPublicKeyPem).toContain("BEGIN PUBLIC KEY");
  });

  it("fails when the embedded key does not match the published key", async () => {
    const d = clone();
    // Swap embedded key for the retired (different) published key.
    d.verification.public_key_pem = KEYS.keys.find((k) => k.status === "retired").public_key_pem;
    const r = await checkPublishedKey(d, { keysFile: KEYS_FILE });
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/does not match the published key/);
  });

  it("fails when key_id is not published", async () => {
    const d = clone();
    d.verification.key_id = "key_does_not_exist";
    const r = await checkPublishedKey(d, { keysFile: KEYS_FILE });
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/is not published/);
  });

  it("fails on a missing keys file", async () => {
    const r = await checkPublishedKey(VALID, { keysFile: "/nonexistent/keys-xyz.json" });
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/failed to read --keys-file/);
  });

  it("fails when the keys file is not valid JSON", async () => {
    const bad = resolve(FIXTURES, "tsa-cacert.pem"); // a real file that isn't JSON
    const r = await checkPublishedKey(VALID, { keysFile: bad });
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/is not valid JSON/);
  });
});

describe("checkPublishedKey — fetch path", () => {
  it("derives the default URL from tenant_id and matches", async () => {
    let calledUrl = null;
    const fetcher = async (url, init) => {
      calledUrl = url;
      void init;
      const body = Buffer.from(JSON.stringify(KEYS), "utf8");
      return { ok: true, status: 200, arrayBuffer: async () => body };
    };
    const d = clone();
    delete d.verification.keys_url;
    const r = await checkPublishedKey(d, { fetcher });
    expect(r.ok).toBe(true);
    expect(calledUrl).toBe(`https://app.usehasp.com/trust/keys/${d.export.tenant_id}`);
  });

  it("uses verification.keys_url when present", async () => {
    let calledUrl = null;
    const fetcher = async (url) => {
      calledUrl = url;
      const body = Buffer.from(JSON.stringify(KEYS), "utf8");
      return { ok: true, status: 200, arrayBuffer: async () => body };
    };
    await checkPublishedKey(VALID, { fetcher });
    expect(calledUrl).toBe(VALID.verification.keys_url);
  });

  it("fails on a non-OK HTTP response", async () => {
    const r = await checkPublishedKey(VALID, {
      fetcher: jsonFetcher({}, { ok: false, status: 404 }),
    });
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/HTTP 404/);
  });

  it("fails when the document has no keys array", async () => {
    const r = await checkPublishedKey(VALID, { fetcher: jsonFetcher({ tenant_id: "x" }) });
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/no "keys" array/);
  });

  it("fails when the keys document is for a different tenant", async () => {
    const r = await checkPublishedKey(VALID, {
      fetcher: jsonFetcher({ tenant_id: "org_someone_else", keys: KEYS.keys }),
    });
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/for tenant org_someone_else/);
  });

  it("fails when the matched key is revoked", async () => {
    const revoked = {
      tenant_id: VALID.export.tenant_id,
      keys: [
        {
          key_id: VALID.verification.key_id,
          public_key_pem: VALID.verification.public_key_pem,
          status: "revoked",
        },
      ],
    };
    const r = await checkPublishedKey(VALID, { fetcher: jsonFetcher(revoked) });
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/revoked/);
  });

  it("fails when the matched published key has no public_key_pem", async () => {
    const doc = {
      tenant_id: VALID.export.tenant_id,
      keys: [{ key_id: VALID.verification.key_id, status: "active" }],
    };
    const r = await checkPublishedKey(VALID, { fetcher: jsonFetcher(doc) });
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/has no public_key_pem/);
  });

  it("fails when the published key is not a parseable public key", async () => {
    const doc = {
      tenant_id: VALID.export.tenant_id,
      keys: [{ key_id: VALID.verification.key_id, public_key_pem: "not a key", status: "active" }],
    };
    const r = await checkPublishedKey(VALID, { fetcher: jsonFetcher(doc) });
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/is not a valid public key/);
  });

  it("fails when the embedded key is not a parseable public key", async () => {
    const d = clone();
    d.verification.public_key_pem = "-----BEGIN PUBLIC KEY-----\nnope\n-----END PUBLIC KEY-----\n";
    const r = await checkPublishedKey(d, { keysFile: KEYS_FILE });
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/verification.public_key_pem is not a valid public key/);
  });

  it("rejects an oversized keys response", async () => {
    const huge = Buffer.alloc(1024 * 1024 + 1, 0x41);
    const fetcher = async () => ({
      ok: true,
      status: 200,
      arrayBuffer: async () =>
        huge.buffer.slice(huge.byteOffset, huge.byteOffset + huge.byteLength),
    });
    const r = await checkPublishedKey(VALID, { fetcher });
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/exceed .*byte cap/);
  });

  it("fails when the fetched body is not valid JSON", async () => {
    const body = Buffer.from("<html>nope</html>", "utf8");
    const fetcher = async () => ({
      ok: true,
      status: 200,
      arrayBuffer: async () =>
        body.buffer.slice(body.byteOffset, body.byteOffset + body.byteLength),
    });
    const r = await checkPublishedKey(VALID, { fetcher });
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/not valid JSON/);
  });

  it("fails when the fetch itself throws", async () => {
    const r = await checkPublishedKey(VALID, {
      fetcher: async () => {
        throw new Error("network down");
      },
    });
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/network down/);
  });

  it("passes an AbortSignal to the fetcher", async () => {
    let signal = null;
    const fetcher = async (_url, init) => {
      signal = init?.signal ?? null;
      const body = Buffer.from(JSON.stringify(KEYS), "utf8");
      return { ok: true, status: 200, arrayBuffer: async () => body };
    };
    await checkPublishedKey(VALID, { fetcher });
    expect(signal).not.toBeNull();
    expect(typeof signal.aborted).toBe("boolean");
  });
});
