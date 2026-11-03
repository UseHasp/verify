/**
 * Tests for checkPublishedKey — the published-key trust root check.
 *
 * The check resolves the tenant's independently-published Ed25519 key from an
 * offline document (expectedKey / keysFile) or the network (/trust/keys) and
 * requires the export's embedded key to match it on key material.
 */
import { generateKeyPairSync } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { checkPublishedKey } from "../src/checks/published-key.js";

const here = dirname(fileURLToPath(import.meta.url));
const load = (name) => JSON.parse(readFileSync(resolve(here, "fixtures", name), "utf8"));
const KEYS_FILE = resolve(here, "fixtures", "published-keys.json");

const VALID = load("valid.json");
const embeddedPem = VALID.verification.public_key_pem;
const keyId = VALID.verification.key_id;
const tenantId = VALID.export.tenant_id;

/** A structurally-valid Ed25519 public key that is NOT the sample's key. */
function otherKeyPem() {
  const { publicKey } = generateKeyPairSync("ed25519");
  return publicKey.export({ type: "spki", format: "pem" }).toString();
}

/** A structurally-valid but wrong-type (RSA) public key PEM. */
function rsaKeyPem() {
  const { publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  return publicKey.export({ type: "spki", format: "pem" }).toString();
}

/** A fetcher that returns the given JSON body with an ok status. */
function jsonFetcher(body, { ok = true, status = 200 } = {}) {
  const buf = Buffer.from(JSON.stringify(body), "utf8");
  return async () => ({ ok, status, arrayBuffer: async () => buf });
}

describe("checkPublishedKey", () => {
  it("passes when the embedded key matches expectedKey (offline PEM)", async () => {
    const r = await checkPublishedKey(VALID, { expectedKey: embeddedPem });
    expect(r.ok).toBe(true);
    expect(r.key_id).toBe(keyId);
    expect(r.source).toMatch(/expectedKey/);
  });

  it("passes when the embedded key matches the local keys document", async () => {
    const r = await checkPublishedKey(VALID, { keysFile: KEYS_FILE });
    expect(r.ok).toBe(true);
    expect(r.source).toMatch(/--keys-file/);
  });

  it("ignores cosmetic PEM formatting differences (matches on key material)", async () => {
    // Re-wrap the PEM: strip the trailing newline. Same key material.
    const r = await checkPublishedKey(VALID, { expectedKey: embeddedPem.trimEnd() });
    expect(r.ok).toBe(true);
  });

  it("fails closed when expectedKey is a different key", async () => {
    const r = await checkPublishedKey(VALID, { expectedKey: otherKeyPem() });
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/does not match the published key/);
  });

  it("fails when the embedded public_key_pem is itself invalid", async () => {
    const bad = JSON.parse(JSON.stringify(VALID));
    bad.verification.public_key_pem =
      "-----BEGIN PUBLIC KEY-----\nNOPE\n-----END PUBLIC KEY-----\n";
    const r = await checkPublishedKey(bad, { expectedKey: embeddedPem });
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/invalid .verification.public_key_pem/);
  });

  it("fails when the embedded key is not Ed25519 (wrong key type)", async () => {
    const bad = JSON.parse(JSON.stringify(VALID));
    const rsa = rsaKeyPem();
    bad.verification.public_key_pem = rsa;
    const r = await checkPublishedKey(bad, { expectedKey: rsa });
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/public_key_pem is not an Ed25519 key/);
  });

  it("fails when the resolved published key is not Ed25519", async () => {
    // Embedded is a real Ed25519 key; the trust root resolves to an RSA key.
    const r = await checkPublishedKey(VALID, { expectedKey: rsaKeyPem() });
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/published key from .* is not an Ed25519 key/);
  });

  it("fails when the keys document is for a different tenant", async () => {
    const r = await checkPublishedKey(VALID, {
      fetcher: jsonFetcher({
        tenant_id: "some-other-tenant",
        keys: [{ key_id: keyId, public_key_pem: embeddedPem }],
      }),
    });
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/is for tenant .* not the export's tenant/);
  });

  it("fails when the keys document has no entry for this key_id", async () => {
    const r = await checkPublishedKey(VALID, {
      fetcher: jsonFetcher({
        tenant_id: tenantId,
        keys: [{ key_id: "some-other-id", public_key_pem: otherKeyPem() }],
      }),
    });
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/no published key with key_id/);
  });

  it("fetches from /trust/keys and matches on key_id (network path)", async () => {
    let requestedUrl = "";
    const fetcher = async (url) => {
      requestedUrl = url;
      const buf = Buffer.from(
        JSON.stringify({
          tenant_id: tenantId,
          keys: [{ key_id: keyId, public_key_pem: embeddedPem }],
        }),
        "utf8",
      );
      return { ok: true, status: 200, arrayBuffer: async () => buf };
    };
    const r = await checkPublishedKey(VALID, { fetcher, keysBaseUrl: "https://app.usehasp.com" });
    expect(r.ok).toBe(true);
    expect(requestedUrl).toBe(`https://app.usehasp.com/trust/keys/${tenantId}`);
  });

  it("fails on a non-OK fetch response", async () => {
    const r = await checkPublishedKey(VALID, {
      fetcher: jsonFetcher({}, { ok: false, status: 404 }),
    });
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/HTTP 404/);
  });

  it("fails when the resolved published key PEM is unparseable", async () => {
    const r = await checkPublishedKey(VALID, {
      expectedKey: "-----BEGIN PUBLIC KEY-----\nNOPE\n-----END PUBLIC KEY-----\n",
    });
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/invalid published key from expectedKey option/);
  });

  it("fails when --keys-file does not exist", async () => {
    const r = await checkPublishedKey(VALID, {
      keysFile: resolve(here, "fixtures", "no-such-keys-file.json"),
    });
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/failed to read --keys-file/);
  });

  it("fails when --keys-file is not valid JSON", async () => {
    // Any committed non-JSON file will do; this test file itself is one.
    const r = await checkPublishedKey(VALID, { keysFile: fileURLToPath(import.meta.url) });
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/is not valid JSON/);
  });

  it('fails when the keys document has no "keys" array', async () => {
    const r = await checkPublishedKey(VALID, {
      fetcher: jsonFetcher({ tenant_id: tenantId, keys: "none" }),
    });
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/has no "keys" array/);
  });

  it("fails when the matched key entry has no public_key_pem", async () => {
    const r = await checkPublishedKey(VALID, {
      fetcher: jsonFetcher({ tenant_id: tenantId, keys: [{ key_id: keyId }] }),
    });
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/has no public_key_pem/);
  });

  it("fails when the fetched keys document exceeds the size cap", async () => {
    const huge = Buffer.alloc(1024 * 1024 + 1, 0x20);
    const fetcher = async () => ({ ok: true, status: 200, arrayBuffer: async () => huge });
    const r = await checkPublishedKey(VALID, { fetcher });
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/exceeds .*-byte cap/);
  });

  it("fails when the fetched keys document is not valid JSON", async () => {
    const buf = Buffer.from("<html>rate limited</html>", "utf8");
    const fetcher = async () => ({ ok: true, status: 200, arrayBuffer: async () => buf });
    const r = await checkPublishedKey(VALID, { fetcher });
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/is not valid JSON/);
  });

  it("fails when the fetch itself throws (network error)", async () => {
    const fetcher = async () => {
      throw new Error("getaddrinfo ENOTFOUND app.usehasp.com");
    };
    const r = await checkPublishedKey(VALID, { fetcher });
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/failed to fetch published keys .* ENOTFOUND/);
  });

  it("stringifies non-Error throw values in the failure message", async () => {
    const fetcher = async () => {
      throw "socket hangup";
    };
    const r = await checkPublishedKey(VALID, { fetcher });
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/socket hangup/);
  });
});
