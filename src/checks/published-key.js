/**
 * Check 2a: published-key trust root.
 *
 * The forgery gap this closes: signatures are only meaningful if verified
 * against a key the auditor trusts independently of the export. An attacker who
 * regenerates the whole chain with their own keypair and embeds their own
 * `public_key_pem` would otherwise pass every signature check. So before
 * trusting `verification.public_key_pem`, we resolve the tenant's key from an
 * independent source and require the embedded key to match it.
 *
 * Trust root, in priority order:
 *   1. `expectedKey` (a PEM string, programmatic) or `keyFile` (a local PEM
 *      path, CLI `--key-file`) — offline / air-gapped, mirroring TSA `--ca-file`.
 *   2. Otherwise fetch `GET {keysBaseUrl}/trust/keys/{tenant_id}` and match
 *      `verification.key_id` against `keys[].key_id`.
 *
 * The match is on key *material* (SPKI DER of the parsed keys), so cosmetic PEM
 * differences (line wrapping, trailing newline) don't cause false negatives,
 * while any real key substitution fails closed. Signatures are then verified
 * against the resolved trusted key, not the embedded one.
 */
import { createPublicKey } from "node:crypto";
import { readFile } from "node:fs/promises";

const FETCH_TIMEOUT_MS = 15000;
const MAX_KEYS_BYTES = 1024 * 1024; // 1 MB — a key document is < 10 KB.
export const DEFAULT_KEYS_BASE_URL = "https://app.usehasp.com";

/**
 * @typedef {Object} PublishedKeyOptions
 * @property {typeof fetch} [fetcher]
 * @property {string} [keyFile] local PEM file holding the independently-published key
 * @property {string} [expectedKey] PEM string of the independently-published key
 * @property {string} [keysBaseUrl] base URL for the /trust/keys endpoint
 */

/**
 * @param {{export: {tenant_id: string}, verification: {public_key_pem: string, key_id: string}}} data
 * @param {PublishedKeyOptions} [opts]
 * @returns {Promise<{ok: true, publicKey: import("node:crypto").KeyObject, key_id: string, source: string}
 *   | {ok: false, error: string}>}
 */
export async function checkPublishedKey(data, opts = {}) {
  const { public_key_pem: embeddedPem, key_id: keyId } = data.verification;

  // The embedded key must itself be a valid Ed25519 public key.
  let embeddedKey;
  try {
    embeddedKey = createPublicKey(embeddedPem);
  } catch (err) {
    return { ok: false, error: `invalid .verification.public_key_pem: ${errMessage(err)}` };
  }

  // 1. Offline trust root: an explicitly supplied key wins over the network.
  const offlinePem = await resolveOfflinePem(opts);
  if (offlinePem && !offlinePem.ok) return offlinePem;
  if (offlinePem) {
    let trustedKey;
    try {
      trustedKey = createPublicKey(offlinePem.pem);
    } catch (err) {
      return {
        ok: false,
        error: `invalid published key from ${offlinePem.source}: ${errMessage(err)}`,
      };
    }
    if (!sameKey(trustedKey, embeddedKey)) {
      return {
        ok: false,
        error: `embedded public_key_pem does not match the published key (${offlinePem.source}) — refusing to trust the export`,
      };
    }
    return { ok: true, publicKey: trustedKey, key_id: keyId, source: offlinePem.source };
  }

  // 2. Network trust root: fetch the tenant's published keys and match key_id.
  const tenantId = data.export.tenant_id;
  const base = (opts.keysBaseUrl ?? DEFAULT_KEYS_BASE_URL).replace(/\/+$/, "");
  const url = `${base}/trust/keys/${encodeURIComponent(tenantId)}`;
  const fetched = await fetchKeys(opts.fetcher ?? fetch, url);
  if (!fetched.ok) return fetched;

  const keys = fetched.body?.keys;
  if (!Array.isArray(keys)) {
    return { ok: false, error: `published key document from ${url} has no "keys" array` };
  }
  const match = keys.find((k) => k && k.key_id === keyId);
  if (!match) {
    return {
      ok: false,
      error: `no published key with key_id ${JSON.stringify(keyId)} at ${url} — cannot establish trust`,
    };
  }
  if (typeof match.public_key_pem !== "string") {
    return {
      ok: false,
      error: `published key ${JSON.stringify(keyId)} at ${url} has no public_key_pem`,
    };
  }
  let trustedKey;
  try {
    trustedKey = createPublicKey(match.public_key_pem);
  } catch (err) {
    return {
      ok: false,
      error: `published key ${JSON.stringify(keyId)} at ${url} is invalid: ${errMessage(err)}`,
    };
  }
  if (!sameKey(trustedKey, embeddedKey)) {
    return {
      ok: false,
      error: `embedded public_key_pem does not match the published key ${JSON.stringify(keyId)} at ${url} — the export may be forged`,
    };
  }
  return { ok: true, publicKey: trustedKey, key_id: keyId, source: url };
}

/**
 * @param {PublishedKeyOptions} opts
 * @returns {Promise<null | {ok: true, pem: string, source: string} | {ok: false, error: string}>}
 */
async function resolveOfflinePem(opts) {
  if (typeof opts.expectedKey === "string") {
    return { ok: true, pem: opts.expectedKey, source: "expectedKey option" };
  }
  if (typeof opts.keyFile === "string") {
    try {
      const pem = await readFile(opts.keyFile, "utf8");
      return { ok: true, pem, source: `--key-file ${opts.keyFile}` };
    } catch (err) {
      return { ok: false, error: `failed to read --key-file ${opts.keyFile}: ${errMessage(err)}` };
    }
  }
  return null;
}

/**
 * @param {typeof fetch} fetcher
 * @param {string} url
 * @returns {Promise<{ok: true, body: any} | {ok: false, error: string}>}
 */
async function fetchKeys(fetcher, url) {
  try {
    const res = await fetcher(url, {
      signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
      headers: { accept: "application/json" },
    });
    if (!res.ok) {
      return { ok: false, error: `failed to fetch published keys from ${url}: HTTP ${res.status}` };
    }
    const buf = Buffer.from(await res.arrayBuffer());
    if (buf.byteLength > MAX_KEYS_BYTES) {
      return {
        ok: false,
        error: `published key document from ${url} exceeds ${MAX_KEYS_BYTES}-byte cap`,
      };
    }
    try {
      return { ok: true, body: JSON.parse(buf.toString("utf8")) };
    } catch (err) {
      return {
        ok: false,
        error: `published key document from ${url} is not valid JSON: ${errMessage(err)}`,
      };
    }
  } catch (err) {
    return { ok: false, error: `failed to fetch published keys from ${url}: ${errMessage(err)}` };
  }
}

/**
 * Compare two public keys by SPKI DER so PEM formatting differences don't matter.
 * @param {import("node:crypto").KeyObject} a
 * @param {import("node:crypto").KeyObject} b
 */
function sameKey(a, b) {
  try {
    return a
      .export({ type: "spki", format: "der" })
      .equals(b.export({ type: "spki", format: "der" }));
  } catch {
    return false;
  }
}

/** @param {unknown} err */
function errMessage(err) {
  return err instanceof Error ? err.message : String(err);
}
