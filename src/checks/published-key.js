/**
 * Check (a): published-key trust root (part of the four-check contract).
 *
 * Signatures are only meaningful if verified against a key the auditor trusts
 * independently of the export. An attacker who regenerates the whole chain with
 * their own keypair and embeds their own `public_key_pem` would otherwise pass
 * every signature check. So before trusting `verification.public_key_pem`, we
 * resolve the tenant's audit-signing key from an *independent* source and
 * require the embedded key to match it — "the hinge of verify-without-trusting-
 * HASP".
 *
 * Trust root, in priority order:
 *   1. `expectedKey` — a PEM string (programmatic use).
 *   2. `keysFile` — a local published-keys document (CLI `--keys-file`), the
 *      exact shape served at `/trust/keys/{org}`:
 *      `{ tenant_id, keys: [{ key_id, public_key_pem, ... }] }`. Match on
 *      `verification.key_id`. This is the offline / air-gapped path and is what
 *      the published sample uses (its tenant is a throwaway that has no live
 *      endpoint — the co-published keys doc is its only trust anchor).
 *   3. Otherwise fetch `GET {keysBaseUrl}/trust/keys/{tenant_id}` and match
 *      `verification.key_id` against `keys[].key_id`.
 *
 * The platform's `/.well-known/audit-keys.json` is a discovery pointer to that
 * per-tenant endpoint (`{ algo, keys_url_template }`), not a key list — no one
 * URL lists every tenant's keys. This check never reads it: it builds the
 * per-tenant URL itself from the export's `tenant_id`.
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
 * @property {typeof fetch} [fetcher] inject a fetch implementation (testing)
 * @property {string} [expectedKey] PEM string of the independently-published key
 * @property {string} [keysFile] local published-keys JSON document (match by key_id)
 * @property {string} [keysBaseUrl] base URL for the /trust/keys endpoint
 */

/**
 * Multi-key envelopes: when `verification.keys[]` is present (the
 * export window spans more than one signing key — a rotation occurred inside
 * it), every key in the array is independently resolved and matched against
 * the published/trusted source; the result carries a `key_id -> KeyObject`
 * map instead of a single key, and {@link module:checks/signature} selects
 * the right one per entry by `entry.key_id`, failing closed if an entry
 * references a key_id absent from the map.
 *
 * @typedef {Object} KeyStatus
 * @property {"active" | "retired" | "revoked" | undefined} status status from the published-keys document, when present (older documents that predate key-revocation status omit it)
 * @property {string | null} revoked_at ISO timestamp, present iff status === "revoked"
 *
 * @param {{export: {tenant_id: string}, verification: {public_key_pem?: string, key_id?: string, keys?: Array<{key_id: string, public_key_pem: string}>}}} data
 * @param {PublishedKeyOptions} [opts]
 * @returns {Promise<{ok: true, publicKey: import("node:crypto").KeyObject, key_id: string, source: string, status: KeyStatus}
 *   | {ok: true, publicKeys: Record<string, import("node:crypto").KeyObject>, source: string, statuses: Record<string, KeyStatus>}
 *   | {ok: false, error: string}>}
 */
export async function checkPublishedKey(data, opts = {}) {
  if (Array.isArray(data.verification.keys) && data.verification.keys.length > 1) {
    return checkPublishedKeysMulti(data, opts);
  }

  const { public_key_pem: embeddedPem, key_id: keyId } = data.verification;

  // checkSchema() already guarantees these are present on the single-key
  // path; narrow the type here rather than threading `| undefined` through
  // every downstream branch.
  if (typeof embeddedPem !== "string" || typeof keyId !== "string") {
    return { ok: false, error: "missing .verification.public_key_pem or .verification.key_id" };
  }

  // The embedded key must itself be a valid Ed25519 public key. Enforce the
  // key TYPE, not just that the PEM parses: the signature check verifies with
  // `crypto.verify(null, …)`, which requires Ed25519 — a non-Ed25519 key that
  // slipped through here would throw there, breaking the structured output.
  let embeddedKey;
  try {
    embeddedKey = createPublicKey(embeddedPem);
  } catch (err) {
    return { ok: false, error: `invalid .verification.public_key_pem: ${errMessage(err)}` };
  }
  if (embeddedKey.asymmetricKeyType !== "ed25519") {
    return {
      ok: false,
      error: `.verification.public_key_pem is not an Ed25519 key (got ${embeddedKey.asymmetricKeyType ?? "unknown"})`,
    };
  }

  const resolved = await resolveTrustedKey(data, keyId, opts);
  if (!resolved.ok) return resolved;

  let trustedKey;
  try {
    trustedKey = createPublicKey(resolved.pem);
  } catch (err) {
    return {
      ok: false,
      error: `invalid published key from ${resolved.source}: ${errMessage(err)}`,
    };
  }
  if (trustedKey.asymmetricKeyType !== "ed25519") {
    return {
      ok: false,
      error: `published key from ${resolved.source} is not an Ed25519 key (got ${trustedKey.asymmetricKeyType ?? "unknown"})`,
    };
  }

  if (!sameKey(trustedKey, embeddedKey)) {
    return {
      ok: false,
      error: `embedded public_key_pem does not match the published key (${resolved.source}) — refusing to trust the export`,
    };
  }

  return {
    ok: true,
    publicKey: trustedKey,
    key_id: keyId,
    source: resolved.source,
    status: { status: resolved.status, revoked_at: resolved.revoked_at ?? null },
  };
}

/**
 * Resolve and match every key in a multi-key envelope's `verification.keys[]`.
 *
 * @param {{export: {tenant_id: string}, verification: {keys?: Array<{key_id: string, public_key_pem: string}>}}} data
 * @param {PublishedKeyOptions} opts
 * @returns {Promise<{ok: true, publicKeys: Record<string, import("node:crypto").KeyObject>, source: string, statuses: Record<string, KeyStatus>}
 *   | {ok: false, error: string}>}
 */
async function checkPublishedKeysMulti(data, opts) {
  /** @type {Record<string, import("node:crypto").KeyObject>} */
  const publicKeys = {};
  /** @type {Record<string, KeyStatus>} */
  const statuses = {};
  let source = "";

  for (const entry of /** @type {Array<{key_id: string, public_key_pem: string}>} */ (
    data.verification.keys
  )) {
    const keyId = entry?.key_id;
    let embeddedKey;
    try {
      embeddedKey = createPublicKey(entry?.public_key_pem);
    } catch (err) {
      return {
        ok: false,
        error: `invalid public_key_pem for .verification.keys entry ${JSON.stringify(keyId)}: ${errMessage(err)}`,
      };
    }
    if (embeddedKey.asymmetricKeyType !== "ed25519") {
      return {
        ok: false,
        error: `.verification.keys entry ${JSON.stringify(keyId)} is not an Ed25519 key (got ${embeddedKey.asymmetricKeyType ?? "unknown"})`,
      };
    }

    const resolved = await resolveTrustedKey(data, keyId, opts);
    if (!resolved.ok) return resolved;

    let trustedKey;
    try {
      trustedKey = createPublicKey(resolved.pem);
    } catch (err) {
      return {
        ok: false,
        error: `invalid published key ${JSON.stringify(keyId)} from ${resolved.source}: ${errMessage(err)}`,
      };
    }
    if (trustedKey.asymmetricKeyType !== "ed25519") {
      return {
        ok: false,
        error: `published key ${JSON.stringify(keyId)} from ${resolved.source} is not an Ed25519 key (got ${trustedKey.asymmetricKeyType ?? "unknown"})`,
      };
    }
    if (!sameKey(trustedKey, embeddedKey)) {
      return {
        ok: false,
        error: `embedded public_key_pem for key_id ${JSON.stringify(keyId)} does not match the published key (${resolved.source}) — refusing to trust the export`,
      };
    }

    publicKeys[keyId] = trustedKey;
    statuses[keyId] = { status: resolved.status, revoked_at: resolved.revoked_at ?? null };
    source = resolved.source;
  }

  return { ok: true, publicKeys, statuses, source };
}

/**
 * Resolve the independently-published PEM for this export's key_id.
 * @param {{export: {tenant_id: string}}} data
 * @param {string} keyId
 * @param {PublishedKeyOptions} opts
 * @returns {Promise<{ok: true, pem: string, source: string, status?: "active" | "retired" | "revoked", revoked_at?: string | null} | {ok: false, error: string}>}
 */
async function resolveTrustedKey(data, keyId, opts) {
  // 1. Explicit PEM — highest priority, fully offline. Carries no revocation
  // status (a bare PEM has none); a key resolved this way is never treated
  // as revoked by the key-revocation check.
  if (typeof opts.expectedKey === "string") {
    return { ok: true, pem: opts.expectedKey, source: "expectedKey option" };
  }

  // 2. Local published-keys document — offline / air-gapped (CLI --keys-file).
  if (typeof opts.keysFile === "string") {
    let raw;
    try {
      raw = await readFile(opts.keysFile, "utf8");
    } catch (err) {
      return {
        ok: false,
        error: `failed to read --keys-file ${opts.keysFile}: ${errMessage(err)}`,
      };
    }
    let doc;
    try {
      doc = JSON.parse(raw);
    } catch (err) {
      return {
        ok: false,
        error: `--keys-file ${opts.keysFile} is not valid JSON: ${errMessage(err)}`,
      };
    }
    return selectKey(doc, keyId, data.export.tenant_id, `--keys-file ${opts.keysFile}`);
  }

  // 3. Network trust root: fetch the tenant's published keys and match key_id.
  const tenantId = data.export.tenant_id;
  const base = (opts.keysBaseUrl ?? DEFAULT_KEYS_BASE_URL).replace(/\/+$/, "");
  const url = `${base}/trust/keys/${encodeURIComponent(tenantId)}`;
  const fetched = await fetchKeys(opts.fetcher ?? fetch, url);
  if (!fetched.ok) return fetched;
  return selectKey(fetched.body, keyId, tenantId, url);
}

/**
 * Pick the `public_key_pem` for `keyId` out of a published-keys document.
 * The document must be for the export's own tenant — `/trust/keys/{org}` (and
 * any offline copy of it) carries a top-level `tenant_id`, so a keys
 * doc for the wrong tenant (a mismatched `--keys-file`, say) is rejected even
 * if it happens to contain an entry with the same `key_id`.
 * @param {any} doc
 * @param {string} keyId
 * @param {string} expectedTenantId
 * @param {string} source
 * @returns {{ok: true, pem: string, source: string, status?: "active" | "retired" | "revoked", revoked_at?: string | null} | {ok: false, error: string}}
 */
function selectKey(doc, keyId, expectedTenantId, source) {
  if (doc?.tenant_id !== expectedTenantId) {
    return {
      ok: false,
      error: `published key document from ${source} is for tenant ${JSON.stringify(doc?.tenant_id ?? null)}, not the export's tenant ${JSON.stringify(expectedTenantId)} — refusing to trust it`,
    };
  }
  const keys = doc?.keys;
  if (!Array.isArray(keys)) {
    return { ok: false, error: `published key document from ${source} has no "keys" array` };
  }
  const match = keys.find((k) => k && k.key_id === keyId);
  if (!match) {
    return {
      ok: false,
      error: `no published key with key_id ${JSON.stringify(keyId)} at ${source} — cannot establish trust`,
    };
  }
  if (typeof match.public_key_pem !== "string") {
    return {
      ok: false,
      error: `published key ${JSON.stringify(keyId)} at ${source} has no public_key_pem`,
    };
  }
  // `status`/`revoked_at` are new, optional fields on a
  // published-keys document — absent on documents from before this change
  // (an old cached --keys-file, a keys doc a customer archived earlier).
  // Absent status is treated as "not known to be revoked", never as revoked.
  return {
    ok: true,
    pem: match.public_key_pem,
    source,
    status: match.status,
    revoked_at: match.revoked_at ?? null,
  };
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
