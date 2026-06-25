/**
 * Check: published-key match.
 *
 * The trust root is NOT the key embedded in the export — anyone can embed a key
 * and sign with it. It is the key the platform publishes out-of-band at
 *
 *     GET https://app.usehasp.com/trust/keys/{tenant_id}
 *       → { tenant_id, keys: [{ key_id, public_key_pem, published_at, status }] }
 *
 * This check fetches that document, finds the key whose `key_id` matches the
 * export's `verification.key_id`, confirms it is not revoked, and confirms its
 * `public_key_pem` matches the key embedded in the export. The matched
 * published key is then what the signature check verifies against — so a forged
 * export that swaps in its own key fails here, before any signature is trusted.
 *
 * `/.well-known/audit-keys.json` is a discovery document
 * (`{ algo, keys_url_template }`), not a key dump; the export carries the
 * resolved `keys_url` (or it is derived from `tenant_id`).
 *
 * Offline: pass a local copy of the keys document via `--keys-file`, or skip
 * this check entirely with `--skip-key-check` (signatures then verify against
 * the embedded key, whose provenance is unconfirmed).
 */
import { createPublicKey } from "node:crypto";
import { readFile } from "node:fs/promises";

const FETCH_TIMEOUT_MS = 15000;
const MAX_KEYS_BYTES = 1024 * 1024; // 1 MB — a keys document is a few KB.
const DEFAULT_KEYS_BASE = "https://app.usehasp.com/trust/keys";

/**
 * @param {{export: {tenant_id: string}, verification: {key_id: string, public_key_pem: string, keys_url?: string}}} data
 * @param {{fetcher?: typeof fetch, keysFile?: string, keysUrl?: string}} [opts]
 * @returns {Promise<{ok: true, key_id: string, keys_source: string, trustedPublicKeyPem: string} | {ok: false, error: string}>}
 */
export async function checkPublishedKey(data, opts = {}) {
  const keyId = data.verification.key_id;
  const tenantId = data.export.tenant_id;

  let doc;
  let source;
  if (opts.keysFile) {
    source = opts.keysFile;
    let raw;
    try {
      raw = await readFile(opts.keysFile, "utf8");
    } catch (err) {
      return {
        ok: false,
        error: `failed to read --keys-file ${opts.keysFile}: ${errMessage(err)}`,
      };
    }
    try {
      doc = JSON.parse(raw);
    } catch (err) {
      return {
        ok: false,
        error: `--keys-file ${opts.keysFile} is not valid JSON: ${errMessage(err)}`,
      };
    }
  } else {
    source = opts.keysUrl ?? data.verification.keys_url ?? `${DEFAULT_KEYS_BASE}/${tenantId}`;
    const fetched = await fetchKeys(opts.fetcher ?? fetch, source);
    if (!fetched.ok) return { ok: false, error: fetched.error };
    doc = fetched.doc;
  }

  if (!doc || typeof doc !== "object" || !Array.isArray(doc.keys)) {
    return { ok: false, error: `published keys document from ${source} has no "keys" array` };
  }
  if (typeof doc.tenant_id === "string" && doc.tenant_id !== tenantId) {
    return {
      ok: false,
      error: `published keys are for tenant ${doc.tenant_id}, but the export is for ${tenantId}`,
    };
  }

  const published = doc.keys.find(/** @param {any} k */ (k) => k && k.key_id === keyId);
  if (!published) {
    const available =
      doc.keys
        .map(/** @param {any} k */ (k) => k?.key_id)
        .filter(Boolean)
        .join(", ") || "(none)";
    return {
      ok: false,
      error: `key_id ${keyId} is not published for tenant ${tenantId} (published: ${available})`,
    };
  }
  if (published.status === "revoked") {
    return { ok: false, error: `published key ${keyId} is revoked` };
  }
  if (typeof published.public_key_pem !== "string") {
    return { ok: false, error: `published key ${keyId} has no public_key_pem` };
  }

  // Compare on the parsed key material (DER), so PEM whitespace/line-ending
  // differences don't cause a spurious mismatch.
  let publishedDer;
  let embeddedDer;
  try {
    publishedDer = derOf(published.public_key_pem);
  } catch (err) {
    return {
      ok: false,
      error: `published key ${keyId} is not a valid public key: ${errMessage(err)}`,
    };
  }
  try {
    embeddedDer = derOf(data.verification.public_key_pem);
  } catch (err) {
    return {
      ok: false,
      error: `export's verification.public_key_pem is not a valid public key: ${errMessage(err)}`,
    };
  }
  if (!publishedDer.equals(embeddedDer)) {
    return {
      ok: false,
      error: `embedded public_key_pem does not match the published key ${keyId} from ${source}`,
    };
  }

  return {
    ok: true,
    key_id: keyId,
    keys_source: source,
    trustedPublicKeyPem: published.public_key_pem,
  };
}

/**
 * @param {typeof fetch} fetcher
 * @param {string} url
 * @returns {Promise<{ok: true, doc: any} | {ok: false, error: string}>}
 */
async function fetchKeys(fetcher, url) {
  try {
    const res = await fetcher(url, { signal: AbortSignal.timeout(FETCH_TIMEOUT_MS) });
    if (!res.ok) {
      return { ok: false, error: `failed to fetch published keys from ${url}: HTTP ${res.status}` };
    }
    const buf = Buffer.from(await res.arrayBuffer());
    if (buf.byteLength > MAX_KEYS_BYTES) {
      return {
        ok: false,
        error: `published keys from ${url} exceed ${MAX_KEYS_BYTES}-byte cap (got ${buf.byteLength})`,
      };
    }
    try {
      return { ok: true, doc: JSON.parse(buf.toString("utf8")) };
    } catch (err) {
      return {
        ok: false,
        error: `published keys from ${url} are not valid JSON: ${errMessage(err)}`,
      };
    }
  } catch (err) {
    return { ok: false, error: `failed to fetch published keys from ${url}: ${errMessage(err)}` };
  }
}

/** @param {string} pem @returns {Buffer} SPKI DER bytes */
function derOf(pem) {
  return createPublicKey(pem).export({ type: "spki", format: "der" });
}

/** @param {unknown} err */
function errMessage(err) {
  return err instanceof Error ? err.message : String(err);
}
