/**
 * Check 2: per-entry Ed25519 signatures.
 *
 * Each entry's `signature` field is `"ed25519:<base64>"`. The HASP platform
 * signs the row's `integrity_hash` — the 64-char ASCII hex string — with the
 * org's per-tenant Ed25519 key. So the signed message is exactly
 * `Buffer.from(entry.hash, "utf8")`.
 *
 * The verifying key is the one established by the published-key check
 * ({@link module:checks/published-key}) — the independently-published tenant
 * key, NOT the key embedded in the export. Pass it via `opts.publicKey`.
 * There is no fallback to the export's embedded `verification.public_key_pem`
 * — verifying an export against its own embedded key proves nothing (an
 * attacker who regenerates the whole chain with their own keypair would pass
 * every check). Callers that genuinely have no independently-resolved key
 * must fail closed rather than silently downgrade to that circular check.
 *
 * Multi-key envelopes: pass `opts.publicKeys` (a `key_id ->
 * KeyObject` map, as returned by the published-key check's multi-key path)
 * instead of `opts.publicKey`. Every entry must then carry its own `key_id`;
 * an entry whose `key_id` is absent from the map fails closed rather than
 * falling back to any other key.
 */
import { verify as edVerify } from "node:crypto";

/**
 * @param {{entries: any[]}} data
 * @param {{publicKey?: import("node:crypto").KeyObject, publicKeys?: Record<string, import("node:crypto").KeyObject>}} [opts]
 * @returns {{ok: true, count: number} | {ok: false, error: string}}
 */
export function checkSignatures(data, opts = {}) {
  const multiKey = opts.publicKeys != null;

  let pubKey;
  if (!multiKey) {
    if (!opts.publicKey) {
      return {
        ok: false,
        error:
          "no trusted public key provided — checkSignatures no longer falls back to the export's " +
          "own embedded public_key_pem (that would verify the export against itself). Pass " +
          "opts.publicKey (or opts.publicKeys), resolved independently via the published-key check.",
      };
    }
    pubKey = opts.publicKey;
  }

  let ok = 0;
  for (const entry of data.entries) {
    let entryKey = pubKey;
    if (multiKey) {
      const keyId = entry.key_id;
      if (typeof keyId !== "string" || !(keyId in /** @type {object} */ (opts.publicKeys))) {
        return {
          ok: false,
          error: `entry seq=${entry.seq} references key_id ${JSON.stringify(keyId)}, which is not among this export's trusted keys — failing closed`,
        };
      }
      entryKey = /** @type {Record<string, import("node:crypto").KeyObject>} */ (opts.publicKeys)[
        keyId
      ];
    }

    const parts = entry.signature.split(":");
    if (parts.length !== 2 || parts[0] !== "ed25519") {
      return { ok: false, error: `entry seq=${entry.seq} signature format invalid` };
    }
    const sig = Buffer.from(parts[1], "base64");
    // The platform signs the hex `integrity_hash` STRING itself, not its bytes.
    const message = Buffer.from(entry.hash, "utf8");
    const valid = edVerify(
      null,
      message,
      /** @type {import("node:crypto").KeyObject} */ (entryKey),
      sig,
    );
    if (!valid) {
      return { ok: false, error: `signature invalid at seq=${entry.seq}` };
    }
    ok++;
  }
  return { ok: true, count: ok };
}
