/**
 * Check 2b: per-entry Ed25519 signatures.
 *
 * Each entry's `signature` is `"ed25519:" + base64(rawSig)`, a detached Ed25519
 * signature over the entry's `hash` **hex string** (ASCII bytes) — NOT over the
 * canonical payload and NOT over the raw hash bytes. This matches the platform:
 *   sodium_crypto_sign_verify_detached(rawSig, entry.hash, publicKey)
 * where `entry.hash` is the 64-char hex string.
 *
 * Signatures are verified against the trusted key resolved by the published-key
 * check (src/checks/published-key.js) — the key proven to match the tenant's
 * independently-published key — not the key embedded in the export.
 */
import { verify as edVerify } from "node:crypto";

/**
 * @param {{entries: any[]}} data
 * @param {{publicKey: import("node:crypto").KeyObject}} ctx resolved trusted key
 * @returns {{ok: true, count: number} | {ok: false, error: string}}
 */
export function checkSignatures(data, ctx) {
  const pubKey = ctx.publicKey;
  let ok = 0;
  for (const [i, entry] of data.entries.entries()) {
    const parts = entry.signature.split(":");
    if (parts.length !== 2 || parts[0] !== "ed25519") {
      return { ok: false, error: `entry[${i}] signature format invalid` };
    }
    const sig = Buffer.from(parts[1], "base64");
    const signed = Buffer.from(entry.hash, "utf8");
    const valid = edVerify(null, signed, pubKey, sig);
    if (!valid) {
      return { ok: false, error: `signature invalid at entry[${i}]` };
    }
    ok++;
  }
  return { ok: true, count: ok };
}
