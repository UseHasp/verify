/**
 * Check 2: per-entry Ed25519 signatures.
 *
 * Each entry's `signature` field is "ed25519:<base64>". The signed payload
 * is the canonical entry minus `hash` and `signature`. Verified against the
 * Ed25519 public key in `verification.public_key_pem` (PEM SPKI).
 */
import { createPublicKey, verify as edVerify } from "node:crypto";
import { canonicalSorted } from "../canonical.js";

/**
 * @param {{entries: any[], verification: {public_key_pem: string}}} data
 * @returns {{ok: true, count: number} | {ok: false, error: string}}
 */
export function checkSignatures(data) {
  let pubKey;
  try {
    pubKey = createPublicKey(data.verification.public_key_pem);
  } catch (err) {
    return { ok: false, error: `invalid public_key_pem: ${errMessage(err)}` };
  }

  let ok = 0;
  for (const entry of data.entries) {
    const { hash, signature, ...rest } = entry;
    void hash;
    const parts = signature.split(":");
    if (parts.length !== 2 || parts[0] !== "ed25519") {
      return { ok: false, error: `entry seq=${entry.seq} signature format invalid` };
    }
    const sig = Buffer.from(parts[1], "base64");
    const payload = Buffer.from(canonicalSorted(rest), "utf8");
    const valid = edVerify(null, payload, pubKey, sig);
    if (!valid) {
      return { ok: false, error: `signature invalid at seq=${entry.seq}` };
    }
    ok++;
  }
  return { ok: true, count: ok };
}

/** @param {unknown} err */
function errMessage(err) {
  return err instanceof Error ? err.message : String(err);
}
