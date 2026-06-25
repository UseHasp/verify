/**
 * Check: per-entry Ed25519 signatures.
 *
 * Each entry's `signature` is `"ed25519:" + base64(rawSig)`, where `rawSig` is a
 * detached Ed25519 signature over the entry's `hash` HEX STRING (the ASCII
 * characters of the 64-char hex digest — NOT the raw 32 hash bytes). It is
 * verified against the trusted public key.
 *
 * The trusted key is the one matched by the published-key check
 * (checks/key.js). When that check is skipped (`--skip-key-check`), the caller
 * falls back to the export's embedded `verification.public_key_pem`, whose
 * provenance is then unconfirmed.
 *
 * The chain check has already confirmed that each `hash` is the correct
 * integrity hash of the entry, so signing the hash transitively signs the
 * entry's contents.
 */
import { createPublicKey, verify as edVerify } from "node:crypto";

/**
 * @param {{entries: any[]}} data
 * @param {string} publicKeyPem the trusted Ed25519 public key (PEM SPKI)
 * @returns {{ok: true, count: number} | {ok: false, error: string}}
 */
export function checkSignatures(data, publicKeyPem) {
  let pubKey;
  try {
    pubKey = createPublicKey(publicKeyPem);
  } catch (err) {
    return { ok: false, error: `invalid public key: ${errMessage(err)}` };
  }
  if (pubKey.asymmetricKeyType !== "ed25519") {
    return { ok: false, error: `public key is not Ed25519 (got ${pubKey.asymmetricKeyType})` };
  }

  let ok = 0;
  for (const [i, entry] of data.entries.entries()) {
    const parts = entry.signature.split(":");
    if (parts.length !== 2 || parts[0] !== "ed25519") {
      return {
        ok: false,
        error: `entry ${i + 1} signature format invalid (expected "ed25519:<base64>")`,
      };
    }
    const sig = Buffer.from(parts[1], "base64");
    // Signed message is the hash hex string, not the raw digest bytes.
    const message = Buffer.from(entry.hash, "utf8");
    if (!edVerify(null, message, pubKey, sig)) {
      return { ok: false, error: `signature invalid at entry ${i + 1}` };
    }
    ok++;
  }
  return { ok: true, count: ok };
}

/** @param {unknown} err */
function errMessage(err) {
  return err instanceof Error ? err.message : String(err);
}
