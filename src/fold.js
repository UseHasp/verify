/**
 * The v2 history-commitment fold (anchor-v2 contract §1).
 *
 * `GENESIS` is 64 ASCII zero characters. Folding a sequence of row hashes
 * (each the entry's `integrity_hash`, in chain order — `created_at` asc, `id`
 * asc — per org) produces a single SHA-256 hex digest that commits to the
 * entire prefix: existence, content, order, and count of every folded row.
 *
 *   state_0 = GENESIS
 *   state_i = sha256_hex( ascii(state_{i-1}) || ascii(hash_i) )
 *
 * This mirrors the auditor's shell recipe exactly:
 *   state=$(printf '%s%s' "$state" "$hash" | sha256sum | cut -d' ' -f1)
 */
import { createHash } from "node:crypto";

/** 64 ASCII zero characters — the fold's starting state. */
export const GENESIS = "0".repeat(64);

/**
 * Fold a sequence of row hashes (in chain order) into the v2 history
 * commitment, starting from GENESIS (or an explicit prior state, for
 * incremental folding).
 *
 * @param {string[]} hashes lowercase-hex SHA-256 row hashes, in chain order
 * @param {string} [start] starting fold state (default GENESIS)
 * @returns {string} the resulting fold state, lowercase hex
 */
export function foldFrom(hashes, start = GENESIS) {
  let state = start;
  for (const hash of hashes) {
    state = createHash("sha256")
      .update(state + hash, "ascii")
      .digest("hex");
  }
  return state;
}
