/**
 * Fixed-width Merkle inclusion recomputation for batched segment anchors.
 *
 * Every node is `sha256_hex( ascii(left_hex) || ascii(right_hex) )` — the
 * same ASCII-hex convention as the history fold (`fold.js`), so the auditor's
 * shell recipe stays a one-liner per step:
 *
 *   state=$(printf '%s%s' "$left" "$right" | sha256sum | cut -d' ' -f1)
 *
 * An inclusion path is the bottom-up list of sibling hashes, each tagged with
 * the side the SIBLING sits on. The platform pads every batch to a fixed
 * leaf width (pad leaf = 64 ASCII zeros), so path depth is constant per batch
 * and does not disclose how many segments were live in it.
 */
import { createHash } from "node:crypto";

/**
 * Recompute the batch root from a leaf and its inclusion path.
 *
 * @param {string} leaf lowercase-hex leaf value (a segment fold state)
 * @param {Array<{position: "left" | "right", hash: string}>} path
 * @returns {string} the recomputed root, lowercase hex
 */
export function rootFromPath(leaf, path) {
  let state = leaf;
  for (const step of path) {
    const pair = step.position === "left" ? step.hash + state : state + step.hash;
    state = createHash("sha256").update(pair, "ascii").digest("hex");
  }
  return state;
}
