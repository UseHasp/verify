#!/usr/bin/env node
/**
 * LOC-claim drift guard.
 *
 * README.md's "Auditable" bullet states two line counts: the cryptographic
 * primitives (merkle.js + fold.js + canonical.js + checks/chain.js +
 * checks/signature.js) and the total src/ size. Both are embedded as an
 * `<!-- verify:loc core=N total=M -->` marker immediately above the bullet.
 * This script recomputes both numbers from the actual source and fails if
 * either has drifted past the stated tolerance — the failure mode this
 * package exists to avoid: a trust claim nobody is watching.
 *
 * Usage: node scripts/check-readme-loc.mjs
 * Exit:  0 in sync · 1 drifted · 2 usage / unreadable input
 */
import { readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const README_PATH = join(ROOT, "README.md");

// The five files that implement the cryptographic primitives — the hash
// chain, the history fold, and the Ed25519 signature check. This is the
// smallest reviewable core, not the whole trust boundary: checks/published-
// key.js establishes the key these primitives verify against and is just as
// trust-critical, it's simply larger (network I/O, key-rotation handling)
// than pure computation.
const CORE_FILES = [
  "src/merkle.js",
  "src/fold.js",
  "src/canonical.js",
  "src/checks/chain.js",
  "src/checks/signature.js",
];

// Any single-line drift (e.g. a formatter adding/removing a trailing blank
// line) shouldn't fail the build; a real change to the claim should.
const TOLERANCE = 2;

const coreLoc = CORE_FILES.reduce((sum, rel) => sum + lineCount(join(ROOT, rel)), 0);
const totalLoc = listSrcJsFiles(join(ROOT, "src")).reduce((sum, abs) => sum + lineCount(abs), 0);

const readme = readFileSync(README_PATH, "utf8");
const match = readme.match(/<!--\s*verify:loc\s+core=(\d+)\s+total=(\d+)\s*-->/);
if (!match) {
  process.stderr.write(
    `error: README.md has no "<!-- verify:loc core=N total=M -->" marker above the Auditable bullet.\n`,
  );
  process.exit(2);
}
const claimedCore = Number(match[1]);
const claimedTotal = Number(match[2]);

const diffs = [];
if (Math.abs(claimedCore - coreLoc) > TOLERANCE) {
  diffs.push(
    `core: README claims ${claimedCore}, actual is ${coreLoc} (${CORE_FILES.join(" + ")})`,
  );
}
if (Math.abs(claimedTotal - totalLoc) > TOLERANCE) {
  diffs.push(`total: README claims ${claimedTotal}, actual src/ is ${totalLoc}`);
}

if (diffs.length === 0) {
  process.stdout.write(
    `✓ README's LOC claim is in sync (core=${coreLoc}, total=${totalLoc}, tolerance=${TOLERANCE})\n`,
  );
  process.exit(0);
}

process.stderr.write(
  `✗ README.md's auditability claim has DRIFTED from the measured source (tolerance=${TOLERANCE}).\n\n`,
);
for (const d of diffs) process.stderr.write(`  • ${d}\n`);
process.stderr.write(
  `\nUpdate the "<!-- verify:loc core=N total=M -->" marker and the prose it backs in README.md ` +
    `to match, or reduce src/ back down if the growth wasn't intentional.\n`,
);
process.exit(1);

/** @param {string} path @returns {number} */
function lineCount(path) {
  const text = readFileSync(path, "utf8");
  return text.length === 0 ? 0 : text.split("\n").length - (text.endsWith("\n") ? 1 : 0);
}

/**
 * .js files only — types.d.ts isn't "plain JS" and is excluded from the
 * claim, matching the README's "plain JS" framing.
 * @param {string} dir @returns {string[]} absolute paths, recursively
 */
function listSrcJsFiles(dir) {
  const out = [];
  for (const entry of readdirSync(dir)) {
    const abs = join(dir, entry);
    if (statSync(abs).isDirectory()) {
      out.push(...listSrcJsFiles(abs));
    } else if (entry.endsWith(".js")) {
      out.push(abs);
    }
  }
  return out;
}
