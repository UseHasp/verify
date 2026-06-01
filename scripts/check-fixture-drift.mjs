#!/usr/bin/env node
/**
 * Drift guard.
 *
 * The committed fixture (test/fixtures/valid.json) is supposed to be a copy of
 * the live published sample at usehasp.com/trust/audit-export-sample.json. If
 * the platform changes how it generates exports, the live sample changes but
 * the committed copy does not — and every fixture-based test keeps passing
 * while real exports may have stopped verifying. This script fails loudly when
 * the two diverge so the copy can't silently rot.
 *
 * Comparison is structural (parsed JSON, deep-equal), not byte-for-byte, so
 * cosmetic formatting differences (indentation, key order, trailing newline)
 * don't cause false alarms — only a genuine content difference does. On a
 * mismatch it prints the diverging field paths.
 *
 * Usage: node scripts/check-fixture-drift.mjs <live.json> <fixture.json>
 * Exit:  0 in sync · 1 drifted · 2 usage / unreadable input
 */
import { readFileSync } from "node:fs";

const [livePath, fixturePath] = process.argv.slice(2);
if (!livePath || !fixturePath) {
  process.stderr.write("usage: check-fixture-drift.mjs <live.json> <fixture.json>\n");
  process.exit(2);
}

const live = readJson(livePath, "live sample");
const fixture = readJson(fixturePath, "committed fixture");

const diffs = [];
collectDiffs(live, fixture, "", diffs);

if (diffs.length === 0) {
  process.stdout.write(`✓ committed fixture is in sync with the live published sample\n`);
  process.exit(0);
}

process.stderr.write(
  `✗ committed fixture has DRIFTED from the live published sample (${diffs.length} difference${
    diffs.length === 1 ? "" : "s"
  }).\n\n` +
    `  live:    ${livePath}\n` +
    `  fixture: ${fixturePath}\n\n` +
    `The platform's published sample no longer matches the copy in this repo.\n` +
    `Update the fixture from the live sample (and regenerate the broken-*.json\n` +
    `fixtures via test/fixtures/build-broken.js), then re-run.\n\n` +
    `Diverging fields:\n`,
);
for (const d of diffs.slice(0, 50)) {
  process.stderr.write(`  • ${d}\n`);
}
if (diffs.length > 50) process.stderr.write(`  … and ${diffs.length - 50} more\n`);
process.exit(1);

/**
 * @param {string} path
 * @param {string} label
 * @returns {unknown}
 */
function readJson(path, label) {
  let raw;
  try {
    raw = readFileSync(path, "utf8");
  } catch (err) {
    process.stderr.write(`error: could not read ${label} (${path}): ${msg(err)}\n`);
    process.exit(2);
  }
  try {
    return JSON.parse(raw);
  } catch (err) {
    process.stderr.write(`error: ${label} (${path}) is not valid JSON: ${msg(err)}\n`);
    process.exit(2);
  }
}

/**
 * Walk two parsed values in parallel and record the paths where they differ.
 * @param {unknown} a live value
 * @param {unknown} b fixture value
 * @param {string} path dotted path to the current node
 * @param {string[]} out accumulator
 */
function collectDiffs(a, b, path, out) {
  const here = path || "(root)";
  if (a === b) return;

  const ta = kind(a);
  const tb = kind(b);
  if (ta !== tb) {
    out.push(`${here}: type differs (live=${ta}, fixture=${tb})`);
    return;
  }

  if (ta === "array") {
    const aa = /** @type {unknown[]} */ (a);
    const bb = /** @type {unknown[]} */ (b);
    if (aa.length !== bb.length) {
      out.push(`${here}: array length differs (live=${aa.length}, fixture=${bb.length})`);
    }
    const n = Math.max(aa.length, bb.length);
    for (let i = 0; i < n; i++) collectDiffs(aa[i], bb[i], `${path}[${i}]`, out);
    return;
  }

  if (ta === "object") {
    const ao = /** @type {Record<string, unknown>} */ (a);
    const bo = /** @type {Record<string, unknown>} */ (b);
    const keys = new Set([...Object.keys(ao), ...Object.keys(bo)]);
    for (const k of keys) {
      const child = path ? `${path}.${k}` : k;
      if (!(k in ao)) out.push(`${child}: present in fixture, missing from live`);
      else if (!(k in bo)) out.push(`${child}: present in live, missing from fixture`);
      else collectDiffs(ao[k], bo[k], child, out);
    }
    return;
  }

  // primitives that aren't ===
  out.push(`${here}: value differs (live=${preview(a)}, fixture=${preview(b)})`);
}

/** @param {unknown} v */
function kind(v) {
  if (v === null) return "null";
  if (Array.isArray(v)) return "array";
  return typeof v;
}

/** @param {unknown} v */
function preview(v) {
  const s = typeof v === "string" ? v : JSON.stringify(v);
  return s.length > 80 ? `${s.slice(0, 77)}…` : s;
}

/** @param {unknown} err */
function msg(err) {
  return err instanceof Error ? err.message : String(err);
}
