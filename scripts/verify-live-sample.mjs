#!/usr/bin/env node
/**
 * Download the LIVE published audit export and verify it through the full
 * pipeline — real published-key fetch, real chain recompute, real per-entry
 * Ed25519 signatures, and a real `openssl ts -verify` of the RFC 3161 anchor.
 * This is the local equivalent of the `real-world` GitHub workflow: it proves
 * the verifier still agrees with what the platform actually publishes today.
 *
 *   npm run verify:real
 *
 * Unlike the committed unit-test fixture (test/fixtures/valid.json — a locally
 * generated, self-issued-TSA export), the live sample is a real staging export
 * with a real freetsa token and a real published key. It is the cross-repo
 * consistency check: "the library verifies the published sample."
 *
 * Strict by design: a non-VERIFIED verdict or a download/openssl failure exits
 * non-zero.
 *
 * Env:
 *   SAMPLE_URL  overrides the export URL (defaults to the published sample).
 */
import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const SAMPLE_URL = process.env.SAMPLE_URL ?? "https://usehasp.com/trust/audit-export-sample.json";

console.log(`Downloading live published sample\n  ${SAMPLE_URL}`);
let res;
try {
  res = await fetch(SAMPLE_URL, { signal: AbortSignal.timeout(30_000) });
} catch (err) {
  fail(`download failed (is the site reachable?): ${err instanceof Error ? err.message : err}`);
}
if (!res.ok) fail(`download failed: HTTP ${res.status}`);
const body = await res.text();
console.log(`  ${Buffer.byteLength(body)} bytes\n`);

const dir = mkdtempSync(join(tmpdir(), "hasp-live-"));
const livePath = join(dir, "live-sample.json");
writeFileSync(livePath, body);

console.log("Verifying live sample (full pipeline: published key + TSA)…");
const r = spawnSync("node", [join(ROOT, "src", "cli.js"), livePath, "--verbose"], {
  stdio: "inherit",
});
if (r.status !== 0) process.exit(r.status ?? 1);

console.log("\n✓ live published sample VERIFIED.");

/** @param {string} m */
function fail(m) {
  console.error(`error: ${m}`);
  process.exit(1);
}
