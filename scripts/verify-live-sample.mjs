#!/usr/bin/env node
/**
 * Download the LIVE published audit export and verify it through the full
 * pipeline (real TSA fetch + `openssl ts -verify`), then assert the committed
 * fixture still matches it. This is the local equivalent of the `real-world`
 * GitHub workflow — run it before merging a dependency bump to confirm the tool
 * still verifies what the platform actually publishes today.
 *
 *   npm run verify:real
 *
 * Strict by design: a non-VERIFIED verdict, a download/openssl failure, or a
 * drifted fixture all exit non-zero.
 *
 * Env: SAMPLE_URL overrides the export URL (defaults to the published sample).
 *      KEYS_URL overrides the published-keys document URL.
 */
import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const SAMPLE_URL = process.env.SAMPLE_URL ?? "https://usehasp.com/trust/audit-export-sample.json";
// The sample's tenant is a throwaway seeded inside a rolled-back mint
// transaction (AuditGenerateSampleCommand) — it has no live /trust/keys
// endpoint, so the published-key check needs the co-published keys doc.
const KEYS_URL = process.env.KEYS_URL ?? "https://usehasp.com/.well-known/audit-keys.json";
const FIXTURE = join(ROOT, "test", "fixtures", "valid.json");

const dir = mkdtempSync(join(tmpdir(), "hasp-live-"));
const livePath = join(dir, "live-sample.json");
writeFileSync(livePath, await download(SAMPLE_URL, "live published sample"));
const keysPath = join(dir, "live-keys.json");
writeFileSync(keysPath, await download(KEYS_URL, "live published keys"));

console.log("Verifying live sample (full TSA path)…");
run("node", [join(ROOT, "src", "cli.js"), livePath, "--keys-file", keysPath, "--verbose"]);

console.log("\nChecking committed fixture is in sync with the live sample…");
run("node", [join(ROOT, "scripts", "check-fixture-drift.mjs"), livePath, FIXTURE]);

console.log("\n✓ live sample VERIFIED and committed fixture is in sync.");

/**
 * @param {string} cmd
 * @param {string[]} args
 */
function run(cmd, args) {
  const r = spawnSync(cmd, args, { stdio: "inherit" });
  if (r.status !== 0) process.exit(r.status ?? 1);
}

/** @param {string} m */
function fail(m) {
  console.error(`error: ${m}`);
  process.exit(1);
}

/**
 * @param {string} url
 * @param {string} label
 * @returns {Promise<string>}
 */
async function download(url, label) {
  console.log(`Downloading ${label}\n  ${url}`);
  let res;
  try {
    res = await fetch(url, { signal: AbortSignal.timeout(30_000) });
  } catch (err) {
    fail(`download failed (is the site reachable?): ${err instanceof Error ? err.message : err}`);
  }
  if (!res.ok) fail(`download failed: HTTP ${res.status}`);
  const body = await res.text();
  console.log(`  ${Buffer.byteLength(body)} bytes\n`);
  return body;
}
