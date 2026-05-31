#!/usr/bin/env node
/**
 * Real-world verification harness.
 *
 * Runs the actual verifier — by default the same `hasp-verify` bin a user gets
 * from npm — against a *live* published audit export, doing the *full* check
 * including the RFC 3161 TSA anchor (real `openssl ts -verify`, real network
 * fetch of the TSA CA cert). This is the signal that the library still works
 * end-to-end after a dependency bump, a Node upgrade, or generator drift on the
 * published sample — the things unit tests against static fixtures cannot see.
 *
 * The hard part is telling a *genuine regression* apart from a *third-party
 * outage*. usehasp.com or the TSA (freetsa.org) being briefly unreachable must
 * not be reported the same way as "the tool no longer verifies a valid export".
 * This script classifies the outcome and signals it through the exit code:
 *
 *   0   PASS         — VERIFIED.
 *   1   GENUINE_FAIL — a real verification failure (schema/chain/signature, or a
 *                      TSA result that is cryptographically wrong). Block.
 *   75  INFRA        — could not complete due to an apparent network / third-party
 *                      outage or environment problem. The caller decides whether
 *                      that blocks (see .github/workflows/real-world.yml: it warns
 *                      on PRs but hard-fails on scheduled / main runs so a
 *                      persistent outage — or a real failure masquerading as one —
 *                      never goes unnoticed).
 *
 * Usage:
 *   node scripts/real-world-verify.mjs [--url <u>] [--bin <path>] [--retries <n>] [--skip-tsa]
 *
 *   --url <u>       Export to fetch and verify.
 *                   Default: https://usehasp.com/trust/audit-export-sample.json
 *   --bin <path>    Run this executable (e.g. an installed node_modules/.bin/hasp-verify)
 *                   instead of `node src/cli.js`, so we exercise the packed artifact
 *                   exactly as `npx @usehasp/verify` would.
 *   --retries <n>   Download retry attempts before giving up. Default: 3.
 *   --skip-tsa      Skip the TSA anchor check (for local offline smoke only).
 */

import { execFile } from "node:child_process";
import { appendFileSync } from "node:fs";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

const CLI = new URL("../src/cli.js", import.meta.url).pathname;
const DEFAULT_URL = "https://usehasp.com/trust/audit-export-sample.json";

// Exit codes. 75 == EX_TEMPFAIL (sysexits.h) — "temporary failure, retry later".
const PASS = 0;
const GENUINE_FAIL = 1;
const INFRA = 75;

const FETCH_TIMEOUT_MS = 20_000;
const MAX_SAMPLE_BYTES = 5_000_000;
const BACKOFF_MS = [2_000, 4_000, 8_000];

// A failed TSA check whose message matches one of these is treated as an outage /
// environment problem, not a cryptographic regression. Everything else that fails
// is a genuine failure. The deterministic offline check in the workflow (real
// `openssl ts -verify` against the bundled CA cert) is the hard gate for actual
// crypto/openssl regressions, so classifying these as INFRA here cannot hide a
// real break — it only avoids blocking a PR on someone else's downtime.
const INFRA_PATTERNS = [
  /CA cert fetch failed: HTTP/i,
  /CA cert too large/i,
  /fetch failed/i,
  /\bnetwork\b/i,
  /timeout|timed out|ETIMEDOUT|AbortError/i,
  /ENOTFOUND|EAI_AGAIN|ECONNREFUSED|ECONNRESET|EHOSTUNREACH|ENETUNREACH/i,
  /socket hang up/i,
  /openssl/i, // a missing/broken openssl is an environment issue; the offline gate covers real openssl breakage
];

/** @param {string[]} argv */
function parseArgs(argv) {
  const out = { url: DEFAULT_URL, bin: null, retries: 3, skipTsa: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--url") out.url = req(argv, ++i, a);
    else if (a === "--bin") out.bin = req(argv, ++i, a);
    else if (a === "--retries") out.retries = Number(req(argv, ++i, a));
    else if (a === "--skip-tsa") out.skipTsa = true;
    else die(`unknown argument: ${a}`);
  }
  if (!Number.isInteger(out.retries) || out.retries < 0) die("--retries must be a non-negative integer");
  return out;
}

/** @param {string[]} argv @param {number} i @param {string} flag */
function req(argv, i, flag) {
  const v = argv[i];
  if (v === undefined) die(`${flag} requires a value`);
  return v;
}

/** @param {string} msg */
function die(msg) {
  process.stderr.write(`real-world-verify: ${msg}\n`);
  process.exit(2);
}

/** @param {number} ms */
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** @param {string} line */
function log(line) {
  process.stdout.write(`${line}\n`);
}

/**
 * GitHub Actions workflow-command annotation (no-op outside Actions).
 * @param {"notice"|"warning"|"error"} level
 * @param {string} msg
 */
function annotate(level, msg) {
  if (process.env.GITHUB_ACTIONS) process.stdout.write(`::${level}::${msg}\n`);
}

/** @param {string} md */
function summary(md) {
  const file = process.env.GITHUB_STEP_SUMMARY;
  if (file) {
    try {
      appendFileSync(file, `${md}\n`);
    } catch {
      // best-effort; never let summary writing change the verdict
    }
  }
}

/**
 * Download the export, retrying with exponential backoff. Throws after the last
 * attempt; the caller treats a download failure as INFRA.
 * @param {string} url
 * @param {number} retries
 * @returns {Promise<string>}
 */
async function fetchWithRetry(url, retries) {
  for (let attempt = 0; ; attempt++) {
    try {
      const res = await fetch(url, {
        signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
        headers: { accept: "application/json" },
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const buf = Buffer.from(await res.arrayBuffer());
      if (buf.byteLength > MAX_SAMPLE_BYTES) throw new Error("sample too large");
      return buf.toString("utf8");
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      if (attempt >= retries) throw new Error(`download failed after ${retries + 1} attempts: ${msg}`);
      const wait = BACKOFF_MS[Math.min(attempt, BACKOFF_MS.length - 1)];
      log(`  download attempt ${attempt + 1} failed (${msg}); retrying in ${wait / 1000}s`);
      await sleep(wait);
    }
  }
}

/**
 * Run the verifier (packed bin if --bin given, else `node src/cli.js`) with
 * `--json`, capturing exit code and output without throwing.
 * @param {string} file
 * @param {{bin: string|null, skipTsa: boolean}} opts
 * @returns {Promise<{code: number|string, stdout: string, stderr: string}>}
 */
async function runVerifier(file, { bin, skipTsa }) {
  const flags = [file, "--json"];
  if (skipTsa) flags.push("--skip-tsa");
  const cmd = bin ?? process.execPath;
  const args = bin ? flags : [CLI, ...flags];
  try {
    const { stdout, stderr } = await execFileAsync(cmd, args, { maxBuffer: 16 * 1024 * 1024 });
    return { code: 0, stdout, stderr };
  } catch (err) {
    // execFile rejects on non-zero exit (err.code = numeric exit) or on a spawn
    // failure (err.code = string like "ENOENT"). Normalise both.
    const e = /** @type {NodeJS.ErrnoException & {stdout?: string, stderr?: string}} */ (err);
    return {
      code: typeof e.code === "number" ? e.code : (e.code ?? "ERR"),
      stdout: e.stdout ?? "",
      stderr: e.stderr ?? (err instanceof Error ? err.message : String(err)),
    };
  }
}

/**
 * Map a verifier invocation to one of pass / fail / infra.
 * @param {{code: number|string, stdout: string, stderr: string}} r
 * @returns {{outcome: "pass"|"fail"|"infra", reason?: string}}
 */
function classify(r) {
  if (r.code === 0) return { outcome: "pass" };

  // Exit 2 = the verifier could not read/parse the file it was handed. Since we
  // just downloaded it, that points at a truncated/garbled download → infra.
  if (r.code === 2) {
    return { outcome: "infra", reason: oneLine(r.stderr) || "verifier exited 2 (unreadable export)" };
  }

  // Anything other than a clean numeric exit-1 (e.g. a spawn error / crash)
  // is an environment problem, not a verdict.
  if (r.code !== 1) {
    return { outcome: "infra", reason: oneLine(r.stderr) || `verifier exited ${r.code}` };
  }

  // Exit 1: either a structured FAILED verdict (JSON on stdout) or a thrown
  // error (e.g. the TSA CA-cert fetch rejected → "error: ..." on stderr).
  let json = null;
  try {
    json = JSON.parse(r.stdout);
  } catch {
    // no JSON → the verifier threw before producing a verdict (typically network)
  }
  if (!json || typeof json !== "object" || !json.checks) {
    return { outcome: "infra", reason: oneLine(r.stderr) || "verifier failed without a verdict" };
  }

  const failing = findFailingCheck(json.checks);
  const name = failing?.name ?? "unknown";
  const error = failing?.error ?? "verification failed";
  if (name === "tsa" && INFRA_PATTERNS.some((re) => re.test(error))) {
    return { outcome: "infra", reason: `tsa: ${error}` };
  }
  return { outcome: "fail", reason: `${name}: ${error}` };
}

/** @param {Record<string, any>} checks */
function findFailingCheck(checks) {
  for (const [name, c] of Object.entries(checks)) {
    if (c && c.ran && c.ok === false) return { name, error: c.error };
  }
  return null;
}

/** @param {string} s */
function oneLine(s) {
  return (s ?? "").trim().split("\n").join(" ");
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  log(`real-world verification`);
  log(`  source:   ${args.url}`);
  log(`  verifier: ${args.bin ? args.bin : `node ${CLI}`}`);
  log(`  tsa:      ${args.skipTsa ? "SKIPPED (--skip-tsa)" : "full (network + openssl)"}`);

  let sample;
  try {
    sample = await fetchWithRetry(args.url, args.retries);
  } catch (err) {
    const reason = err instanceof Error ? err.message : String(err);
    annotate("warning", `Could not download the live sample: ${reason}`);
    summary(`### Real-world verification — ⚠️ skipped (outage)\nCould not download \`${args.url}\`: ${reason}`);
    log(`\n⚠ INFRA: ${reason}`);
    return INFRA;
  }

  const dir = await mkdtemp(join(tmpdir(), "hasp-rw-"));
  const file = join(dir, "live-sample.json");
  await writeFile(file, sample);

  const result = await runVerifier(file, { bin: args.bin, skipTsa: args.skipTsa });
  const verdict = classify(result);

  if (verdict.outcome === "pass") {
    annotate("notice", `Real-world verification PASSED against ${args.url}`);
    summary(`### Real-world verification — ✅ VERIFIED\nLive sample \`${args.url}\` passed all checks${args.skipTsa ? " (TSA skipped)" : " including the live RFC 3161 TSA anchor"}.`);
    log(`\n✓ PASS — live sample VERIFIED.`);
    return PASS;
  }

  if (verdict.outcome === "infra") {
    annotate("warning", `Real-world verification could not complete (apparent outage): ${verdict.reason}`);
    summary(`### Real-world verification — ⚠️ skipped (outage)\n\`${verdict.reason}\``);
    log(`\n⚠ INFRA: ${verdict.reason}`);
    return INFRA;
  }

  // genuine failure — surface the full report for debugging
  annotate("error", `Real-world verification FAILED: ${verdict.reason}`);
  summary(`### Real-world verification — ❌ FAILED\nThe published tool no longer verifies the live sample.\n\n\`\`\`\n${verdict.reason}\n\`\`\``);
  log(`\n✗ FAIL — ${verdict.reason}`);
  if (result.stdout.trim()) log(`\n${result.stdout.trim()}`);
  if (result.stderr.trim()) log(`\n${result.stderr.trim()}`);
  return GENUINE_FAIL;
}

main().then(
  (code) => process.exit(code),
  (err) => {
    // An unexpected crash in the harness itself is an infra problem, not a verdict.
    process.stderr.write(`real-world-verify: internal error: ${err?.stack ?? err}\n`);
    process.exit(INFRA);
  },
);
