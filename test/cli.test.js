/**
 * End-to-end CLI tests. Spawns the binary as a subprocess.
 *
 * The committed fixture carries a PLACEHOLDER RFC 3161 token (freetsa.org is
 * egress-blocked where the real-crypto fixture is minted), so the live
 * `openssl ts -verify` path cannot pass against it and is not exercised here —
 * the TSA path is covered by the mocked unit tests in test/tsa.test.js. These
 * subprocess tests drive the schema/chain/signature pipeline (`--skip-tsa`),
 * argument handling, stdin, and the CA-file plumbing up to the point it reads
 * the cert.
 */

import { spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const here = dirname(fileURLToPath(import.meta.url));
const CLI = resolve(here, "..", "src", "cli.js");
const FIXTURES = resolve(here, "fixtures");
// Offline published-key trust root for the throwaway sample tenant.
const KEYS = resolve(FIXTURES, "published-keys.json");
// Offline trust root for the anchor-v2 fixture family (test/fixtures/build-v2.js).
const KEYS_V2 = resolve(FIXTURES, "published-keys-v2.json");
// Offline trust root for the multi-key fixture family (test/fixtures/build-multikey.js).
const KEYS_MULTIKEY = resolve(FIXTURES, "published-keys-multikey.json");

function run(args, { env = {}, stdin } = {}) {
  return new Promise((res) => {
    const proc = spawn(process.execPath, [CLI, ...args], {
      env: { ...process.env, ...env },
      stdio: ["pipe", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    proc.stdout.on("data", (c) => (stdout += c));
    proc.stderr.on("data", (c) => (stderr += c));
    proc.on("close", (code) => res({ code, stdout, stderr }));
    if (stdin !== undefined) {
      proc.stdin.write(stdin);
    }
    proc.stdin.end();
  });
}

describe("cli", () => {
  it("prints help with --help", async () => {
    const r = await run(["--help"]);
    expect(r.code).toBe(0);
    expect(r.stdout).toMatch(/Usage:\s+hasp-verify/);
    expect(r.stdout).toMatch(/--allow-unanchored/);
  });

  it("prints version with --version", async () => {
    const r = await run(["--version"]);
    expect(r.code).toBe(0);
    expect(r.stdout.trim()).toMatch(/^\d+\.\d+\.\d+$/);
  });

  it("usage error (exit 2) when no file", async () => {
    const r = await run([]);
    expect(r.code).toBe(2);
    expect(r.stderr).toMatch(/missing required argument/);
  });

  it("usage error (exit 2) when file missing", async () => {
    const r = await run(["./nope-does-not-exist.json"]);
    expect(r.code).toBe(2);
    expect(r.stderr).toMatch(/could not read/);
  });

  it("valid fixture with --skip-tsa exits 0 and prints VERIFIED", async () => {
    const r = await run([resolve(FIXTURES, "valid.json"), "--skip-tsa", "--keys-file", KEYS]);
    expect(r.code).toBe(0);
    expect(r.stdout).toMatch(/VERIFIED\./);
    expect(r.stdout).toMatch(/published key matches/);
  });

  it("valid fixture with --json --skip-tsa returns ok:true", async () => {
    const r = await run([
      resolve(FIXTURES, "valid.json"),
      "--json",
      "--skip-tsa",
      "--keys-file",
      KEYS,
    ]);
    expect(r.code).toBe(0);
    const parsed = JSON.parse(r.stdout);
    expect(parsed.ok).toBe(true);
    expect(parsed.checks.publishedKey.ok).toBe(true);
    expect(parsed.checks.tsa.skipped).toBe(true);
  });

  it("without --keys-file the sample's throwaway tenant can't be resolved (exit 1)", async () => {
    // No offline key source and no reachable /trust/keys for the throwaway
    // tenant → the published-key trust root can't be established, so it fails
    // closed. Inject an unreachable base URL so the test never touches network.
    const r = await run([
      resolve(FIXTURES, "valid.json"),
      "--skip-tsa",
      "--keys-base-url",
      "http://127.0.0.1:1",
    ]);
    expect(r.code).toBe(1);
    expect(r.stdout).toMatch(/FAILED/);
    expect(r.stdout).toMatch(/published key/i);
  });

  it("lineage-reset export verifies (exit 0) but prints a loud CHAIN LINEAGE WAS RESET warning", async () => {
    const r = await run([
      resolve(FIXTURES, "lineage-reset-v2.json"),
      "--skip-tsa",
      "--keys-file",
      KEYS_V2,
    ]);
    expect(r.code).toBe(0);
    expect(r.stdout).toMatch(/VERIFIED\./);
    expect(r.stdout).toMatch(/CHAIN LINEAGE WAS RESET at 2026-07-19T12:00:00\+00:00/);
    expect(r.stdout).toMatch(/cannot be verified from this export/);
  });

  it("lineage-reset export surfaces lineage_reset_at in --json output", async () => {
    const r = await run([
      resolve(FIXTURES, "lineage-reset-v2.json"),
      "--json",
      "--skip-tsa",
      "--keys-file",
      KEYS_V2,
    ]);
    expect(r.code).toBe(0);
    const parsed = JSON.parse(r.stdout);
    expect(parsed.ok).toBe(true);
    expect(parsed.lineage_reset_at).toBe("2026-07-19T12:00:00+00:00");
  });

  it("broken-schema exits 1", async () => {
    const r = await run([resolve(FIXTURES, "broken-schema.json"), "--skip-tsa"]);
    expect(r.code).toBe(1);
    expect(r.stdout + r.stderr).toMatch(/schema_version|FAILED/i);
  });

  it("broken-chain exits 1", async () => {
    const r = await run([resolve(FIXTURES, "broken-chain.json"), "--skip-tsa"]);
    expect(r.code).toBe(1);
    expect(r.stdout).toMatch(/FAILED/);
  });

  it("broken-signature exits 1", async () => {
    const r = await run([
      resolve(FIXTURES, "broken-signature.json"),
      "--skip-tsa",
      "--keys-file",
      KEYS,
    ]);
    expect(r.code).toBe(1);
    expect(r.stdout).toMatch(/FAILED/);
  });

  it("reads export from stdin when file is '-'", async () => {
    const raw = readFileSync(resolve(FIXTURES, "valid.json"), "utf8");
    const r = await run(["-", "--skip-tsa", "--keys-file", KEYS], { stdin: raw });
    expect(r.code).toBe(0);
    expect(r.stdout).toMatch(/VERIFIED\./);
  });

  it("stdin with invalid JSON exits 2 with stdin in error message", async () => {
    const r = await run(["-", "--skip-tsa"], { stdin: "not json" });
    expect(r.code).toBe(2);
    expect(r.stderr).toMatch(/stdin/);
  });

  it("--verbose on success prints Detail block with key fields", async () => {
    const r = await run([
      resolve(FIXTURES, "valid.json"),
      "--skip-tsa",
      "--verbose",
      "--keys-file",
      KEYS,
    ]);
    expect(r.code).toBe(0);
    expect(r.stdout).toMatch(/VERIFIED\./);
    expect(r.stdout).toMatch(/Detail:/);
    expect(r.stdout).toMatch(/schema_version:/);
    expect(r.stdout).toMatch(/tenant_id:/);
    expect(r.stdout).toMatch(/range:/);
    expect(r.stdout).toMatch(/entries:\s+\d+/);
    expect(r.stdout).toMatch(/key_id:/);
    expect(r.stdout).toMatch(/anchors:\s+\d+/);
  });

  it("--ca-file requires an argument", async () => {
    const r = await run([resolve(FIXTURES, "valid.json"), "--ca-file"]);
    expect(r.code).toBe(2);
    expect(r.stderr).toMatch(/--ca-file requires a path/);
  });

  it("--ca-file with a missing file fails with exit 1 and a clear error", async () => {
    const r = await run([
      resolve(FIXTURES, "valid.json"),
      "--keys-file",
      KEYS,
      "--ca-file",
      "/nonexistent/ca-xyz.pem",
    ]);
    expect(r.code).toBe(1);
    expect(r.stdout + r.stderr).toMatch(/failed to read --ca-file/);
  });

  it("--ca-file=<path> form also parses", async () => {
    const r = await run([
      resolve(FIXTURES, "valid.json"),
      "--keys-file",
      KEYS,
      `--ca-file=/nonexistent/ca-xyz.pem`,
    ]);
    expect(r.code).toBe(1);
    expect(r.stdout + r.stderr).toMatch(/failed to read --ca-file/);
  });

  it("--keys-file with a missing file fails with a clear error", async () => {
    const r = await run([
      resolve(FIXTURES, "valid.json"),
      "--skip-tsa",
      "--keys-file",
      "/nonexistent/keys-xyz.json",
    ]);
    expect(r.code).toBe(1);
    expect(r.stdout + r.stderr).toMatch(/failed to read --keys-file/);
  });

  it("valid-multikey fixture (rotation-spanning export) exits 0 and reports every key", async () => {
    const r = await run([
      resolve(FIXTURES, "valid-multikey.json"),
      "--skip-tsa",
      "--keys-file",
      KEYS_MULTIKEY,
      "--verbose",
    ]);
    expect(r.code).toBe(0);
    expect(r.stdout).toMatch(/VERIFIED\./);
    expect(r.stdout).toMatch(/published keys match \(2 keys:/);
    expect(r.stdout).toMatch(/keys:\s+2 \(/);
  });

  it("wrong-entry-key fixture exits 1 — signature check fails closed on a mismatched per-entry key", async () => {
    const r = await run([
      resolve(FIXTURES, "wrong-entry-key.json"),
      "--skip-tsa",
      "--keys-file",
      KEYS_MULTIKEY,
    ]);
    expect(r.code).toBe(1);
    expect(r.stdout).toMatch(/FAILED/);
    expect(r.stdout).toMatch(/signature invalid/);
  });

  it("tampered-attribution fixture exits 1 — chain check fails on a tampered caller_attribution", async () => {
    const r = await run([
      resolve(FIXTURES, "tampered-attribution.json"),
      "--skip-tsa",
      "--keys-file",
      KEYS_MULTIKEY,
    ]);
    expect(r.code).toBe(1);
    expect(r.stdout).toMatch(/FAILED/);
    expect(r.stdout).toMatch(/chain broken/);
  });

  it("valid-v2 fixture (two sha256-fold-v2 anchors) exits 0 with full-coverage output", async () => {
    const r = await run([resolve(FIXTURES, "valid-v2.json"), "--skip-tsa", "--keys-file", KEYS_V2]);
    expect(r.code).toBe(0);
    expect(r.stdout).toMatch(/VERIFIED\./);
    expect(r.stdout).toMatch(/time-attested/);
    expect(r.stdout).toMatch(/entries 1\.\.4 time-attested/);
  });

  it("insider-rewrite fixture exits 1 — anchoring fails even though chain and signatures pass", async () => {
    const r = await run([
      resolve(FIXTURES, "insider-rewrite.json"),
      "--skip-tsa",
      "--keys-file",
      KEYS_V2,
    ]);
    expect(r.code).toBe(1);
    expect(r.stdout).toMatch(/FAILED/);
    expect(r.stdout).toMatch(/fold mismatch/);
    expect(r.stdout).toMatch(/chain intact/); // chain check passed and printed
    expect(r.stdout).toMatch(/signatures verified/); // signature check passed and printed
  });

  it("purge-rebased-v2 exits 0 but prints a loud RETENTION PURGE warning naming fold_base", async () => {
    const r = await run([
      resolve(FIXTURES, "purge-rebased-v2.json"),
      "--skip-tsa",
      "--keys-file",
      KEYS_V2,
    ]);
    expect(r.code).toBe(0);
    expect(r.stdout).toMatch(/VERIFIED\./);
    const fixture = JSON.parse(readFileSync(resolve(FIXTURES, "purge-rebased-v2.json"), "utf8"));
    expect(r.stdout).toMatch(/⚠ RETENTION PURGE/);
    expect(r.stdout).toContain(fixture.verification.fold_base);
  });

  it("unattested-tail-v2 exits 0 but prints a prominent unanchored-tail warning naming the first unattested seq", async () => {
    const r = await run([
      resolve(FIXTURES, "unattested-tail-v2.json"),
      "--skip-tsa",
      "--keys-file",
      KEYS_V2,
    ]);
    expect(r.code).toBe(0);
    expect(r.stdout).toMatch(/VERIFIED\./);
    expect(r.stdout).toMatch(/⚠ UNANCHORED TAIL: entries 3\.\.4/);
  });

  it("no-anchors fixture exits 1 without --allow-unanchored, 0 with it", async () => {
    const withoutFlag = await run([
      resolve(FIXTURES, "no-anchors.json"),
      "--skip-tsa",
      "--keys-file",
      KEYS_V2,
    ]);
    expect(withoutFlag.code).toBe(1);
    expect(withoutFlag.stdout).toMatch(/not time-attested/);

    const withFlag = await run([
      resolve(FIXTURES, "no-anchors.json"),
      "--skip-tsa",
      "--allow-unanchored",
      "--keys-file",
      KEYS_V2,
    ]);
    expect(withFlag.code).toBe(0);
    expect(withFlag.stdout).toMatch(/VERIFIED\./);
    expect(withFlag.stdout).toMatch(/not time-attested \(allowed via --allow-unanchored\)/);
  });
});
