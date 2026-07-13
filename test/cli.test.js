/**
 * End-to-end CLI tests. Spawns the binary as a subprocess.
 *
 * Fully offline: the published key is supplied with --key-file and the TSA CA
 * cert with --ca-file, so no test needs network. openssl must be on PATH for
 * the TSA-path tests (skipped if not).
 */

import { execFileSync, spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { beforeAll, describe, expect, it } from "vitest";
import { CA_FILE, fixture, PUBLISHED_KEY_FILE } from "./helpers.js";

const here = dirname(fileURLToPath(import.meta.url));
const CLI = resolve(here, "..", "src", "cli.js");

const KEY = ["--key-file", PUBLISHED_KEY_FILE];
const CA = ["--ca-file", CA_FILE];

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
    if (stdin !== undefined) proc.stdin.write(stdin);
    proc.stdin.end();
  });
}

let hasOpenssl = false;
beforeAll(() => {
  try {
    execFileSync("openssl", ["version"], { stdio: "ignore" });
    hasOpenssl = true;
  } catch {
    hasOpenssl = false;
  }
});

describe("cli", () => {
  it("prints help with --help (documents new flags)", async () => {
    const r = await run(["--help"]);
    expect(r.code).toBe(0);
    expect(r.stdout).toMatch(/Usage:\s+hasp-verify/);
    expect(r.stdout).toMatch(/--key-file/);
    expect(r.stdout).toMatch(/--keys-url/);
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
    const r = await run([fixture("valid.json"), "--skip-tsa", ...KEY]);
    expect(r.code).toBe(0);
    expect(r.stdout).toMatch(/VERIFIED\./);
    expect(r.stdout).toMatch(/published key matched/);
  });

  it("valid fixture with --json --skip-tsa returns ok:true", async () => {
    const r = await run([fixture("valid.json"), "--json", "--skip-tsa", ...KEY]);
    expect(r.code).toBe(0);
    const parsed = JSON.parse(r.stdout);
    expect(parsed.ok).toBe(true);
    expect(parsed.checks.publishedKey.ok).toBe(true);
    expect(parsed.checks.tsa.skipped).toBe(true);
  });

  it("broken-hash exits 1", async () => {
    const r = await run([fixture("broken-hash.json"), "--skip-tsa", ...KEY]);
    expect(r.code).toBe(1);
    expect(r.stdout).toMatch(/FAILED/);
  });

  it("broken-chain exits 1", async () => {
    const r = await run([fixture("broken-chain.json"), "--skip-tsa", ...KEY]);
    expect(r.code).toBe(1);
    expect(r.stdout).toMatch(/FAILED/);
  });

  it("broken-signature exits 1", async () => {
    const r = await run([fixture("broken-signature.json"), "--skip-tsa", ...KEY]);
    expect(r.code).toBe(1);
    expect(r.stdout).toMatch(/FAILED/);
  });

  it("forged-chain exits 1 and reports the published-key mismatch", async () => {
    const r = await run([fixture("forged-chain.json"), "--skip-tsa", ...KEY]);
    expect(r.code).toBe(1);
    expect(r.stdout).toMatch(/FAILED/);
    expect(r.stdout + r.stderr).toMatch(/does not match the published key/);
  });

  it("valid fixture full verify (offline key + local CA) exits 0", async () => {
    if (!hasOpenssl) return;
    const r = await run([fixture("valid.json"), ...KEY, ...CA]);
    if (r.code !== 0) {
      console.error("STDOUT:", r.stdout);
      console.error("STDERR:", r.stderr);
    }
    expect(r.code).toBe(0);
    expect(r.stdout).toMatch(/VERIFIED\./);
    expect(r.stdout).toMatch(/TSA anchor valid/);
  }, 30000);

  it("broken-tsa full verify exits 1", async () => {
    if (!hasOpenssl) return;
    const r = await run([fixture("broken-tsa.json"), ...KEY, ...CA]);
    expect(r.code).toBe(1);
    expect(r.stdout).toMatch(/FAILED/);
  }, 30000);

  it("reads export from stdin when file is '-'", async () => {
    const raw = readFileSync(fixture("valid.json"), "utf8");
    const r = await run(["-", "--skip-tsa", ...KEY], { stdin: raw });
    expect(r.code).toBe(0);
    expect(r.stdout).toMatch(/VERIFIED\./);
  });

  it("stdin with invalid JSON exits 2 with stdin in error message", async () => {
    const r = await run(["-", "--skip-tsa", ...KEY], { stdin: "not json" });
    expect(r.code).toBe(2);
    expect(r.stderr).toMatch(/stdin/);
  });

  it("--verbose on success prints Detail block with key fields", async () => {
    const r = await run([fixture("valid.json"), "--skip-tsa", "--verbose", ...KEY]);
    expect(r.code).toBe(0);
    expect(r.stdout).toMatch(/VERIFIED\./);
    expect(r.stdout).toMatch(/Detail:/);
    expect(r.stdout).toMatch(/schema_version:/);
    expect(r.stdout).toMatch(/tenant_id:/);
    expect(r.stdout).toMatch(/range:/);
    expect(r.stdout).toMatch(/entries:\s+\d+/);
    expect(r.stdout).toMatch(/key_id:/);
    expect(r.stdout).toMatch(/trust root:/);
    expect(r.stdout).toMatch(/anchors:\s+\d+/);
    // Old fields must be gone.
    expect(r.stdout).not.toMatch(/seq \d+ →/);
  });

  it("--ca-file requires an argument", async () => {
    const r = await run([fixture("valid.json"), "--ca-file"]);
    expect(r.code).toBe(2);
    expect(r.stderr).toMatch(/--ca-file requires a path/);
  });

  it("--key-file requires an argument", async () => {
    const r = await run([fixture("valid.json"), "--key-file"]);
    expect(r.code).toBe(2);
    expect(r.stderr).toMatch(/--key-file requires a path/);
  });

  it("--keys-url requires an argument", async () => {
    const r = await run([fixture("valid.json"), "--keys-url"]);
    expect(r.code).toBe(2);
    expect(r.stderr).toMatch(/--keys-url requires a URL/);
  });

  it("--key-file with a missing file fails closed (exit 1)", async () => {
    const r = await run([fixture("valid.json"), "--skip-tsa", "--key-file", "/nonexistent/k.pem"]);
    expect(r.code).toBe(1);
    expect(r.stdout + r.stderr).toMatch(/failed to read --key-file/);
  });

  it("--key-file=<path> form also parses", async () => {
    const r = await run([fixture("valid.json"), "--skip-tsa", `--key-file=${PUBLISHED_KEY_FILE}`]);
    expect(r.code).toBe(0);
    expect(r.stdout).toMatch(/VERIFIED\./);
  });

  it("--ca-file with a missing file fails with exit 1 and a clear error", async () => {
    const r = await run([fixture("valid.json"), ...KEY, "--ca-file", "/nonexistent/ca-xyz.pem"]);
    expect(r.code).toBe(1);
    expect(r.stdout + r.stderr).toMatch(/failed to read --ca-file/);
  });

  it("--ca-file with local TSA cert verifies offline (no network)", async () => {
    if (!hasOpenssl) return;
    const r = await run([fixture("valid.json"), ...KEY, ...CA]);
    if (r.code !== 0) {
      console.error("STDOUT:", r.stdout);
      console.error("STDERR:", r.stderr);
    }
    expect(r.code).toBe(0);
    expect(r.stdout).toMatch(/VERIFIED\./);
  }, 30000);
});
