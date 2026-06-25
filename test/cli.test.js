/**
 * End-to-end CLI tests. Spawns the binary as a subprocess.
 *
 * Fully offline and deterministic: the published-key check reads the committed
 * keys document via --keys-file, and the TSA check reads the committed local CA
 * via --ca-file. openssl must be on PATH for the full-verify tests.
 */

import { spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const here = dirname(fileURLToPath(import.meta.url));
const CLI = resolve(here, "..", "src", "cli.js");
const FIXTURES = resolve(here, "fixtures");
const KEYS = resolve(FIXTURES, "published-keys.json");
const CACERT = resolve(FIXTURES, "tsa-cacert.pem");
const fixture = (name) => resolve(FIXTURES, name);

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

describe("cli — meta", () => {
  it("prints help with --help", async () => {
    const r = await run(["--help"]);
    expect(r.code).toBe(0);
    expect(r.stdout).toMatch(/Usage:\s+hasp-verify/);
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
});

describe("cli — verification", () => {
  it("valid fixture, full pipeline offline (keys-file + ca-file) exits 0", async () => {
    const r = await run([fixture("valid.json"), "--keys-file", KEYS, "--ca-file", CACERT]);
    if (r.code !== 0) {
      console.error("STDOUT:", r.stdout);
      console.error("STDERR:", r.stderr);
    }
    expect(r.code).toBe(0);
    expect(r.stdout).toMatch(/published key matched/);
    expect(r.stdout).toMatch(/TSA anchor valid/);
    expect(r.stdout).toMatch(/VERIFIED\./);
  }, 30000);

  it("valid fixture --json reports every check ok", async () => {
    const r = await run([
      fixture("valid.json"),
      "--json",
      "--keys-file",
      KEYS,
      "--ca-file",
      CACERT,
    ]);
    expect(r.code).toBe(0);
    const parsed = JSON.parse(r.stdout);
    expect(parsed.ok).toBe(true);
    expect(parsed.checks.key.ok).toBe(true);
    expect(parsed.checks.signatures.ok).toBe(true);
    expect(parsed.checks.tsa.ok).toBe(true);
  }, 30000);

  it("--skip-tsa --skip-key-check exits 0 with warnings", async () => {
    const r = await run([fixture("valid.json"), "--skip-tsa", "--skip-key-check"]);
    expect(r.code).toBe(0);
    expect(r.stdout).toMatch(/published-key check skipped/);
    expect(r.stdout).toMatch(/TSA anchor check skipped/);
    expect(r.stdout).toMatch(/VERIFIED\./);
  });

  it("broken-schema exits 1", async () => {
    const r = await run([fixture("broken-schema.json"), "--skip-tsa", "--keys-file", KEYS]);
    expect(r.code).toBe(1);
    expect(r.stdout + r.stderr).toMatch(/schema_version|FAILED/i);
  });

  it("broken-chain exits 1", async () => {
    const r = await run([fixture("broken-chain.json"), "--skip-tsa", "--keys-file", KEYS]);
    expect(r.code).toBe(1);
    expect(r.stdout).toMatch(/FAILED/);
  });

  it("broken-key exits 1 (key mismatch)", async () => {
    const r = await run([fixture("broken-key.json"), "--skip-tsa", "--keys-file", KEYS]);
    expect(r.code).toBe(1);
    expect(r.stdout).toMatch(/does not match the published key/);
    expect(r.stdout).toMatch(/FAILED/);
  });

  it("broken-signature exits 1", async () => {
    const r = await run([fixture("broken-signature.json"), "--skip-tsa", "--keys-file", KEYS]);
    expect(r.code).toBe(1);
    expect(r.stdout).toMatch(/FAILED/);
  });

  it("broken-tsa exits 1 (full TSA path)", async () => {
    const r = await run([fixture("broken-tsa.json"), "--keys-file", KEYS, "--ca-file", CACERT]);
    expect(r.code).toBe(1);
    expect(r.stdout).toMatch(/FAILED/);
  }, 30000);

  it("reads export from stdin when file is '-'", async () => {
    const raw = readFileSync(fixture("valid.json"), "utf8");
    const r = await run(["-", "--skip-tsa", "--keys-file", KEYS], { stdin: raw });
    expect(r.code).toBe(0);
    expect(r.stdout).toMatch(/VERIFIED\./);
  });

  it("stdin with invalid JSON exits 2 with stdin in error message", async () => {
    const r = await run(["-", "--skip-tsa", "--skip-key-check"], { stdin: "not json" });
    expect(r.code).toBe(2);
    expect(r.stderr).toMatch(/stdin/);
  });

  it("--verbose on success prints Detail block with key fields", async () => {
    const r = await run([fixture("valid.json"), "--skip-tsa", "--keys-file", KEYS, "--verbose"]);
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
});

describe("cli — argument handling", () => {
  it("--ca-file requires an argument", async () => {
    const r = await run([fixture("valid.json"), "--ca-file"]);
    expect(r.code).toBe(2);
    expect(r.stderr).toMatch(/--ca-file requires an argument/);
  });

  it("--keys-file requires an argument", async () => {
    const r = await run([fixture("valid.json"), "--keys-file"]);
    expect(r.code).toBe(2);
    expect(r.stderr).toMatch(/--keys-file requires an argument/);
  });

  it("--keys-file with a missing file fails with exit 1 and a clear error", async () => {
    const r = await run([
      fixture("valid.json"),
      "--skip-tsa",
      "--keys-file",
      "/nonexistent/keys.json",
    ]);
    expect(r.code).toBe(1);
    expect(r.stdout + r.stderr).toMatch(/failed to read --keys-file/);
  });

  it("--ca-file with a missing file fails with exit 1 and a clear error", async () => {
    const r = await run([
      fixture("valid.json"),
      "--keys-file",
      KEYS,
      "--ca-file",
      "/nonexistent/ca-xyz.pem",
    ]);
    expect(r.code).toBe(1);
    expect(r.stdout + r.stderr).toMatch(/failed to read --ca-file/);
  });

  it("--keys-file=<path> form also parses", async () => {
    const r = await run([fixture("valid.json"), "--skip-tsa", `--keys-file=${KEYS}`]);
    expect(r.code).toBe(0);
    expect(r.stdout).toMatch(/VERIFIED\./);
  });

  it("rejects an empty --flag=value (exit 2) instead of fetching an empty URL", async () => {
    const r = await run([fixture("valid.json"), "--keys-url="]);
    expect(r.code).toBe(2);
    expect(r.stderr).toMatch(/--keys-url requires a non-empty argument/);
  });
});
