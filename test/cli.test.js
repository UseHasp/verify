/**
 * End-to-end CLI tests. Spawns the binary as a subprocess.
 *
 * TSA fixture (valid.json full verify, broken-tsa.json) requires network
 * + openssl. Marked skipIfOffline: skipped when freetsa.org is unreachable
 * (CI containers without outbound HTTPS).
 */

import { spawn } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { beforeAll, describe, expect, it } from "vitest";

const here = dirname(fileURLToPath(import.meta.url));
const CLI = resolve(here, "..", "src", "cli.js");
const FIXTURES = resolve(here, "fixtures");

function run(args, env = {}) {
  return new Promise((res) => {
    const proc = spawn(process.execPath, [CLI, ...args], {
      env: { ...process.env, ...env },
    });
    let stdout = "";
    let stderr = "";
    proc.stdout.on("data", (c) => (stdout += c));
    proc.stderr.on("data", (c) => (stderr += c));
    proc.on("close", (code) => res({ code, stdout, stderr }));
  });
}

let online = false;
beforeAll(async () => {
  try {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), 4000);
    const r = await fetch("https://freetsa.org/files/cacert.pem", { signal: ctrl.signal });
    clearTimeout(t);
    online = r.ok;
  } catch {
    online = false;
  }
});

describe("cli", () => {
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

  it("valid fixture with --skip-tsa exits 0 and prints VERIFIED", async () => {
    const r = await run([resolve(FIXTURES, "valid.json"), "--skip-tsa"]);
    expect(r.code).toBe(0);
    expect(r.stdout).toMatch(/VERIFIED\./);
  });

  it("valid fixture with --json --skip-tsa returns ok:true", async () => {
    const r = await run([resolve(FIXTURES, "valid.json"), "--json", "--skip-tsa"]);
    expect(r.code).toBe(0);
    const parsed = JSON.parse(r.stdout);
    expect(parsed.ok).toBe(true);
    expect(parsed.checks.tsa.skipped).toBe(true);
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
    const r = await run([resolve(FIXTURES, "broken-signature.json"), "--skip-tsa"]);
    expect(r.code).toBe(1);
    expect(r.stdout).toMatch(/FAILED/);
  });

  it("valid fixture full verify (TSA + network) exits 0", async () => {
    if (!online) return;
    const r = await run([resolve(FIXTURES, "valid.json")]);
    if (r.code !== 0) {
      // Surface stderr for diagnosis when this fails.
      console.error("STDOUT:", r.stdout);
      console.error("STDERR:", r.stderr);
    }
    expect(r.code).toBe(0);
    expect(r.stdout).toMatch(/VERIFIED\./);
  }, 30000);

  it("broken-tsa full verify exits 1", async () => {
    if (!online) return;
    const r = await run([resolve(FIXTURES, "broken-tsa.json")]);
    expect(r.code).toBe(1);
    expect(r.stdout).toMatch(/FAILED/);
  }, 30000);
});
