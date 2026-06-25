/**
 * Orchestrator tests for verifyExport: VERSION wiring, the offline check
 * pipeline (schema → chain → key → signatures), and skip semantics.
 *
 * The published-key check reads from a local keys file; the TSA check is
 * skipped here (covered end-to-end in tsa.test.js / cli.test.js).
 */
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { beforeAll, describe, expect, it } from "vitest";
import { VERSION, verifyExport } from "../src/verify.js";

const here = dirname(fileURLToPath(import.meta.url));
const FIXTURES = resolve(here, "fixtures");
const KEYS_FILE = resolve(FIXTURES, "published-keys.json");
const CA_FILE = resolve(FIXTURES, "tsa-cacert.pem");
const load = (name) => JSON.parse(readFileSync(resolve(FIXTURES, name), "utf8"));

let hasOpenssl = false;
beforeAll(() => {
  try {
    execFileSync("openssl", ["version"], { stdio: "ignore" });
    hasOpenssl = true;
  } catch {
    hasOpenssl = false;
  }
});

describe("VERSION", () => {
  it("matches package.json version (single source of truth)", () => {
    const pkg = JSON.parse(readFileSync(resolve(here, "..", "package.json"), "utf8"));
    expect(VERSION).toBe(pkg.version);
  });
});

describe("verifyExport — offline checks (TSA skipped)", () => {
  it("passes schema, chain, key, signatures on the valid sample", async () => {
    const r = await verifyExport(load("valid.json"), { skipTsa: true, keysFile: KEYS_FILE });
    expect(r.checks.schema.ok).toBe(true);
    expect(r.checks.chain.ok).toBe(true);
    expect(r.checks.key.ok).toBe(true);
    expect(r.checks.signatures.ok).toBe(true);
    expect(r.checks.tsa.skipped).toBe(true);
    expect(r.ok).toBe(true);
  });

  it("runs the full pipeline (key + TSA) offline via keysFile + caFile", async () => {
    if (!hasOpenssl) return;
    const r = await verifyExport(load("valid.json"), { keysFile: KEYS_FILE, caFile: CA_FILE });
    expect(r.checks.key.ok).toBe(true);
    expect(r.checks.tsa.ok).toBe(true);
    expect(r.checks.tsa.anchors).toHaveLength(1);
    expect(r.ok).toBe(true);
  }, 30000);

  it("propagates a TSA failure (tampered TSR) through the orchestrator", async () => {
    if (!hasOpenssl) return;
    const r = await verifyExport(load("broken-tsa.json"), { keysFile: KEYS_FILE, caFile: CA_FILE });
    expect(r.ok).toBe(false);
    expect(r.checks.signatures.ok).toBe(true);
    expect(r.checks.tsa.ok).toBe(false);
  }, 30000);

  it("skips the key check with skipKeyCheck and still verifies signatures", async () => {
    const r = await verifyExport(load("valid.json"), { skipTsa: true, skipKeyCheck: true });
    expect(r.checks.key.skipped).toBe(true);
    expect(r.checks.signatures.ok).toBe(true);
    expect(r.ok).toBe(true);
  });

  it("fails on broken-schema (and stops before chain)", async () => {
    const r = await verifyExport(load("broken-schema.json"), {
      skipTsa: true,
      keysFile: KEYS_FILE,
    });
    expect(r.ok).toBe(false);
    expect(r.checks.schema.ok).toBe(false);
    expect(r.checks.schema.error).toMatch(/schema_version/);
    expect(r.checks.chain.ran).toBe(false);
  });

  it("fails on broken-chain", async () => {
    const r = await verifyExport(load("broken-chain.json"), { skipTsa: true, keysFile: KEYS_FILE });
    expect(r.ok).toBe(false);
    expect(r.checks.chain.ok).toBe(false);
    expect(r.checks.chain.error).toMatch(/chain (broken|head|linkage)|anchored_data/i);
  });

  it("fails on broken-key (embedded key != published key)", async () => {
    const r = await verifyExport(load("broken-key.json"), { skipTsa: true, keysFile: KEYS_FILE });
    expect(r.ok).toBe(false);
    expect(r.checks.chain.ok).toBe(true);
    expect(r.checks.key.ok).toBe(false);
    expect(r.checks.key.error).toMatch(/does not match the published key/);
  });

  it("fails on broken-signature (chain + key pass, signature fails)", async () => {
    const r = await verifyExport(load("broken-signature.json"), {
      skipTsa: true,
      keysFile: KEYS_FILE,
    });
    expect(r.ok).toBe(false);
    expect(r.checks.chain.ok).toBe(true);
    expect(r.checks.key.ok).toBe(true);
    expect(r.checks.signatures.ok).toBe(false);
    expect(r.checks.signatures.error).toMatch(/signature/);
  });

  it("propagates a published-key fetch failure when no keysFile is given", async () => {
    const r = await verifyExport(load("valid.json"), {
      skipTsa: true,
      fetcher: async () => ({
        ok: false,
        status: 503,
        arrayBuffer: async () => new ArrayBuffer(0),
      }),
    });
    expect(r.ok).toBe(false);
    expect(r.checks.key.ran).toBe(true);
    expect(r.checks.key.ok).toBe(false);
    expect(r.checks.key.error).toMatch(/HTTP 503/);
  });
});
