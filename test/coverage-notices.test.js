/**
 * Coverage notices verifyExport surfaces alongside a VERIFIED
 * result — never failures, but loud enough that a reviewer can't miss them.
 *
 *   - fold_base: a retention purge removed a prefix ahead of this export's
 *     window (purge-rebased-v2.json). Symmetrical to lineage_reset_at.
 *   - unattested tail: entries exist beyond the newest anchor
 *     (unattested-tail-v2.json) — normal, expected, still worth naming.
 */
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { verifyExport } from "../src/verify.js";

const here = dirname(fileURLToPath(import.meta.url));
const load = (name) => JSON.parse(readFileSync(resolve(here, "fixtures", name), "utf8"));
const KEYS_V2 = resolve(here, "fixtures", "published-keys-v2.json");

describe("fold_base notice (retention-purged prefix)", () => {
  it("verifies green and surfaces the fold_base value on the result", async () => {
    const r = await verifyExport(load("purge-rebased-v2.json"), {
      skipTsa: true,
      keysFile: KEYS_V2,
    });
    expect(r.ok).toBe(true);
    expect(r.fold_base).toBe(load("purge-rebased-v2.json").verification.fold_base);
    expect(r.fold_base).toMatch(/^[0-9a-f]{64}$/);
  });

  it("an export with no purge reports fold_base as null", async () => {
    const r = await verifyExport(load("valid-v2.json"), { skipTsa: true, keysFile: KEYS_V2 });
    expect(r.ok).toBe(true);
    expect(r.fold_base).toBeNull();
  });
});

describe("unattested tail (entries beyond the newest anchor)", () => {
  it("verifies green with partial coverage naming the first unattested seq", async () => {
    const r = await verifyExport(load("unattested-tail-v2.json"), {
      skipTsa: true,
      keysFile: KEYS_V2,
    });
    expect(r.ok).toBe(true);
    expect(r.checks.anchoring.ok).toBe(true);
    expect(r.checks.anchoring.coverage.attested_through_seq).toBe(2);
    expect(r.checks.anchoring.coverage.unattested_from_seq).toBe(3);
    expect(r.checks.anchoring.coverage.total_entries).toBe(4);
  });
});
