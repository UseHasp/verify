/**
 * Tests for checkChain: integrity recompute, prev_hash linkage, chain head,
 * and the anchor↔checkpoint binding.
 */
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { checkChain } from "../src/checks/chain.js";

const here = dirname(fileURLToPath(import.meta.url));
const VALID = JSON.parse(readFileSync(resolve(here, "fixtures", "valid.json"), "utf8"));
const clone = () => JSON.parse(JSON.stringify(VALID));

describe("checkChain", () => {
  it("passes on the valid fixture", () => {
    const r = checkChain(VALID);
    expect(r.ok).toBe(true);
    expect(r.count).toBe(VALID.entries.length);
  });

  it("fails when a hashed field is mutated (recompute no longer matches)", () => {
    const d = clone();
    d.entries[0].action = "tampered";
    const r = checkChain(d);
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/chain broken at entry 1/);
  });

  it("fails when metadata is mutated", () => {
    const d = clone();
    d.entries[0].metadata.input_tokens = 999999;
    const r = checkChain(d);
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/chain broken/);
  });

  it("fails when prev_hash linkage is broken (but each hash still self-consistent)", () => {
    const d = clone();
    d.entries[2].prev_hash = "0".repeat(64);
    const r = checkChain(d);
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/chain linkage broken at entry 3/);
  });

  it("fails when chain_head_hash does not match the last entry", () => {
    const d = clone();
    d.verification.chain_head_hash = "f".repeat(64);
    const r = checkChain(d);
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/chain head mismatch/);
  });

  it("fails when an anchor's anchored_data does not match its checkpoint entry", () => {
    const d = clone();
    d.verification.tsa_anchor_chain[0].anchored_data = "a".repeat(64);
    const r = checkChain(d);
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/anchored_data .* does not match the hash of entry/);
  });

  it("fails when checkpoint_after_entry is out of range", () => {
    const d = clone();
    d.verification.tsa_anchor_chain[0].checkpoint_after_entry = 99;
    const r = checkChain(d);
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/out of range/);
  });
});
