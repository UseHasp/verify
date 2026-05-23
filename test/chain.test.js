/**
 * Negative tests for checkChain: prev_hash mismatch, hash mismatch,
 * chain head mismatch.
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
  it("passes on valid fixture", () => {
    const r = checkChain(VALID);
    expect(r.ok).toBe(true);
    expect(r.count).toBe(VALID.entries.length);
  });

  it("fails when entry.prev_hash is wrong", () => {
    const d = clone();
    d.entries[1].prev_hash = "0".repeat(64);
    const r = checkChain(d);
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/prev_hash mismatch/);
  });

  it("fails when entry payload is mutated (hash no longer matches)", () => {
    const d = clone();
    d.entries[0].action = "tampered";
    const r = checkChain(d);
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/chain broken/);
  });

  it("fails when chain_head_hash is wrong", () => {
    const d = clone();
    d.verification.chain_head_hash = "f".repeat(64);
    const r = checkChain(d);
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/chain head mismatch/);
  });
});
