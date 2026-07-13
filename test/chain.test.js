/**
 * Tests for checkChain: hash recompute, prev_hash linkage, genesis anchor,
 * chain head.
 */
import { describe, expect, it } from "vitest";
import { checkChain, GENESIS_PREV_HASH } from "../src/checks/chain.js";
import { loadFixture } from "./helpers.js";

const VALID = loadFixture("valid.json");
const clone = () => JSON.parse(JSON.stringify(VALID));

describe("checkChain", () => {
  it("passes on valid fixture", () => {
    const r = checkChain(VALID);
    expect(r.ok).toBe(true);
    expect(r.count).toBe(VALID.entries.length);
  });

  it("genesis prev_hash is null (not 64 zeros)", () => {
    expect(GENESIS_PREV_HASH).toBe(null);
    expect(VALID.entries[0].prev_hash).toBe(null);
  });

  it("fails when a mid-chain prev_hash linkage is broken", () => {
    const d = clone();
    d.entries[2].prev_hash = "0".repeat(64);
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

  it("fails when a metadata value is mutated (canonicalized field is hashed)", () => {
    const d = clone();
    d.entries[0].metadata.model = "some-other-model";
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
