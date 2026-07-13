/**
 * Tests for checkSignatures. Signatures are detached Ed25519 over each entry's
 * `hash` hex string, verified against the trusted key resolved by the
 * published-key check (here supplied directly).
 */
import { createPublicKey } from "node:crypto";
import { describe, expect, it } from "vitest";
import { checkSignatures } from "../src/checks/signature.js";
import { loadFixture, PUBLISHED_KEY_PEM } from "./helpers.js";

const VALID = loadFixture("valid.json");
const clone = () => JSON.parse(JSON.stringify(VALID));
const KEY = createPublicKey(PUBLISHED_KEY_PEM);
const ctx = { publicKey: KEY };

describe("checkSignatures", () => {
  it("passes on valid fixture", () => {
    const r = checkSignatures(VALID, ctx);
    expect(r.ok).toBe(true);
    expect(r.count).toBe(VALID.entries.length);
  });

  it("fails on malformed signature prefix", () => {
    const d = clone();
    d.entries[0].signature = "garbage-no-colon";
    const r = checkSignatures(d, ctx);
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/signature format invalid/);
  });

  it("fails on wrong algo prefix", () => {
    const d = clone();
    d.entries[0].signature = "rsa:AAAA";
    const r = checkSignatures(d, ctx);
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/signature format invalid/);
  });

  it("fails on tampered signature bytes", () => {
    const d = clone();
    const e = d.entries[0];
    const [algo, b64] = e.signature.split(":");
    const buf = Buffer.from(b64, "base64");
    buf[0] ^= 0x01;
    e.signature = `${algo}:${buf.toString("base64")}`;
    const r = checkSignatures(d, ctx);
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/signature invalid at entry\[0\]/);
  });

  it("fails when the hash a signature covers is changed", () => {
    // The signature is over the hash hex string; changing the hash (without a
    // matching re-sign) invalidates it.
    const d = clone();
    d.entries[0].hash = "a".repeat(64);
    const r = checkSignatures(d, ctx);
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/signature invalid/);
  });

  it("fails when verified against the wrong key", () => {
    // The forged chain is validly self-signed by the attacker key, so it must
    // FAIL against the legitimate published key.
    const forged = loadFixture("forged-chain.json");
    const r = checkSignatures(forged, ctx);
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/signature invalid/);
  });
});
