/**
 * Negative tests for checkSignatures: no trusted key supplied, invalid PEM,
 * malformed sig prefix, bad signature bytes.
 */
import { createPublicKey } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { checkSignatures } from "../src/checks/signature.js";

const here = dirname(fileURLToPath(import.meta.url));
const VALID = JSON.parse(readFileSync(resolve(here, "fixtures", "valid.json"), "utf8"));
const clone = () => JSON.parse(JSON.stringify(VALID));
const trustedKey = () => createPublicKey(VALID.verification.public_key_pem);

describe("checkSignatures", () => {
  it("passes on valid fixture when given the trusted key", () => {
    const r = checkSignatures(VALID, { publicKey: trustedKey() });
    expect(r.ok).toBe(true);
    expect(r.count).toBe(VALID.entries.length);
  });

  it("fails closed with no opts.publicKey (no fallback to the export's embedded key)", () => {
    const r = checkSignatures(VALID);
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/no trusted public key provided/);
  });

  it("fails closed when opts is an empty object", () => {
    const r = checkSignatures(VALID, {});
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/no trusted public key provided/);
  });

  it("fails on malformed signature prefix", () => {
    const d = clone();
    d.entries[0].signature = "garbage-no-colon";
    const r = checkSignatures(d, { publicKey: trustedKey() });
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/signature format invalid/);
  });

  it("fails on wrong algo prefix", () => {
    const d = clone();
    d.entries[0].signature = "rsa:AAAA";
    const r = checkSignatures(d, { publicKey: trustedKey() });
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
    const r = checkSignatures(d, { publicKey: trustedKey() });
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/signature invalid at seq=1/);
  });
});
