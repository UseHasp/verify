/**
 * Tests for checkSignatures: signatures over the hash hex string, verified
 * against an explicitly-passed trusted key.
 */
import { generateKeyPairSync } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { checkSignatures } from "../src/checks/signature.js";

const here = dirname(fileURLToPath(import.meta.url));
const VALID = JSON.parse(readFileSync(resolve(here, "fixtures", "valid.json"), "utf8"));
const KEY = VALID.verification.public_key_pem;
const clone = () => JSON.parse(JSON.stringify(VALID));

describe("checkSignatures", () => {
  it("passes on the valid fixture against the trusted key", () => {
    const r = checkSignatures(VALID, KEY);
    expect(r.ok).toBe(true);
    expect(r.count).toBe(VALID.entries.length);
  });

  it("fails on an unparseable public key", () => {
    const r = checkSignatures(
      VALID,
      "-----BEGIN PUBLIC KEY-----\nNOT A KEY\n-----END PUBLIC KEY-----\n",
    );
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/invalid public key/);
  });

  it("fails on a valid but non-Ed25519 (RSA) key", () => {
    const { publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
    const rsa = publicKey.export({ type: "spki", format: "pem" }).toString();
    const r = checkSignatures(VALID, rsa);
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/not Ed25519/);
  });

  it("fails on a malformed signature prefix", () => {
    const d = clone();
    d.entries[0].signature = "garbage-no-colon";
    const r = checkSignatures(d, KEY);
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/signature format invalid/);
  });

  it("fails on a wrong algo prefix", () => {
    const d = clone();
    d.entries[0].signature = "rsa:AAAA";
    const r = checkSignatures(d, KEY);
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
    const r = checkSignatures(d, KEY);
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/signature invalid at entry 1/);
  });

  it("fails when verified against the wrong (but valid Ed25519) key", () => {
    // The retired published key in the fixture is a different valid Ed25519 key.
    const keys = JSON.parse(readFileSync(resolve(here, "fixtures", "published-keys.json"), "utf8"));
    const otherKey = keys.keys.find((k) => k.status === "retired").public_key_pem;
    const r = checkSignatures(VALID, otherKey);
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/signature invalid/);
  });
});
