/**
 * Unit tests for checkTsa using an injected mock fetcher.
 *
 * The TSA CA certificate is bundled at test/fixtures/tsa-cacert.pem so
 * tests are fully offline. openssl must be on PATH (skipped if not).
 */
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { beforeAll, describe, expect, it } from "vitest";
import { checkTsa } from "../src/checks/tsa.js";

const here = dirname(fileURLToPath(import.meta.url));
const VALID = JSON.parse(readFileSync(resolve(here, "fixtures", "valid.json"), "utf8"));
const BROKEN_TSA = JSON.parse(readFileSync(resolve(here, "fixtures", "broken-tsa.json"), "utf8"));
const CACERT = readFileSync(resolve(here, "fixtures", "tsa-cacert.pem"));

let hasOpenssl = false;
beforeAll(() => {
  try {
    execFileSync("openssl", ["version"], { stdio: "ignore" });
    hasOpenssl = true;
  } catch {
    hasOpenssl = false;
  }
});

function mockFetcher(body, ok = true, status = 200) {
  return async () => ({
    ok,
    status,
    arrayBuffer: async () => body.buffer.slice(body.byteOffset, body.byteOffset + body.byteLength),
  });
}

describe("checkTsa", () => {
  it("passes on valid fixture with mocked cacert fetch", async () => {
    if (!hasOpenssl) return;
    const r = await checkTsa(VALID, { fetcher: mockFetcher(CACERT) });
    expect(r.ok).toBe(true);
    expect(r.anchors).toHaveLength(1);
    expect(r.anchors[0].output).toMatch(/Verification:\s*OK/);
  });

  it("fails when TSR is tampered", async () => {
    if (!hasOpenssl) return;
    const r = await checkTsa(BROKEN_TSA, { fetcher: mockFetcher(CACERT) });
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/openssl ts -verify failed/);
  });

  it("fails when chain head doesn't match TSR-signed data", async () => {
    if (!hasOpenssl) return;
    const d = JSON.parse(JSON.stringify(VALID));
    d.verification.chain_head_hash = "0".repeat(64);
    const r = await checkTsa(d, { fetcher: mockFetcher(CACERT) });
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/openssl ts -verify failed/);
  });

  it("fails when cacert fetch returns non-OK HTTP", async () => {
    if (!hasOpenssl) return;
    const r = await checkTsa(VALID, { fetcher: mockFetcher(Buffer.alloc(0), false, 503) });
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/HTTP 503/);
  });

  it("fails when cacert fetch throws", async () => {
    if (!hasOpenssl) return;
    const r = await checkTsa(VALID, {
      fetcher: async () => {
        throw new Error("network down");
      },
    });
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/network down/);
  });

  it("fails when CA cert content is invalid PEM", async () => {
    if (!hasOpenssl) return;
    const r = await checkTsa(VALID, { fetcher: mockFetcher(Buffer.from("not a cert")) });
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/openssl ts -verify failed/);
  });

  it("throws when openssl binary is missing", async () => {
    await expect(
      checkTsa(VALID, { fetcher: mockFetcher(CACERT), opensslPath: "/nonexistent/openssl-xyz" }),
    ).rejects.toThrow(/openssl not found/);
  });

  it("rejects oversized cacert response", async () => {
    if (!hasOpenssl) return;
    const huge = Buffer.alloc(1024 * 1024 + 1, 0x41);
    const r = await checkTsa(VALID, { fetcher: mockFetcher(huge) });
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/exceeds .*byte cap/);
  });

  it("passes AbortSignal to the fetcher (so the 15s timeout can fire)", async () => {
    if (!hasOpenssl) return;
    let receivedSignal = null;
    const fetcher = async (_url, init) => {
      receivedSignal = init?.signal ?? null;
      return {
        ok: true,
        status: 200,
        arrayBuffer: async () =>
          CACERT.buffer.slice(CACERT.byteOffset, CACERT.byteOffset + CACERT.byteLength),
      };
    };
    await checkTsa(VALID, { fetcher });
    expect(receivedSignal).not.toBeNull();
    expect(typeof receivedSignal.aborted).toBe("boolean");
  });
});
