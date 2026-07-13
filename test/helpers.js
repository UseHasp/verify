/**
 * Shared test helpers: locating fixtures and standing in for the network
 * (published-key fetch + TSA CA-cert fetch) so the suite runs fully offline.
 */
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));

export const FIXTURES = resolve(here, "fixtures");
export const fixture = (name) => resolve(FIXTURES, name);
export const loadFixture = (name) => JSON.parse(readFileSync(fixture(name), "utf8"));

/** The published-key document served at /trust/keys/{tenant_id}. */
export const TRUST_KEYS = loadFixture("trust-keys.json");
/** The published signing key as a bare PEM (for --key-file / expectedKey). */
export const PUBLISHED_KEY_PEM = readFileSync(fixture("published-key.pem"), "utf8");
export const PUBLISHED_KEY_FILE = fixture("published-key.pem");
export const CA_FILE = fixture("tsa-cacert.pem");

const CACERT = readFileSync(fixture("tsa-cacert.pem"));

/** A fetch stub that returns the given bytes with a configurable status. */
export function bytesFetcher(body, ok = true, status = 200) {
  return async () => ({
    ok,
    status,
    arrayBuffer: async () => body.buffer.slice(body.byteOffset, body.byteOffset + body.byteLength),
  });
}

/**
 * A fetch stub that answers both network calls the verifier makes:
 * `/trust/keys/…` returns TRUST_KEYS (or a supplied override), anything else
 * returns the bundled TSA CA cert.
 */
export function offlineFetcher(keysDoc = TRUST_KEYS) {
  const keysBody = Buffer.from(JSON.stringify(keysDoc));
  return async (url) => {
    const body = String(url).includes("/trust/keys/") ? keysBody : CACERT;
    return {
      ok: true,
      status: 200,
      arrayBuffer: async () =>
        body.buffer.slice(body.byteOffset, body.byteOffset + body.byteLength),
    };
  };
}

/** Verify options that keep everything offline (key from disk, CA from disk). */
export function offlineOpts(extra = {}) {
  return { keyFile: PUBLISHED_KEY_FILE, caFile: CA_FILE, ...extra };
}
