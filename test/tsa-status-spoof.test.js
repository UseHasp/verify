/**
 * A timestamp response is `{ status, token }` and only the token is signed.
 * The status block carries a free-text string that `openssl ts -reply -text`
 * prints verbatim — newlines included — ahead of the token's own fields.
 *
 * So anyone holding a genuine token can re-wrap it in a response whose status
 * string contains a line reading "Time stamp: <a date of their choosing>".
 * `openssl ts -verify` still says OK (the token is untouched), and a reader
 * that takes the first "Time stamp:" line from the printed response gets the
 * forged date.
 *
 * That date decides two things in this verifier: whether an anchor is
 * backdated, and whether a signature made with a since-revoked key is proven
 * to predate the revocation. With a spoofable date, the holder of a leaked,
 * revoked key timestamps a forged chain today and presents it as anchored
 * before the revocation. These tests use a real token and real openssl.
 */
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { checkTsa } from "../src/checks/tsa.js";
import { verifyExport } from "../src/verify.js";

const here = dirname(fileURLToPath(import.meta.url));
const load = (name) => JSON.parse(readFileSync(resolve(here, "fixtures", name), "utf8"));
// forged-tsa-v2.json carries a genuine RFC 3161 token from a test TSA whose
// root is forged-tsa-root-cacert.pem. Trusting that root via caFile makes it
// stand in for any TSA the verifier trusts. Its real genTime is 2026-08-02.
const TRUSTED_ROOT = resolve(here, "fixtures", "forged-tsa-root-cacert.pem");
const KEYS_REVOKED = resolve(here, "fixtures", "published-keys-v2-revoked.json"); // revoked 2026-07-25
const REAL_GEN_TIME = "2026-08-02T21:46:51.000Z";

/** DER tag-length-value. */
function tlv(tag, body) {
  const length =
    body.length < 128
      ? Buffer.from([body.length])
      : Buffer.from([0x82, body.length >> 8, body.length & 0xff]);
  return Buffer.concat([Buffer.from([tag]), length, body]);
}

/** Header length + content length of the TLV starting at `offset`. */
function tlvSize(buf, offset) {
  const first = buf[offset + 1];
  if (first < 128) return 2 + first;
  const lengthBytes = first & 0x7f;
  let length = 0;
  for (let i = 0; i < lengthBytes; i++) length = (length << 8) | buf[offset + 2 + i];
  return 2 + lengthBytes + length;
}

/**
 * Re-wrap the response's signed token in a new, unsigned status block whose
 * status string smuggles in a "Time stamp:" line.
 */
function rewrapWithStatusText(tsrBase64, statusText) {
  const tsr = Buffer.from(tsrBase64, "base64");
  const body = tsr.subarray(tsr.length - tlvContentLength(tsr)); // strip the outer SEQUENCE header
  const token = body.subarray(tlvSize(body, 0)); // everything after the original status
  const status = tlv(
    0x30,
    Buffer.concat([
      tlv(0x02, Buffer.from([0])), // PKIStatus: granted
      tlv(0x30, tlv(0x0c, Buffer.from(statusText, "utf8"))), // PKIFreeText
    ]),
  );
  return tlv(0x30, Buffer.concat([status, token])).toString("base64");
}

function tlvContentLength(buf) {
  const first = buf[1];
  if (first < 128) return first;
  const lengthBytes = first & 0x7f;
  let length = 0;
  for (let i = 0; i < lengthBytes; i++) length = (length << 8) | buf[2 + i];
  return length;
}

function spoofedExport(statusText) {
  const data = load("forged-tsa-v2.json");
  const anchor = data.verification.tsa_anchor_chain[0];
  anchor.tsa_tsr_base64 = rewrapWithStatusText(anchor.tsa_tsr_base64, statusText);
  return data;
}

describe.skipIf(process.platform === "darwin")(
  "genTime comes from the signed token, not the unsigned status text (real openssl)",
  () => {
    it("reads the true genTime from an untouched response", async () => {
      const r = await checkTsa(load("forged-tsa-v2.json"), { caFile: TRUSTED_ROOT });
      expect(r.ok).toBe(true);
      expect(r.anchors[0].genTime).toBe(REAL_GEN_TIME);
    });

    it("still reads the true genTime when the status text injects its own 'Time stamp:' line", async () => {
      const r = await checkTsa(spoofedExport("ok\nTime stamp: Jul 24 00:00:00 2026 GMT"), {
        caFile: TRUSTED_ROOT,
      });
      // The token is genuine, so the response verifies — that is the point.
      expect(r.ok).toBe(true);
      expect(r.anchors[0].genTime).toBe(REAL_GEN_TIME);
    });

    it("FAILS a chain signed under a revoked key whose anchor is re-wrapped to look pre-revocation", async () => {
      // Token really issued 2026-08-02, key revoked 2026-07-25, status text
      // claims 2026-07-24.
      const r = await verifyExport(spoofedExport("ok\nTime stamp: Jul 24 00:00:00 2026 GMT"), {
        keysFile: KEYS_REVOKED,
        caFile: TRUSTED_ROOT,
      });
      expect(r.checks.tsa.ok).toBe(true);
      expect(r.checks.keyRevocation.ok).toBe(false);
      expect(r.checks.keyRevocation.error).toMatch(/does not precede the revocation/);
      expect(r.ok).toBe(false);
    });
  },
);
