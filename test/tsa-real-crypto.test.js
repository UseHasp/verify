/**
 * Unmocked, end-to-end confirmation that the default trust root (the bundled
 * `roots/freetsa-cacert.pem`) genuinely verifies a real FreeTSA token with a
 * real `openssl ts -verify` invocation and no network access — the exact
 * property the TSA trust-root hardening requires ("a genuine FreeTSA export verifies against a
 * bundled root with no network fetch"). The committed `test/fixtures/valid.json`
 * carries a real RFC 3161 token from production FreeTSA (unlike the synthetic
 * anchor-v2 fixtures, whose TSA fields are placeholder base64).
 *
 * Skipped on macOS: LibreSSL's `openssl ts -verify` behaves differently from
 * OpenSSL (see README "macOS LibreSSL caveat"), which is exactly why the
 * `real-world` GitHub workflow restricts itself to ubuntu-latest. Every other
 * TSA behavior is covered by the mocked tests in tsa.test.js, which run on
 * every platform.
 */
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { checkTsa } from "../src/checks/tsa.js";

const here = dirname(fileURLToPath(import.meta.url));
const VALID = JSON.parse(readFileSync(resolve(here, "fixtures", "valid.json"), "utf8"));
// A real token from DigiCert's public TSA (HASP's second TSA), over a fixed
// digest — proves the bundled DigiCert root is the one that actually anchors
// its tokens, not a guessed certificate.
const DIGICERT = JSON.parse(
  readFileSync(resolve(here, "fixtures", "digicert-tsa-anchor.json"), "utf8"),
);

describe.skipIf(process.platform === "darwin")(
  "checkTsa — real openssl, bundled root, no mocks",
  () => {
    it("verifies the committed real-crypto sample with no --ca-file, no --allow-untrusted-tsa, and no fetcher", async () => {
      const r = await checkTsa(VALID, {
        fetcher: async () => {
          throw new Error("the default path must not touch the network");
        },
      });
      expect(r.ok).toBe(true);
      expect(r.anchors).toHaveLength(1);
      expect(r.anchors[0].genTime).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/);
    });

    it("verifies a real DigiCert TSA token against the bundled roots with no network access", async () => {
      const r = await checkTsa(DIGICERT, {
        fetcher: async () => {
          throw new Error("the default path must not touch the network");
        },
      });
      expect(r.ok).toBe(true);
      expect(r.anchors).toHaveLength(1);
    });
  },
);
