/**
 * The forged-CA negative fixture. `forged-tsa-v2.json` carries a
 * GENUINE RFC 3161 token — built by build-forged-tsa.js with a real openssl
 * TSA responder — signed by a freshly-minted, self-signed attacker CA rather
 * than FreeTSA, over the SAME anchored_data the real head anchor in
 * valid-v2.json commits to. Binding (the anchoring check) is untouched and
 * still passes; only the TSA signer differs. This is exactly the attack
 * the TSA trust-root hardening closes: before it, checkTsa fetched the
 * CA cert from the export's own tsa_cacert_url — a value the export (and so
 * the attacker) controls — and this forged token would have verified.
 */
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { verifyExport } from "../src/verify.js";

const here = dirname(fileURLToPath(import.meta.url));
const load = (name) => JSON.parse(readFileSync(resolve(here, "fixtures", name), "utf8"));
const KEYS_V2 = resolve(here, "fixtures", "published-keys-v2.json");
const ATTACKER_ROOT = resolve(here, "fixtures", "forged-tsa-root-cacert.pem");

describe.skipIf(process.platform === "darwin")(
  "forged-tsa-v2 fixture (real openssl, no mocks)",
  () => {
    it("FAILS by default — the bundled FreeTSA root does not trust the attacker's CA", async () => {
      const r = await verifyExport(load("forged-tsa-v2.json"), { keysFile: KEYS_V2 });
      expect(r.ok).toBe(false);
      // Binding is untouched — anchored_data still matches the real fold — so
      // the anchoring check itself passes; only the TSA check catches this.
      expect(r.checks.anchoring.ok).toBe(true);
      expect(r.checks.tsa.ok).toBe(false);
      expect(r.checks.tsa.error).toMatch(/untrusted TSA/);
      expect(r.checks.tsa.error).toMatch(/--ca-file/);
      expect(r.checks.tsa.error).toMatch(/--allow-untrusted-tsa/);
    });

    it("passes with an explicit --ca-file naming the attacker's root (the token itself is well-formed)", async () => {
      const r = await verifyExport(load("forged-tsa-v2.json"), {
        keysFile: KEYS_V2,
        caFile: ATTACKER_ROOT,
      });
      expect(r.ok).toBe(true);
      expect(r.checks.tsa.ok).toBe(true);
    });

    it("passes with --allow-untrusted-tsa fetching the export's own (attacker) tsa_cacert_url", async () => {
      const attackerCert = readFileSync(ATTACKER_ROOT);
      const r = await verifyExport(load("forged-tsa-v2.json"), {
        keysFile: KEYS_V2,
        allowUntrustedTsa: true,
        fetcher: async () => ({
          ok: true,
          status: 200,
          arrayBuffer: async () =>
            attackerCert.buffer.slice(
              attackerCert.byteOffset,
              attackerCert.byteOffset + attackerCert.byteLength,
            ),
        }),
      });
      expect(r.ok).toBe(true);
      expect(r.checks.tsa.ok).toBe(true);
    });
  },
);
