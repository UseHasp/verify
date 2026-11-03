#!/usr/bin/env node
/**
 * Builds `forged-tsa-v2.json` — a TSA trust-root negative fixture proving the
 * TSA trust-root hardening in `src/checks/tsa.js`: an export whose head
 * anchor carries a GENUINE RFC 3161 token, minted by a real (self-signed)
 * attacker-controlled CA rather than FreeTSA, over the exact same
 * `anchored_data` the real head anchor in `valid-v2.json` commits to.
 *
 * The token is not a fake byte string — it is produced by an actual openssl
 * TSA responder (`openssl ts -reply`), signed by a freshly-minted attacker
 * root + TSA leaf cert, so the fixture exercises the real ASN.1 parse and
 * signature-chain verification path, not a shortcut. Because `anchored_data`
 * is untouched, the anchoring check (binding) still passes — this fixture
 * isolates the TSA check specifically: is the token's SIGNER trusted?
 *
 * Before this hardening, `checkTsa` fetched the CA cert from the export's own
 * `tsa_cacert_url` and would have verified this token successfully (an
 * attacker who controls the export controls that URL too). After hardening,
 * the default path trusts only the bundled FreeTSA root
 * (`roots/freetsa-cacert.pem`) and never reads `tsa_cacert_url` at all unless
 * `--allow-untrusted-tsa` is passed — so this fixture FAILS by default.
 *
 * Also writes `forged-tsa-root-cacert.pem` — the attacker's root CA cert —
 * so a test can prove the token verifies fine against an explicitly-trusted
 * `--ca-file`, confirming the token is cryptographically well-formed and it
 * really is the DEFAULT TRUST ROOT (not the token) that makes it fail.
 *
 * Not deterministic (openssl key generation uses real randomness) — unlike
 * build-v2.js's fixed test key. Re-run only if this script or the anchoring
 * math changes; the committed output is what CI and local tests run against.
 */
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const tmp = mkdtempSync(resolve(tmpdir(), "hasp-forge-tsa-"));

function openssl(args) {
  return execFileSync("openssl", args, { cwd: tmp, encoding: "utf8" });
}

// 1. Attacker root CA (self-signed) + TSA leaf cert with the timeStamping EKU
//    openssl ts requires on the signer.
openssl(["genrsa", "-out", "root-key.pem", "2048"]);
openssl([
  "req",
  "-x509",
  "-new",
  "-key",
  "root-key.pem",
  "-sha256",
  "-days",
  "3650",
  "-out",
  "root-cert.pem",
  "-subj",
  "/CN=Forged Attacker Root CA/O=TSA trust-root negative fixture (not a real CA)",
]);
openssl(["genrsa", "-out", "tsa-key.pem", "2048"]);
openssl([
  "req",
  "-new",
  "-key",
  "tsa-key.pem",
  "-out",
  "tsa.csr",
  "-subj",
  "/CN=Forged Attacker TSA/O=TSA trust-root negative fixture (not a real TSA)",
]);
writeFileSync(
  resolve(tmp, "tsa_ext.cnf"),
  "extendedKeyUsage=critical,timeStamping\nbasicConstraints=critical,CA:false\n",
);
openssl([
  "x509",
  "-req",
  "-in",
  "tsa.csr",
  "-CA",
  "root-cert.pem",
  "-CAkey",
  "root-key.pem",
  "-CAcreateserial",
  "-out",
  "tsa-cert.pem",
  "-days",
  "3650",
  "-sha256",
  "-extfile",
  "tsa_ext.cnf",
]);

// 2. Mint a genuine RFC 3161 response over the REAL head anchor's
//    anchored_data from valid-v2.json, so the binding math still passes —
//    only the signing authority differs from the genuine FreeTSA token.
const validV2 = JSON.parse(readFileSync(resolve(here, "valid-v2.json"), "utf8"));
const headAnchor = validV2.verification.tsa_anchor_chain[1];
const digest = headAnchor.anchored_data;

writeFileSync(resolve(tmp, "serial.txt"), "01\n");
writeFileSync(
  resolve(tmp, "tsa.cnf"),
  [
    "[ tsa ]",
    "default_tsa = tsa_config1",
    "",
    "[ tsa_config1 ]",
    "serial = serial.txt",
    "signer_cert = tsa-cert.pem",
    "certs = tsa-cert.pem",
    "signer_key = tsa-key.pem",
    "signer_digest = sha256",
    "default_policy = 1.2.3.4.1",
    "digests = sha256",
    "accuracy = secs:1",
    "clock_precision_digits = 0",
    "ordering = yes",
    "tsa_name = no",
    "ess_cert_id_chain = no",
    "ess_cert_id_alg = sha256",
    "",
  ].join("\n"),
);
openssl(["ts", "-query", "-digest", digest, "-sha256", "-cert", "-out", "req.tsq"]);
openssl(["ts", "-reply", "-config", "tsa.cnf", "-queryfile", "req.tsq", "-out", "resp.tsr"]);

// Sanity-check the forged token at build time: valid against the attacker's
// own root, invalid against the real bundled FreeTSA root.
const okAgainstAttacker = openssl([
  "ts",
  "-verify",
  "-in",
  "resp.tsr",
  "-CAfile",
  "root-cert.pem",
  "-digest",
  digest,
]);
if (!/Verification:\s*OK/.test(okAgainstAttacker)) {
  throw new Error("forged token failed to verify against its own attacker root — build is broken");
}
let failsAgainstReal = false;
try {
  openssl([
    "ts",
    "-verify",
    "-in",
    "resp.tsr",
    "-CAfile",
    resolve(here, "..", "..", "roots", "freetsa-cacert.pem"),
    "-digest",
    digest,
  ]);
} catch {
  failsAgainstReal = true;
}
if (!failsAgainstReal) {
  throw new Error("forged token verified against the REAL bundled root — build is broken");
}

const forgedTsrBase64 = readFileSync(resolve(tmp, "resp.tsr")).toString("base64");
const attackerRootCert = readFileSync(resolve(tmp, "root-cert.pem"), "utf8");

// 3. Assemble the fixture: valid-v2.json's head anchor, with its TSR + CA URL
//    swapped for the forged ones. anchored_data, anchored_entry_id, and
//    checkpoint_after_entry are untouched — binding still passes. Drop the
//    interior anchor entirely — its tsa_tsr_base64 in valid-v2.json is
//    placeholder text (that fixture family is only ever exercised with
//    skipTsa: true), and this fixture is specifically about the real TSA
//    path, which would choke on it as malformed ASN.1.
const fixture = JSON.parse(JSON.stringify(validV2));
fixture.verification.tsa_anchor_chain = [
  {
    ...fixture.verification.tsa_anchor_chain[1],
    tsa_url: "https://attacker-tsa.test/tsr",
    tsa_cacert_url: "https://attacker-tsa.test/cacert.pem",
    tsa_tsr_base64: forgedTsrBase64,
  },
];

writeFileSync(resolve(here, "forged-tsa-v2.json"), `${JSON.stringify(fixture, null, 2)}\n`);
writeFileSync(resolve(here, "forged-tsa-root-cacert.pem"), attackerRootCert);

rmSync(tmp, { recursive: true, force: true });

console.log("Wrote forged-tsa-v2.json, forged-tsa-root-cacert.pem");
