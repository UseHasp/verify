# Bundled TSA trust roots

`src/checks/tsa.js` verifies every anchor against every `*.pem` file directly under this directory
by default (concatenated into one `openssl ts -verify -CAfile`, which natively accepts a multi-cert
bundle and matches whichever cert completes the chain) — not the `tsa_cacert_url` embedded in the
export under test, which an attacker controls. This closes the trust-root circularity where a
forged export naming its own CA at any `https:` URL would otherwise verify against itself. Pass
`--ca-file <path>` to trust a different CA explicitly, or `--allow-untrusted-tsa` to opt back into
fetching the export's declared `tsa_cacert_url` (only for sources you already trust).

An anchor verifies if it matches ANY bundled root — this check doesn't need to know which
configured TSA (platform-side: `hasp.security.audit.tsas`) actually produced a given
anchor, only that it chains to a root we've pinned. Add a TSA to the trust bundle by dropping its
root CA cert here as a new `*.pem` file — no code change.

## Currently pinned

`freetsa-cacert.pem` — [FreeTSA](https://freetsa.org)'s Root CA certificate, self-signed, valid
until 2041-03-07. This is the CA that issues FreeTSA's TSA signing certificate, which signs every
RFC 3161 token FreeTSA issues. HASP's first configured TSA.

`digicert-trusted-root-g4.pem` — DigiCert Trusted Root G4, self-signed, valid until 2038-01-15,
SHA-256 fingerprint `55:2F:7B:DC:F1:A7:AF:9E:6C:E6:72:01:7F:4F:12:AB:F7:72:40:C7:8E:76:1A:C2:03:D1:D9:D2:0A:C8:99:88`.
It roots the chain (via *DigiCert Trusted G4 TimeStamping RSA4096 SHA256 2025 CA1*) that signs every
token from DigiCert's public timestamp service (`http://timestamp.digicert.com`) — HASP's second
configured TSA. HASP anchors every fold with both TSAs, so an export carries an anchor from each.
`test/fixtures/digicert-tsa-anchor.json` is a real DigiCert token that `test/tsa-real-crypto.test.js`
verifies against this bundle offline.

Re-download and re-commit before each root's expiry, or sooner if either CA rotates its root:

```bash
curl -o roots/freetsa-cacert.pem https://freetsa.org/files/cacert.pem
curl -o roots/digicert-trusted-root-g4.pem https://cacerts.digicert.com/DigiCertTrustedRootG4.crt.pem
```

Confirm a replacement by verifying a fresh token against it, never by trusting the download alone:

```bash
openssl ts -query -digest "$(printf x | sha256sum | cut -d' ' -f1)" -sha256 -cert -no_nonce -out q.tsq
curl -s -H 'Content-Type: application/timestamp-query' --data-binary @q.tsq http://timestamp.digicert.com -o r.tsr
openssl ts -verify -digest "$(printf x | sha256sum | cut -d' ' -f1)" -in r.tsr -CAfile roots/digicert-trusted-root-g4.pem
```
