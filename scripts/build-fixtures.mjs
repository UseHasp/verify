#!/usr/bin/env node
/**
 * Regenerate the test fixtures for the schema_version 1.0 envelope.
 *
 * This script is the in-repo stand-in for the platform's
 * `AuditExportEnvelopeBuilder`: it emits an export that is byte-for-byte
 * verifiable by @usehasp/verify, using REAL cryptography end to end —
 *
 *   - a deterministic Ed25519 key (fixed seed, so hashes/signatures are stable
 *     across regenerations), signing each entry's `hash` hex string;
 *   - per-entry integrity hashes computed by the SAME src/hash.js the verifier
 *     uses, so the generator and the checker cannot drift;
 *   - a genuine RFC 3161 timestamp token over the chain head, issued by a
 *     throwaway local TSA (CA + timeStamping cert minted here with `openssl`),
 *     so `openssl ts -verify` really runs.
 *
 * Why a local TSA and not freetsa: the published marketing sample
 * (apps/marketing/public/trust/audit-export-sample.json, the monorepo half of
 * HASP-197) is the artifact that must carry a real freetsa `.tsr` from a real
 * staging export. This committed fixture only needs to exercise the verifier's
 * RFC 3161 code path with real crypto, which a self-issued TSA does. The
 * verifier is agnostic to which TSA signed the token — it verifies whatever CA
 * the export's `tsa_cacert_url` points to (here, the bundled local CA).
 *
 * Outputs (all under test/fixtures/):
 *   valid.json            — a self-consistent, fully-verifiable export
 *   broken-schema.json    — unsupported schema_version
 *   broken-chain.json     — a mutated entry field (recomputed hash won't match)
 *   broken-signature.json — a flipped signature byte
 *   broken-tsa.json       — corrupted TSR bytes
 *   broken-key.json       — published_key_pem that doesn't match the signer
 *   published-keys.json   — the GET /trust/keys/{tenant_id} response
 *   tsa-cacert.pem        — the local TSA's CA certificate (the "cacert_url" body)
 *
 * Re-run after changing the contract:  node scripts/build-fixtures.mjs
 */
import { execFileSync } from "node:child_process";
import { createPrivateKey, createPublicKey, sign as edSign } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { computeIntegrityHash } from "../src/hash.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURES = resolve(HERE, "..", "test", "fixtures");
const ZERO_HASH = "0".repeat(64);

// ---------------------------------------------------------------------------
// 1. Deterministic Ed25519 signing key (fixed 32-byte seed → stable fixture).
// ---------------------------------------------------------------------------
const SEED = Buffer.alloc(32, 0x2a); // any fixed seed; this is a TEST key only.
// PKCS#8 prefix for an Ed25519 private key, followed by the 32-byte seed.
const PKCS8 = Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), SEED]);
const privateKey = createPrivateKey({ key: PKCS8, format: "der", type: "pkcs8" });
const publicKeyPem = createPublicKey(privateKey).export({ type: "spki", format: "pem" }).toString();

/** @param {string} hashHex */
function signHashHex(hashHex) {
  // Detached Ed25519 over the ASCII hex string (NOT the raw 32 hash bytes).
  const raw = edSign(null, Buffer.from(hashHex, "utf8"), privateKey);
  return `ed25519:${raw.toString("base64")}`;
}

// A second, unrelated but VALID Ed25519 public key — used for the retired
// published key and for the broken-key fixture, so the "does not match the
// published key" branch is exercised with real key material, not garbage.
const OTHER_SEED = Buffer.alloc(32, 0x55);
const OTHER_PKCS8 = Buffer.concat([
  Buffer.from("302e020100300506032b657004220420", "hex"),
  OTHER_SEED,
]);
const otherPublicKeyPem = createPublicKey(
  createPrivateKey({ key: OTHER_PKCS8, format: "der", type: "pkcs8" }),
)
  .export({ type: "spki", format: "pem" })
  .toString();

// ---------------------------------------------------------------------------
// 2. The audit entries (fictional tenant — Cedar Valley Pediatrics).
//    Each object carries the full integrity-field set so the hash is
//    recomputable from the envelope alone.
// ---------------------------------------------------------------------------
const TENANT_ID = "org_01J9ZK7Q2M4X8B3C6D5E7F0G1H";
const KEY_ID = "key_01J9YV0F3JBA7Z2N8D5Q3R7V8M";

/** @type {Array<Record<string, unknown>>} */
const sourceEntries = [
  {
    user_id: 5012,
    org_id: 87,
    project_id: 1204,
    action: "ai.chat.message",
    entity_type: "AiChatSession",
    entity_id: "chat_01J9ZM1A2B3C4D5E6F7G8H9J0K",
    metadata: {
      model: "claude-sonnet-4-6",
      input_tokens: 412,
      phi_scan: {
        engine: "hasp-phi-scan-v1",
        redaction_count: 2,
        categories_detected: ["NAME", "DATE_OF_BIRTH"],
        action: "redact",
      },
    },
    ip_address: "203.0.113.42",
    created_at: "2026-04-25T14:02:11+00:00",
    phi_disposition: "redacted",
    subject_type: "patient",
    subject_id_hmac: "9f2c4a1be83d77065b0a4e2f1c8d6093ab57e4d2c19f8a3b06e7d5c4b3a29180",
  },
  {
    user_id: 5012,
    org_id: 87,
    project_id: 1204,
    action: "ai.chat.response",
    entity_type: "AiChatSession",
    entity_id: "chat_01J9ZM1A2B3C4D5E6F7G8H9J0K",
    metadata: {
      model: "claude-sonnet-4-6",
      output_tokens: 287,
      finish_reason: "stop",
    },
    ip_address: "203.0.113.42",
    created_at: "2026-04-25T14:02:14+00:00",
    phi_disposition: "none",
    subject_type: "patient",
    subject_id_hmac: "9f2c4a1be83d77065b0a4e2f1c8d6093ab57e4d2c19f8a3b06e7d5c4b3a29180",
  },
  {
    user_id: null,
    org_id: 87,
    project_id: 1204,
    action: "data.record.create",
    entity_type: "EncounterRecord",
    entity_id: "rec_01J9ZN02M3N4P5Q6R7S8T9U0V1",
    metadata: {
      entity: "encounter",
      source: "ehr-bridge",
      api_key_id: "key_01J9ZN2A3B4C5D6E7F8G9H0J1K",
    },
    ip_address: "198.51.100.7",
    created_at: "2026-04-25T14:08:42+00:00",
    phi_disposition: "contains_phi",
    subject_type: "patient",
    subject_id_hmac: "1c8d6093ab57e4d2c19f8a3b06e7d5c4b3a291809f2c4a1be83d77065b0a4e2f",
  },
  {
    user_id: 6188,
    org_id: 87,
    project_id: null,
    action: "audit.export.request",
    entity_type: "AuditExport",
    entity_id: "exp_01J9ZP2N3P4Q5R6S7T8U9V0W1X",
    metadata: {
      format: "json",
      range: "2026-04-25",
    },
    ip_address: "203.0.113.99",
    created_at: "2026-04-25T14:11:55+00:00",
    phi_disposition: "none",
    subject_type: null,
    subject_id_hmac: null,
  },
];

// Hash + chain-link + sign each entry, in order.
let prev = ZERO_HASH; // fresh org: the first row links to the genesis hash.
const entries = sourceEntries.map((src, i) => {
  const hash = computeIntegrityHash(src);
  const entry = {
    seq: i + 1,
    ...src,
    prev_hash: prev,
    hash,
    signature: signHashHex(hash),
  };
  prev = hash;
  return entry;
});

const chainHead = entries[entries.length - 1].hash;

// ---------------------------------------------------------------------------
// 3. A real RFC 3161 timestamp token over the chain head, from a local TSA.
// ---------------------------------------------------------------------------
const { tsrBase64, caCertPem } = issueTimestamp(chainHead);

// ---------------------------------------------------------------------------
// 4. Assemble the envelope and the published-keys response.
// ---------------------------------------------------------------------------
const envelope = {
  schema_version: "1.0",
  export: {
    tenant: "Cedar Valley Pediatrics",
    tenant_id: TENANT_ID,
    range: {
      from: "2026-04-25T00:00:00+00:00",
      to: "2026-04-25T23:59:59+00:00",
    },
    exported_at: "2026-04-25T14:12:03+00:00",
    exported_by: "auditor@northwind-cpa.example",
    entry_count: entries.length,
  },
  verification: {
    algo: "ed25519",
    key_id: KEY_ID,
    public_key_pem: publicKeyPem,
    keys_url: `https://app.usehasp.com/trust/keys/${TENANT_ID}`,
    key_published_at: "2026-04-01T00:00:00+00:00",
    chain_head_hash: chainHead,
    tsa_anchor_chain: [
      {
        checkpoint_after_entry: entries.length,
        tsa_url: "https://tsa.hasp-test.example/tsr",
        tsa_cacert_url: "https://tsa.hasp-test.example/cacert.pem",
        tsa_tsr_base64: tsrBase64,
        anchored_data: chainHead,
        anchored_at: "2026-04-25T14:12:05+00:00",
      },
    ],
    instructions: "https://usehasp.com/trust/verify",
  },
  entries,
};

const publishedKeys = {
  tenant_id: TENANT_ID,
  keys: [
    {
      key_id: KEY_ID,
      public_key_pem: publicKeyPem,
      published_at: "2026-04-01T00:00:00+00:00",
      status: "active",
    },
    {
      // A retired key, to prove the verifier matches on key_id, not position.
      key_id: "key_01J8RETIRED0000000000000000",
      public_key_pem: otherPublicKeyPem,
      published_at: "2025-10-01T00:00:00+00:00",
      status: "retired",
    },
  ],
};

// ---------------------------------------------------------------------------
// 5. Write valid + published-keys + cacert, then derive the broken variants.
// ---------------------------------------------------------------------------
writeJson("valid.json", envelope);
writeJson("published-keys.json", publishedKeys);
writeFileSync(join(FIXTURES, "tsa-cacert.pem"), caCertPem);

writeJson(
  "broken-schema.json",
  mutate(envelope, (f) => (f.schema_version = "99.0")),
);
writeJson(
  "broken-chain.json",
  mutate(envelope, (f) => (f.entries[1].action = "ai.chat.response.tampered")),
);
writeJson(
  "broken-signature.json",
  mutate(envelope, (f) => {
    const e = f.entries[f.entries.length - 1];
    const [, b64] = e.signature.split(":");
    const buf = Buffer.from(b64, "base64");
    buf[0] ^= 0x01;
    e.signature = `ed25519:${buf.toString("base64")}`;
  }),
);
writeJson(
  "broken-tsa.json",
  mutate(envelope, (f) => {
    const a = f.verification.tsa_anchor_chain[0];
    const buf = Buffer.from(a.tsa_tsr_base64, "base64");
    buf[12] ^= 0xff;
    a.tsa_tsr_base64 = buf.toString("base64");
  }),
);
// broken-key.json: same valid export, but the published-keys response is the
// one to feed via --keys-file; the embedded key no longer matches the published
// one. We mutate the EXPORT's embedded public_key_pem so it diverges from the
// (genuine) published-keys.json.
writeJson(
  "broken-key.json",
  mutate(envelope, (f) => {
    f.verification.public_key_pem = otherPublicKeyPem;
  }),
);

console.log(`Wrote fixtures to ${FIXTURES}`);
console.log(`  chain_head_hash = ${chainHead}`);

// ===========================================================================
// helpers
// ===========================================================================

/**
 * Mint a throwaway TSA (root CA + timeStamping signer) and produce a genuine
 * RFC 3161 timestamp token over the UTF-8 bytes of `data`.
 *
 * @param {string} data the exact string the token must cover (the chain head)
 * @returns {{tsrBase64: string, caCertPem: string}}
 */
function issueTimestamp(data) {
  const dir = mkdtempSync(join(tmpdir(), "hasp-tsa-"));
  const p = (name) => join(dir, name);
  try {
    const openssl = (args) => execFileSync("openssl", args, { stdio: ["ignore", "pipe", "pipe"] });

    // Root CA.
    openssl([
      "req",
      "-x509",
      "-newkey",
      "rsa:2048",
      "-nodes",
      "-keyout",
      p("ca.key"),
      "-out",
      p("ca.crt"),
      "-days",
      "7300",
      "-subj",
      "/O=Hasp Test/CN=Hasp Test TSA Root CA",
    ]);

    // TSA signing cert (extendedKeyUsage = critical timeStamping).
    openssl([
      "req",
      "-newkey",
      "rsa:2048",
      "-nodes",
      "-keyout",
      p("tsa.key"),
      "-out",
      p("tsa.csr"),
      "-subj",
      "/O=Hasp Test/CN=Hasp Test TSA Signer",
    ]);
    writeFileSync(p("tsa.ext"), "extendedKeyUsage = critical,timeStamping\n");
    openssl([
      "x509",
      "-req",
      "-in",
      p("tsa.csr"),
      "-CA",
      p("ca.crt"),
      "-CAkey",
      p("ca.key"),
      "-CAcreateserial",
      "-out",
      p("tsa.crt"),
      "-days",
      "7300",
      "-extfile",
      p("tsa.ext"),
    ]);

    // Minimal TSA config for `openssl ts -reply`.
    writeFileSync(p("tsa.cnf"), tsaConfig(dir));
    writeFileSync(p("serial"), "01\n");
    writeFileSync(p("data.bin"), Buffer.from(data, "utf8"));

    // Request → reply.
    openssl(["ts", "-query", "-data", p("data.bin"), "-sha256", "-cert", "-out", p("req.tsq")]);
    openssl([
      "ts",
      "-reply",
      "-config",
      p("tsa.cnf"),
      "-queryfile",
      p("req.tsq"),
      "-signer",
      p("tsa.crt"),
      "-inkey",
      p("tsa.key"),
      "-chain",
      p("ca.crt"),
      "-out",
      p("resp.tsr"),
    ]);

    // Sanity-check the token verifies before we commit it.
    openssl([
      "ts",
      "-verify",
      "-in",
      p("resp.tsr"),
      "-CAfile",
      p("ca.crt"),
      "-data",
      p("data.bin"),
    ]);

    const tsr = execFileSync("openssl", ["base64", "-A", "-in", p("resp.tsr")])
      .toString()
      .trim();
    const caCertPem = readFileSync(p("ca.crt"), "utf8");
    return { tsrBase64: tsr, caCertPem };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

/** @param {string} dir */
function tsaConfig(dir) {
  return [
    "[tsa]",
    "default_tsa = tsa_config",
    "",
    "[tsa_config]",
    `serial = ${join(dir, "serial")}`,
    "crypto_device = builtin",
    `signer_cert = ${join(dir, "tsa.crt")}`,
    `certs = ${join(dir, "ca.crt")}`,
    `signer_key = ${join(dir, "tsa.key")}`,
    "signer_digest = sha256",
    "default_policy = 1.3.6.1.4.1.99999.1.1",
    "digests = sha256, sha384, sha512",
    "accuracy = secs:1, millisecs:500, microsecs:100",
    "ordering = yes",
    "tsa_name = yes",
    "ess_cert_id_chain = no",
    "",
  ].join("\n");
}

/**
 * @param {Record<string, any>} obj
 * @param {(clone: any) => void} fn
 */
function mutate(obj, fn) {
  const clone = JSON.parse(JSON.stringify(obj));
  fn(clone);
  return clone;
}

/** @param {string} name @param {unknown} obj */
function writeJson(name, obj) {
  writeFileSync(join(FIXTURES, name), `${JSON.stringify(obj, null, 2)}\n`);
}
