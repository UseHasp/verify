#!/usr/bin/env node
/**
 * Regenerates every fixture from a fixed keypair + the real freetsa anchor.
 *
 * Outputs (all committed):
 *   valid.json            — golden schema-1.0 export; real per-entry Ed25519
 *                           signatures over the hash hex, real prev_hash chain
 *                           rooted at genesis (null), real freetsa RFC 3161 TSR.
 *   trust-keys.json       — the /trust/keys/{tenant_id} response for the export's
 *                           signing key (the independent trust root).
 *   published-key.pem     — the same published key as a PEM, for --key-file.
 *   broken-hash.json      — a field mutated after signing (hash no longer matches).
 *   broken-chain.json     — a prev_hash linkage broken mid-chain.
 *   broken-signature.json — one entry's signature bytes flipped.
 *   forged-chain.json     — the whole chain re-signed with an ATTACKER keypair
 *                           whose public key is embedded in the export. Passes
 *                           schema/chain/signature but must fail the published-key
 *                           match — this is the security-critical case.
 *   broken-tsa.json       — the TSR bytes corrupted.
 *
 * The keypairs and the freetsa TSR are pinned so regeneration is deterministic.
 * Re-run after changing the contract:  node test/fixtures/generate.js
 */
import { createHash, createPrivateKey, sign as edSign } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { canonicalEntryPayload } from "../../src/canonical.js";

const here = dirname(fileURLToPath(import.meta.url));
const out = (name) => resolve(here, name);

// ── Pinned key material (fictional; generated once for the fixtures) ──────────
const LEGIT_PRIV_PEM = `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIBSgf92V8Kr5Y1yNhOoVSMyR6dBURlcz9fBp9POKalrL
-----END PRIVATE KEY-----
`;
const LEGIT_PUB_PEM = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAad/8yq23MMLSNVcn/vBYfkcN8HzvTeZrAJODh5046JA=
-----END PUBLIC KEY-----
`;
const ATTACKER_PRIV_PEM = `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIDJgJ6Caed/KNEffSrypy5A99vm838NMZocX39gFskup
-----END PRIVATE KEY-----
`;
const ATTACKER_PUB_PEM = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAGN5K/b/2Xpp840DyokRNJv3i7zJX1PfNnGNknWjxgZI=
-----END PUBLIC KEY-----
`;

const legitKey = createPrivateKey(LEGIT_PRIV_PEM);
const attackerKey = createPrivateKey(ATTACKER_PRIV_PEM);

// Real freetsa RFC 3161 TSR + the exact hash it covers (openssl ts -verify OK
// over the ASCII hex string). anchored_data is therefore that hash, anchored as
// the hex-ASCII string — matching the platform's AuditExportEnvelopeBuilder.
const FREETSA_TSR_B64 = readFileSync(out("freetsa-anchor.tsr.b64"), "utf8").trim();
const FREETSA_ANCHORED_DATA = readFileSync(out("freetsa-anchored-data.txt"), "utf8").trim();

const TENANT_ID = "org_01HV9WX3PQ8CK6N5Z2T4M7Y0HD";
const KEY_ID = "key_01HV0F3JBA7Z2N8D5Q3R7V8M1C";
const KEY_PUBLISHED_AT = "2026-04-01T00:00:00+00:00";

// Fixed HMAC-shaped subject identifier (opaque 64-hex).
const SUBJECT_HMAC = "3d2b1f0e9c8a7b6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d";

/** @param {import("node:crypto").KeyObject} key */
function sign(hashHex, key) {
  const sig = edSign(null, Buffer.from(hashHex, "utf8"), key);
  return `ed25519:${sig.toString("base64")}`;
}

function hashOf(entry) {
  return createHash("sha256").update(canonicalEntryPayload(entry)).digest("hex");
}

/**
 * The twelve hashed fields of each entry, in the source's own (deliberately
 * unsorted-metadata) form. hash/signature/prev_hash are added by buildChain.
 * `metadata` keys are intentionally out of lexical order — and one value carries
 * a slash + multibyte character — so the fixture exercises canonical key-sort
 * and UNESCAPED_SLASHES/UNESCAPED_UNICODE byte-parity.
 */
const ENTRY_SEEDS = [
  {
    user_id: "user_01HV9WY1FQ3K8M5N2T7P0R4S6X",
    org_id: TENANT_ID,
    project_id: "proj_01HV9WXA2B3C4D5E6F7G8H9J0K",
    action: "ai.chat.message",
    entity_type: "ai_chat_session",
    entity_id: "chat_01HV9WY3FZ2K6N5M8T7P0R4S6X",
    metadata: {
      model: "claude-sonnet-4-6",
      input_tokens: 412,
      phi_scan: {
        redaction_count: 2,
        engine: "hasp-phi-scan-v1",
        categories_detected: ["NAME", "DATE_OF_BIRTH"],
        action: "redact",
        note: "façade/naïve path é",
      },
    },
    ip_address: "198.51.100.24",
    created_at: "2026-04-25T14:02:11+00:00",
    phi_disposition: "redacted_at_delivery",
    subject_type: "patient",
    subject_id_hmac: SUBJECT_HMAC,
  },
  {
    user_id: "user_01HV9WY1FQ3K8M5N2T7P0R4S6X",
    org_id: TENANT_ID,
    project_id: "proj_01HV9WXA2B3C4D5E6F7G8H9J0K",
    action: "ai.chat.response",
    entity_type: "ai_chat_session",
    entity_id: "chat_01HV9WY3FZ2K6N5M8T7P0R4S6X",
    metadata: { output_tokens: 287, model: "claude-sonnet-4-6", finish_reason: "stop" },
    ip_address: "198.51.100.24",
    created_at: "2026-04-25T14:02:14+00:00",
    phi_disposition: "reidentified_at_delivery",
    subject_type: "patient",
    subject_id_hmac: SUBJECT_HMAC,
  },
  {
    // System / API-key actor: user_id, project_id and subject fields are null.
    user_id: null,
    org_id: TENANT_ID,
    project_id: null,
    action: "data.record.create",
    entity_type: "app_entity_record",
    entity_id: "rec_01HV9X02M3N4P5Q6R7S8T9U0V1",
    metadata: { source: "ehr-bridge", entity: "encounter" },
    ip_address: "10.0.42.18",
    created_at: "2026-04-25T14:08:42+00:00",
    phi_disposition: "not_present",
    subject_type: null,
    subject_id_hmac: null,
  },
  {
    user_id: "user_01HV9X1B3C4D5E6F7G8H9J0K1L",
    org_id: TENANT_ID,
    project_id: "proj_01HV9WXA2B3C4D5E6F7G8H9J0K",
    action: "audit.export.request",
    entity_type: "audit_export",
    entity_id: "exp_01HV9X2N3P4Q5R6S7T8U9V0W1X",
    metadata: { format: "json", range: "2026-04-25" },
    ip_address: null,
    created_at: "2026-04-25T14:11:55+00:00",
    phi_disposition: "not_present",
    subject_type: null,
    subject_id_hmac: null,
  },
];

/**
 * Compute the hash chain and per-entry signatures over a list of entry seeds.
 * Genesis prev_hash is `null` (matches the platform: the first entry's prev_hash
 * is the chain anchor and is not linkage-checked).
 * @param {import("node:crypto").KeyObject} signingKey
 */
function buildChain(signingKey) {
  const entries = [];
  let prev = null;
  for (const seed of ENTRY_SEEDS) {
    const hash = hashOf(seed);
    entries.push({
      ...seed,
      prev_hash: prev,
      hash,
      signature: sign(hash, signingKey),
    });
    prev = hash;
  }
  return entries;
}

function buildEnvelope(entries, publicKeyPem) {
  const chainHead = entries[entries.length - 1].hash;
  return {
    schema_version: "1.0",
    export: {
      tenant: "Northridge Health",
      tenant_id: TENANT_ID,
      range: {
        from: "2026-04-25T00:00:00+00:00",
        to: "2026-04-25T23:59:59+00:00",
      },
      exported_at: "2026-04-25T14:12:03+00:00",
      exported_by: "auditor@acme-cpa.example",
      entry_count: entries.length,
    },
    verification: {
      algo: "ed25519",
      public_key_pem: publicKeyPem,
      key_id: KEY_ID,
      key_published_at: KEY_PUBLISHED_AT,
      chain_head_hash: chainHead,
      tsa_anchor_chain: [
        {
          checkpoint_after_entry: entries.length,
          tsa_url: "https://freetsa.org/tsr",
          tsa_cacert_url: "https://freetsa.org/files/cacert.pem",
          tsa_tsr_base64: FREETSA_TSR_B64,
          anchored_data: FREETSA_ANCHORED_DATA,
          anchored_at: "2026-05-21T02:15:12+00:00",
        },
      ],
      instructions: "https://usehasp.com/trust/verify",
    },
    entries,
  };
}

const clone = (x) => JSON.parse(JSON.stringify(x));
const write = (name, obj) => writeFileSync(out(name), `${JSON.stringify(obj, null, 2)}\n`);

// ── valid.json — the golden export ────────────────────────────────────────────
const valid = buildEnvelope(buildChain(legitKey), LEGIT_PUB_PEM);
write("valid.json", valid);

// ── trust-keys.json + published-key.pem — the independent trust root ──────────
write("trust-keys.json", {
  tenant_id: TENANT_ID,
  keys: [
    {
      key_id: KEY_ID,
      public_key_pem: LEGIT_PUB_PEM,
      published_at: KEY_PUBLISHED_AT,
      status: "active",
    },
  ],
});
writeFileSync(out("published-key.pem"), LEGIT_PUB_PEM);

// ── broken-hash.json — mutate a field after signing (hash mismatch) ──────────
{
  const f = clone(valid);
  f.entries[1].action = "ai.chat.response.tampered";
  write("broken-hash.json", f);
}

// ── broken-chain.json — break a prev_hash linkage mid-chain ──────────────────
{
  const f = clone(valid);
  f.entries[2].prev_hash = "0".repeat(64);
  write("broken-chain.json", f);
}

// ── broken-signature.json — flip one entry's signature bytes ─────────────────
{
  const f = clone(valid);
  const e = f.entries[0];
  const [algo, b64] = e.signature.split(":");
  const buf = Buffer.from(b64, "base64");
  buf[0] ^= 0x01;
  e.signature = `${algo}:${buf.toString("base64")}`;
  write("broken-signature.json", f);
}

// ── forged-chain.json — whole chain re-signed by an attacker key, attacker's
//    public key embedded. Self-consistent (schema/chain/signature all pass) but
//    the embedded key does not match the published trust root, so the
//    published-key check must fail closed. This is the forgery gap. ───────────
{
  const forged = buildEnvelope(buildChain(attackerKey), ATTACKER_PUB_PEM);
  write("forged-chain.json", forged);
}

// ── broken-tsa.json — corrupt the TSR bytes ──────────────────────────────────
{
  const f = clone(valid);
  const a = f.verification.tsa_anchor_chain[0];
  const buf = Buffer.from(a.tsa_tsr_base64, "base64");
  buf[10] ^= 0xff;
  a.tsa_tsr_base64 = buf.toString("base64");
  write("broken-tsa.json", f);
}

console.log(
  "Wrote valid.json, trust-keys.json, published-key.pem, broken-{hash,chain,signature,tsa}.json, forged-chain.json",
);
