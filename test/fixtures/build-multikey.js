#!/usr/bin/env node
/**
 * Builds the multi-key fixture family: a synthetic, deterministic export
 * signed by TWO throwaway Ed25519 test keys (embedded below — NOT real HASP
 * signing keys, never used for anything but these fixtures), exercising
 * multi-key envelopes (a rotation occurred inside the export window) and the
 * caller_attribution/user_agent extension slots (15/16).
 *
 * Deterministic and re-runnable: the keypairs, ids, and timestamps are all
 * fixed constants, so re-running this script reproduces byte-identical
 * output (given a stable `src/canonical.js`).
 *
 * Produces:
 *   valid-multikey.json       — genesis-rooted, 3 entries: entry 1 signed
 *                                under key A, entries 2-3 signed under key B
 *                                (a rotation occurred between them).
 *                                verification.keys[] carries both keys; every
 *                                entry carries its own key_id. Entry 2 also
 *                                carries a populated caller_attribution and
 *                                user_agent (slots 15/16).
 *   tampered-attribution.json — valid-multikey with entry 2's
 *                                caller_attribution mutated (delegated agent
 *                                swapped) WITHOUT recomputing the hash —
 *                                chain check must fail.
 *   wrong-entry-key.json      — valid-multikey with entry 1's key_id
 *                                repointed at key B (the key that did NOT
 *                                sign it) — signature check must fail closed.
 *   published-keys-multikey.json — the published-keys document for this
 *                                fixture family's throwaway tenant, carrying
 *                                both keys (offline trust root).
 *
 * TSA fields carry placeholder base64 — these fixtures are exercised with
 * `skipTsa: true`.
 *
 * Re-run if `src/canonical.js` or this script changes.
 */
import { createHash, createPrivateKey, createPublicKey, sign } from "node:crypto";
import { writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { canonicalizeForHash } from "../../src/canonical.js";

const here = dirname(fileURLToPath(import.meta.url));

// Two throwaway Ed25519 test keys, generated once for these fixtures. Never
// used for anything real — do not treat these as HASP signing keys.
const KEY_A_PEM = `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIB1L1uRQ9YRIsPILKGpMFVUgQd0BEqzYYQFqQnBW5fXm
-----END PRIVATE KEY-----
`;
const KEY_B_PEM = `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIF3fW2X8pQwZ2f0GzKlR3E+M8m6xWKcTLQxrM9d0v0kM
-----END PRIVATE KEY-----
`;

const privateKeyA = createPrivateKey(KEY_A_PEM);
const publicKeyA = createPublicKey(privateKeyA);
const PUBLIC_KEY_A_PEM = publicKeyA.export({ type: "spki", format: "pem" }).toString();

const privateKeyB = createPrivateKey(KEY_B_PEM);
const publicKeyB = createPublicKey(privateKeyB);
const PUBLIC_KEY_B_PEM = publicKeyB.export({ type: "spki", format: "pem" }).toString();

const TENANT = "Multi-Key Fixture Tenant";
const TENANT_ID = "01mkfixture0000000000tenant";
const ORG_ID = TENANT_ID;
const KEY_A_ID = "01mkfixture000000000000key1";
const KEY_B_ID = "01mkfixture000000000000key2";
const KEY_A_PUBLISHED_AT = "2026-07-01T00:00:00+00:00";
const KEY_B_PUBLISHED_AT = "2026-07-19T00:00:00+00:00";
const EXPORTED_AT = "2026-07-20T00:00:00+00:00";
const EXPORTED_BY = "compliance@mkfixture.test";

/** Row hash exactly as `src/checks/chain.js` recomputes it (base 12 + presence-conditional extension slots). */
function rowHash(entry) {
  const fields = [
    entry.user_id,
    entry.org_id,
    entry.project_id ?? null,
    entry.action,
    entry.entity_type,
    entry.entity_id,
    canonicalizeForHash(entry.metadata),
    entry.ip_address,
    entry.created_at,
    entry.phi_disposition ?? null,
    entry.subject_type ?? null,
    entry.subject_id_hmac ?? null,
  ];
  const asserted = entry.asserted_actor_hmac ?? null;
  const customer = entry.customer_id ?? null;
  const callerAttribution = entry.caller_attribution ?? null;
  const userAgent = entry.user_agent ?? null;
  const callerAttributionPresent = callerAttribution !== null;
  const userAgentPresent = userAgent !== null;
  if (asserted !== null || customer !== null || callerAttributionPresent || userAgentPresent) {
    fields.push(asserted);
  }
  if (customer !== null || callerAttributionPresent || userAgentPresent) {
    fields.push(customer);
  }
  if (callerAttributionPresent || userAgentPresent) {
    fields.push(canonicalizeForHash(callerAttribution));
  }
  if (userAgentPresent) {
    fields.push(userAgent);
  }
  return createHash("sha256").update(JSON.stringify(fields)).digest("hex");
}

/** Ed25519 signature over the hex hash string, exactly as the platform signs rows. */
function signHash(hash, privateKey) {
  const sig = sign(null, Buffer.from(hash, "utf8"), privateKey);
  return `ed25519:${sig.toString("base64")}`;
}

function clone(x) {
  return JSON.parse(JSON.stringify(x));
}

function write(name, obj) {
  writeFileSync(resolve(here, name), `${JSON.stringify(obj, null, 2)}\n`);
}

const ENTRY_TEMPLATES = [
  {
    id: "01mkfixture00000000000ent1",
    action: "assistant.message.sent",
    entity_type: "ai_chat_session",
    metadata: { model: "claude-sonnet-4-6", input_tokens: 88 },
    key: "A",
  },
  {
    id: "01mkfixture00000000000ent2",
    action: "workflow.run.step_completed",
    entity_type: "workflow_run",
    metadata: { step: "route" },
    key: "B",
    caller_attribution: {
      caller_type: "agent",
      caller_id: "01mkfixture0000000000cred1",
      org_id: ORG_ID,
      delegating_user_id: "01mkfixture0000000000user1",
      personal_access_token_id: null,
      agent_credential_id: "01mkfixture0000000000cred1",
      agent_id: "01mkfixture000000000agent1",
      delegation_chain: ["01mkfixture0000000000user1"],
    },
    user_agent: "HaspAgentSDK/1.0",
  },
  {
    id: "01mkfixture00000000000ent3",
    action: "audit.export.generated",
    entity_type: "audit_export",
    metadata: { range: "last_30_days", entry_count: 3 },
    key: "B",
  },
];

function buildEntries() {
  const entries = [];
  let prevHash = null;
  for (const [i, t] of ENTRY_TEMPLATES.entries()) {
    const base = {
      seq: i + 1,
      id: t.id,
      user_id: null,
      org_id: ORG_ID,
      project_id: null,
      action: t.action,
      entity_type: t.entity_type,
      entity_id: null,
      metadata: t.metadata,
      ip_address: "127.0.0.1",
      created_at: `2026-07-20T00:00:0${i}+00:00`,
      phi_disposition: null,
      subject_type: null,
      subject_id_hmac: null,
      prev_hash: prevHash,
      ...(t.caller_attribution ? { caller_attribution: t.caller_attribution } : {}),
      ...(t.user_agent ? { user_agent: t.user_agent } : {}),
    };
    const hash = rowHash(base);
    const privateKey = t.key === "A" ? privateKeyA : privateKeyB;
    const keyId = t.key === "A" ? KEY_A_ID : KEY_B_ID;
    entries.push({ ...base, hash, signature: signHash(hash, privateKey), key_id: keyId });
    prevHash = hash;
  }
  return entries;
}

function buildEnvelope(entries) {
  return {
    schema_version: "1.0",
    export: {
      tenant: TENANT,
      tenant_id: TENANT_ID,
      range: { from: null, to: null },
      exported_at: EXPORTED_AT,
      exported_by: EXPORTED_BY,
      entry_count: entries.length,
    },
    verification: {
      algo: "ed25519",
      keys: [
        { key_id: KEY_A_ID, public_key_pem: PUBLIC_KEY_A_PEM, published_at: KEY_A_PUBLISHED_AT },
        { key_id: KEY_B_ID, public_key_pem: PUBLIC_KEY_B_PEM, published_at: KEY_B_PUBLISHED_AT },
      ],
      chain_head_hash: entries[entries.length - 1].hash,
      tsa_anchor_chain: [
        {
          checkpoint_after_entry: 3,
          tsa_url: "https://tsa.mkfixture.test/tsr",
          tsa_cacert_url: "https://tsa.mkfixture.test/cacert.pem",
          tsa_tsr_base64: Buffer.from("placeholder-tsr-head").toString("base64"),
          anchored_data: entries[entries.length - 1].hash,
          anchored_at: "2026-07-20T00:00:03+00:00",
          algo: "row-hash-v1",
          anchored_entry_id: entries[entries.length - 1].id,
        },
      ],
    },
    entries,
  };
}

// --- valid-multikey.json -----------------------------------------------------
const baseEntries = buildEntries();
const validMultikey = buildEnvelope(baseEntries);
write("valid-multikey.json", validMultikey);

// --- tampered-attribution.json ------------------------------------------------
// Swap the delegated agent id on entry 2's caller_attribution WITHOUT
// recomputing the hash — simulates an insider bypassing the immutability
// triggers to rewrite which agent performed the action.
{
  const f = clone(validMultikey);
  f.entries[1].caller_attribution.agent_id = "01mkfixture000000EVILAGENT0";
  write("tampered-attribution.json", f);
}

// --- wrong-entry-key.json -----------------------------------------------------
// Entry 1 (genuinely signed by key A) is repointed at key B in the envelope —
// the wrong-per-entry key must fail closed rather than silently trying every
// published key.
{
  const f = clone(validMultikey);
  f.entries[0].key_id = KEY_B_ID;
  write("wrong-entry-key.json", f);
}

// --- published-keys-multikey.json ---------------------------------------------
write("published-keys-multikey.json", {
  tenant_id: TENANT_ID,
  keys: [
    {
      key_id: KEY_A_ID,
      public_key_pem: PUBLIC_KEY_A_PEM,
      published_at: KEY_A_PUBLISHED_AT,
      status: "retired",
    },
    {
      key_id: KEY_B_ID,
      public_key_pem: PUBLIC_KEY_B_PEM,
      published_at: KEY_B_PUBLISHED_AT,
      status: "active",
    },
  ],
});

console.log(
  "Wrote valid-multikey.json, tampered-attribution.json, wrong-entry-key.json, published-keys-multikey.json",
);
