#!/usr/bin/env node
/**
 * Builds the anchor-v2 fixture family: a synthetic, deterministic export
 * signed by a throwaway Ed25519 test key (embedded below — NOT a real HASP
 * signing key, never used for anything but these fixtures), exercising the
 * `sha256-fold-v2` anchor binding the real-crypto `valid.json` sample cannot
 * (it only carries a legacy `row-hash-v1` anchor).
 *
 * Deterministic and re-runnable: the keypair, ids, and timestamps are all
 * fixed constants, so re-running this script reproduces byte-identical
 * output (given a stable `src/canonical.js` / `src/fold.js`).
 *
 * Produces:
 *   valid-v2.json          — genesis-rooted, 4 entries, TWO v2 anchors (one
 *                             interior after entry 2, one at head after
 *                             entry 4) → anchoring passes, full coverage.
 *   insider-rewrite.json   — valid-v2 with entry 2's metadata rewritten,
 *                             hash recomputed, RE-SIGNED with the same test
 *                             key, and entry 3's prev_hash patched to match.
 *                             Chain + signatures + published-key still pass;
 *                             anchoring MUST fail (fold mismatch) — this is
 *                             the test proving the insider-rewrite gap v2
 *                             anchoring closes.
 *   unbindable-anchor.json — valid-v2 with the head anchor's
 *                             anchored_entry_id pointing at an entry id not
 *                             present in the export → anchoring fails.
 *   no-anchors.json        — valid-v2 with an empty tsa_anchor_chain →
 *                             anchoring fails without --allow-unanchored,
 *                             passes-with-warning with it.
 *   range-bounded-v2.json  — valid-v2 with export.range.from set (not
 *                             genesis-rooted) → the v2 anchors can't be
 *                             bound; anchoring fails asking for a full export.
 *   lineage-reset-v2.json  — a post-(foreign-truncation)-reset export: genesis-
 *                             rooted with a fresh anchor set (valid-v2 shape)
 *                             plus verification.lineage_reset_at. Verifies green
 *                             but must be surfaced as a reset lineage, never a
 *                             pristine full history.
 *   purge-rebased-v2.json  — the export shape after a retention purge
 *                             removed entries 1–2: only entries 3–4 remain
 *                             (re-sequenced, first prev_hash re-rooted to
 *                             null), verification.fold_base carries the fold
 *                             state over the purged prefix, and the head
 *                             anchor (minted pre-purge over the full history)
 *                             still binds because fold(fold_base, retained)
 *                             reproduces its anchored_data. The interior
 *                             anchor (whose anchored entry was purged) is
 *                             omitted, as the platform emitter omits
 *                             unbindable anchors.
 *   unattested-tail-v2.json — valid-v2 with only the INTERIOR anchor (the
 *                             head anchor at entry 4 is dropped): entries
 *                             1–2 are time-attested, entries 3–4 are signed
 *                             but not yet anchored. Verifies green — an
 *                             unanchored tail is normal, expected behavior,
 *                             not a failure — but the CLI must print a
 *                             prominent (not merely bulleted) warning naming
 *                             the first unattested seq (3).
 *   published-keys-v2.json — the published-keys document for this fixture
 *                             family's throwaway tenant (offline trust root
 *                             for the published-key check).
 *
 * All TSA fields carry placeholder base64 — these fixtures are exercised
 * with `skipTsa: true` (the anchoring check is pure computation and runs
 * regardless of that flag).
 *
 * Re-run if `src/canonical.js`, `src/fold.js`, or this script changes.
 */
import { createHash, createPrivateKey, createPublicKey, sign } from "node:crypto";
import { writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { canonicalizeForHash } from "../../src/canonical.js";
import { foldFrom } from "../../src/fold.js";

const here = dirname(fileURLToPath(import.meta.url));

// Throwaway Ed25519 test key, generated once for these fixtures. Never used
// for anything real — do not treat this as a HASP signing key.
const TEST_PRIVATE_KEY_PEM = `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIEsBAVoU7wLDugMUHg3XUpi49lM+eCYUaljLTdv0GDc1
-----END PRIVATE KEY-----
`;

const privateKey = createPrivateKey(TEST_PRIVATE_KEY_PEM);
const publicKey = createPublicKey(privateKey);
const PUBLIC_KEY_PEM = publicKey.export({ type: "spki", format: "pem" }).toString();

const TENANT = "Anchor V2 Fixture Tenant";
const TENANT_ID = "01v2fixture00000000000tenant";
const KEY_ID = "01v2fixture00000000000key01";
const ORG_ID = TENANT_ID;
const KEY_PUBLISHED_AT = "2026-07-19T00:00:00+00:00";
const EXPORTED_AT = "2026-07-20T00:00:00+00:00";
const EXPORTED_BY = "compliance@v2fixture.test";

/** Row hash exactly as `src/checks/chain.js` recomputes it. */
function rowHash(entry) {
  const payload = JSON.stringify([
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
  ]);
  return createHash("sha256").update(payload).digest("hex");
}

/** Ed25519 signature over the hex hash string, exactly as the platform signs rows. */
function signHash(hash) {
  const sig = sign(null, Buffer.from(hash, "utf8"), privateKey);
  return `ed25519:${sig.toString("base64")}`;
}

const ENTRY_TEMPLATES = [
  {
    id: "01v2fixture0000000000ent1",
    action: "assistant.message.sent",
    entity_type: "ai_chat_session",
    metadata: { model: "claude-sonnet-4-6", input_tokens: 120 },
  },
  {
    id: "01v2fixture0000000000ent2",
    action: "document.rag.ingested",
    entity_type: "document",
    metadata: { source: "referral.pdf", pages: 2 },
  },
  {
    id: "01v2fixture0000000000ent3",
    action: "policy.gateway.evaluated",
    entity_type: "gateway_request",
    metadata: { decision: "allow", policy_id: "phi-egress-guard" },
  },
  {
    id: "01v2fixture0000000000ent4",
    action: "audit.export.generated",
    entity_type: "audit_export",
    metadata: { range: "last_30_days", entry_count: 4 },
  },
];

/** Build the base (untampered) entries array, chained and signed. */
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
    };
    const hash = rowHash(base);
    entries.push({ ...base, hash, signature: signHash(hash) });
    prevHash = hash;
  }
  return entries;
}

/** Build the two v2 anchors (interior after entry 2, head after entry 4) for `entries`. */
function buildAnchors(entries) {
  const foldThrough2 = foldFrom([entries[0].hash, entries[1].hash]);
  const foldThrough4 = foldFrom(entries.map((e) => e.hash));
  return [
    {
      checkpoint_after_entry: 2,
      tsa_url: "https://tsa.v2fixture.test/tsr",
      tsa_cacert_url: "https://tsa.v2fixture.test/cacert.pem",
      tsa_tsr_base64: Buffer.from("placeholder-tsr-interior").toString("base64"),
      anchored_data: foldThrough2,
      anchored_at: "2026-07-20T00:00:01+00:00",
      algo: "sha256-fold-v2",
      anchored_entry_id: entries[1].id,
    },
    {
      checkpoint_after_entry: 4,
      tsa_url: "https://tsa.v2fixture.test/tsr",
      tsa_cacert_url: "https://tsa.v2fixture.test/cacert.pem",
      tsa_tsr_base64: Buffer.from("placeholder-tsr-head").toString("base64"),
      anchored_data: foldThrough4,
      anchored_at: "2026-07-20T00:00:03+00:00",
      algo: "sha256-fold-v2",
      anchored_entry_id: entries[3].id,
    },
  ];
}

function buildEnvelope(entries, anchors, rangeFrom = null) {
  return {
    schema_version: "1.0",
    export: {
      tenant: TENANT,
      tenant_id: TENANT_ID,
      range: { from: rangeFrom, to: null },
      exported_at: EXPORTED_AT,
      exported_by: EXPORTED_BY,
      entry_count: entries.length,
    },
    verification: {
      algo: "ed25519",
      public_key_pem: PUBLIC_KEY_PEM,
      key_id: KEY_ID,
      key_published_at: KEY_PUBLISHED_AT,
      chain_head_hash: entries[entries.length - 1].hash,
      tsa_anchor_chain: anchors,
    },
    entries,
  };
}

function clone(x) {
  return JSON.parse(JSON.stringify(x));
}

function write(name, obj) {
  writeFileSync(resolve(here, name), `${JSON.stringify(obj, null, 2)}\n`);
}

// --- valid-v2.json ---------------------------------------------------------
const baseEntries = buildEntries();
const baseAnchors = buildAnchors(baseEntries);
const validV2 = buildEnvelope(baseEntries, baseAnchors);
write("valid-v2.json", validV2);

// --- insider-rewrite.json ---------------------------------------------------
// Rewrite entry 2's metadata (an interior entry covered by the interior
// anchor), recompute its hash, re-sign it with the same test key, and patch
// entry 3's prev_hash so the row-hash chain itself stays internally
// consistent. Simulates an attacker with signing-key access rewriting
// already-anchored history: the row hash chain and signatures verify fine,
// but the anchored history fold no longer matches.
{
  const f = clone(validV2);
  const tampered = f.entries[1];
  tampered.metadata = { ...tampered.metadata, source: "TAMPERED.pdf" };
  const newHash = rowHash(tampered);
  tampered.hash = newHash;
  tampered.signature = signHash(newHash);
  f.entries[2].prev_hash = newHash;
  // chain_head_hash is entries[3].hash, which is untouched — still correct.
  write("insider-rewrite.json", f);
}

// --- unbindable-anchor.json --------------------------------------------------
{
  const f = clone(validV2);
  f.verification.tsa_anchor_chain[1].anchored_entry_id = "01v2fixture-does-not-exist";
  write("unbindable-anchor.json", f);
}

// --- no-anchors.json ---------------------------------------------------------
{
  const f = clone(validV2);
  f.verification.tsa_anchor_chain = [];
  write("no-anchors.json", f);
}

// --- range-bounded-v2.json -----------------------------------------------------
{
  const f = clone(validV2);
  f.export.range.from = "2026-07-01T00:00:00+00:00";
  write("range-bounded-v2.json", f);
}

// --- purge-rebased-v2.json ----------------------------------------------------
// Retention purge removed entries 1–2. The platform folded their hashes into
// the org's baseline (= fold_base), re-rooted the first retained entry's
// prev_hash to null, and re-sequenced the export. The pre-purge HEAD anchor
// still binds: fold(fold_base, [h3, h4]) === foldFrom([h1, h2, h3, h4]).
{
  const f = clone(validV2);
  const retained = f.entries.slice(2).map((e, i) => ({ ...e, seq: i + 1 }));
  retained[0].prev_hash = null;
  f.entries = retained;
  f.export.entry_count = retained.length;
  f.verification.fold_base = foldFrom([baseEntries[0].hash, baseEntries[1].hash]);
  // Only the head anchor survives: the interior anchor's anchored entry
  // (entry 2) was purged, so the platform marks it unbindable and omits it.
  const headAnchor = clone(baseAnchors[1]);
  // checkpoint_after_entry is the bound entry's seq WITHIN this export: the
  // head anchor's entry is now retained[1] (seq 2 post-purge), not seq 4.
  headAnchor.checkpoint_after_entry = 2;
  f.verification.tsa_anchor_chain = [headAnchor];
  write("purge-rebased-v2.json", f);
}

// --- lineage-reset-v2.json ----------------------------------------------------
// A post-reset export: the org's chain lineage was force-reset because a prefix
// was truncated outside retention maintenance, so it is genesis-rooted with a
// fresh anchor set (identical shape to valid-v2) BUT carries
// verification.lineage_reset_at. It must verify green (the retained rows are
// valid) while the verifier surfaces the reset loudly — it must never read as a
// pristine full history.
{
  const f = clone(validV2);
  f.verification.lineage_reset_at = "2026-07-19T12:00:00+00:00";
  write("lineage-reset-v2.json", f);
}

// --- unattested-tail-v2.json ---------------------------------------------------
{
  const f = clone(validV2);
  f.verification.tsa_anchor_chain = [f.verification.tsa_anchor_chain[0]];
  write("unattested-tail-v2.json", f);
}

// --- published-keys-v2.json ---------------------------------------------------
write("published-keys-v2.json", {
  tenant_id: TENANT_ID,
  keys: [
    {
      key_id: KEY_ID,
      public_key_pem: PUBLIC_KEY_PEM,
      published_at: KEY_PUBLISHED_AT,
      status: "active",
    },
  ],
});

console.log(
  "Wrote valid-v2.json, insider-rewrite.json, unbindable-anchor.json, " +
    "no-anchors.json, range-bounded-v2.json, purge-rebased-v2.json, " +
    "lineage-reset-v2.json, unattested-tail-v2.json, published-keys-v2.json",
);
