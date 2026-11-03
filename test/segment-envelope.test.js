/**
 * Customer-segment envelope variant (schema 1.1): end-to-end verification of
 * a synthetic scoped export, plus the tamper cases that define the variant's
 * security claims — thinned segments, reordered entries, stripped/re-homed
 * attribution, forged inclusion paths, and cross-variant confusion. All
 * offline: a throwaway ed25519 keypair signs the entries, the trust root is
 * injected via `expectedKey`, and the TSA check is skipped (token
 * verification over a root is exercised by the org-envelope TSA tests; the
 * segment path feeds the same check the batch ROOT instead of a fold state).
 */
import { createHash, sign as edSign, generateKeyPairSync } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { checkSegmentAnchoring } from "../src/checks/segment-anchoring.js";
import { foldFrom, GENESIS } from "../src/fold.js";
import { rootFromPath } from "../src/merkle.js";
import { verifyExport } from "../src/verify.js";

const { publicKey, privateKey } = generateKeyPairSync("ed25519");
const PUBLIC_PEM = publicKey.export({ type: "spki", format: "pem" }).toString();

const CUSTOMER = "01HKCUSTOMER00000000000000";

/** Hash an entry's canonical fields the platform way (attributed extended form). */
function entryHash(fields) {
  const payload = JSON.stringify([
    fields.user_id,
    fields.org_id,
    fields.project_id ?? null,
    fields.action,
    fields.entity_type,
    fields.entity_id,
    fields.metadata,
    fields.ip_address,
    fields.created_at,
    fields.phi_disposition ?? null,
    fields.subject_type ?? null,
    fields.subject_id_hmac ?? null,
    // Extension rule: the asserted slot is explicit-null whenever the
    // customer slot is present; these synthetic entries carry no assertion.
    null,
    fields.customer_id,
  ]);
  return createHash("sha256").update(payload).digest("hex");
}

/** Build a fixed-width padded tree the platform way (pad leaf = GENESIS). */
function buildTree(leaves, width) {
  let level = [...leaves, ...Array(width - leaves.length).fill(GENESIS)];
  const paths = leaves.map(() => []);
  const positions = leaves.map((_, i) => i);

  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) {
      next.push(
        createHash("sha256")
          .update(level[i] + level[i + 1], "ascii")
          .digest("hex"),
      );
    }
    positions.forEach((pos, leafIndex) => {
      const sibling = pos % 2 === 0 ? pos + 1 : pos - 1;
      paths[leafIndex].push({
        position: pos % 2 === 0 ? "right" : "left",
        hash: level[sibling],
      });
      positions[leafIndex] = Math.floor(pos / 2);
    });
    level = next;
  }
  return { root: level[0], paths };
}

/** Build a complete, internally consistent synthetic scoped export. */
function segmentEnvelope({ entryCount = 3, foldBase = undefined } = {}) {
  const entries = [];
  let prev = null;

  for (let i = 0; i < entryCount; i++) {
    const fields = {
      user_id: "01HKUSER000000000000000000",
      org_id: "01HKORG0000000000000000000",
      project_id: "01HKPROJECT000000000000000",
      customer_id: CUSTOMER,
      action: "record.created",
      entity_type: "project",
      entity_id: `01HKENTITY000000000000000${i}`,
      metadata: { n: i },
      ip_address: "203.0.113.7",
      created_at: `2026-07-2${i}T00:00:00+00:00`,
      phi_disposition: null,
      subject_type: null,
      subject_id_hmac: null,
    };
    const hash = entryHash(fields);
    entries.push({
      seq: i + 1,
      id: `01HKAUDIT0000000000000000${i}`,
      ...fields,
      segment_prev_hash: prev,
      hash,
      signature: `ed25519:${edSign(null, Buffer.from(hash, "ascii"), privateKey).toString("base64")}`,
    });
    prev = hash;
  }

  const foldState = foldFrom(
    entries.map((e) => e.hash),
    foldBase,
  );
  const tree = buildTree([foldState], 4);

  return {
    schema_version: "1.1",
    variant: "customer_segment",
    export: {
      tenant: "Acme Health",
      tenant_id: "01HKORG0000000000000000000",
      customer_id: CUSTOMER,
      customer_name: "Lakeside Family Clinic",
      range: { from: null, to: null },
      exported_at: "2026-07-23T00:00:00+00:00",
      exported_by: "builder@example.com",
      entry_count: entryCount,
    },
    verification: {
      algo: "ed25519",
      public_key_pem: PUBLIC_PEM,
      key_id: "01HKKEY0000000000000000000",
      key_published_at: "2026-07-01T00:00:00+00:00",
      segment_head_hash: entries.at(-1)?.hash ?? null,
      ...(foldBase ? { segment_fold_base: foldBase } : {}),
      segment_anchor_chain: [
        {
          checkpoint_after_entry: entryCount,
          fold_state: foldState,
          merkle_path: tree.paths[0],
          merkle_root: tree.root,
          tsa_url: "https://freetsa.org/tsr",
          tsa_cacert_url: "https://freetsa.org/files/cacert.pem",
          tsa_tsr_base64: Buffer.from("synthetic-token").toString("base64"),
          anchored_at: "2026-07-23T00:00:00+00:00",
          algo: "sha256-fold-merkle-v1",
          anchored_entry_id: entries.at(-1).id,
        },
      ],
    },
    entries,
  };
}

const OPTS = { skipTsa: true, expectedKey: PUBLIC_PEM };

describe("customer-segment envelope verification", () => {
  it("verifies a consistent scoped export end-to-end (schema, chain, key, signatures, anchoring)", async () => {
    const result = await verifyExport(segmentEnvelope(), OPTS);
    expect(result.checks.schema.ok).toBe(true);
    expect(result.checks.chain.ok).toBe(true);
    expect(result.checks.signatures.ok).toBe(true);
    expect(result.checks.anchoring.ok).toBe(true);
    expect(result.checks.anchoring.coverage.attested_through_seq).toBe(3);
    expect(result.checks.anchoring.coverage.unattested_from_seq).toBe(null);
    expect(result.ok).toBe(true);
  });

  it("verifies with a segment fold base (retention-rebased segment)", async () => {
    const base = createHash("sha256").update("purged-prefix", "ascii").digest("hex");
    const result = await verifyExport(segmentEnvelope({ foldBase: base }), OPTS);
    expect(result.ok).toBe(true);
  });

  it("surfaces lineage_reset_at without failing verification", async () => {
    const env = segmentEnvelope();
    env.verification.lineage_reset_at = "2026-07-20T00:00:00+00:00";
    const result = await verifyExport(env, OPTS);
    expect(result.ok).toBe(true);
    expect(result.lineage_reset_at).toBe("2026-07-20T00:00:00+00:00");
  });

  it("fails closed when the segment is THINNED (an interior entry omitted)", async () => {
    const env = segmentEnvelope();
    // Drop entry 2 and stitch the linkage so the naive chain looks intact.
    env.entries.splice(1, 1);
    env.entries[1].segment_prev_hash = env.entries[0].hash;
    env.entries[1].seq = 2;
    env.export.entry_count = 2;
    const result = await verifyExport(env, OPTS);
    // The anchored fold no longer recomputes — omission is detectable.
    expect(result.ok).toBe(false);
    expect(result.checks.anchoring.ok).toBe(false);
    expect(result.checks.anchoring.error).toContain("fold mismatch");
  });

  it("fails closed when the TAIL is truncated below the anchored entry", async () => {
    const env = segmentEnvelope();
    env.entries.pop();
    env.export.entry_count = 2;
    env.verification.segment_head_hash = env.entries.at(-1).hash;
    const result = await verifyExport(env, OPTS);
    expect(result.ok).toBe(false);
    expect(result.checks.anchoring.error).toContain("not among the exported entries");
  });

  it("fails closed when attribution is re-homed on an entry", async () => {
    const env = segmentEnvelope();
    env.entries[1].customer_id = "01HKOTHERCUSTOMER000000000";
    const result = await verifyExport(env, OPTS);
    // Schema consistency catches it first (one segment per export)…
    expect(result.ok).toBe(false);
    // …and even if it didn't, the sealed hash would: recompute directly.
    env.entries[1].customer_id = CUSTOMER;
    env.export.customer_id = "01HKOTHERCUSTOMER000000000";
    for (const e of env.entries) {
      e.customer_id = "01HKOTHERCUSTOMER000000000";
    }
    env.export.customer_name = "Mallory Clinic";
    const rehomed = await verifyExport(env, OPTS);
    expect(rehomed.ok).toBe(false);
    expect(rehomed.checks.chain.ok).toBe(false);
  });

  it("fails closed on a forged inclusion path", async () => {
    const env = segmentEnvelope();
    env.verification.segment_anchor_chain[0].merkle_path[0].hash = "f".repeat(64);
    const result = await verifyExport(env, OPTS);
    expect(result.checks.anchoring.ok).toBe(false);
    expect(result.checks.anchoring.error).toContain("inclusion mismatch");
  });

  it("fails closed when a segment envelope smuggles org-chain prev_hash", async () => {
    const env = segmentEnvelope();
    env.entries[0].prev_hash = null;
    const result = await verifyExport(env, OPTS);
    expect(result.checks.schema.ok).toBe(false);
    expect(result.checks.schema.error).toContain("prev_hash");
  });

  it("fails closed on zero anchors unless allowUnanchored", async () => {
    const env = segmentEnvelope();
    env.verification.segment_anchor_chain = [];
    const failed = await verifyExport(env, OPTS);
    expect(failed.ok).toBe(false);

    const allowed = await verifyExport(env, { ...OPTS, allowUnanchored: true });
    expect(allowed.ok).toBe(true);
    expect(allowed.checks.anchoring.attested).toBe("none");
  });

  it("rejects an unknown variant and a 1.1 envelope without a variant", async () => {
    const env = segmentEnvelope();
    env.variant = "something_else";
    expect((await verifyExport(env, OPTS)).checks.schema.ok).toBe(false);

    const org10 = segmentEnvelope();
    delete org10.variant;
    expect((await verifyExport(org10, OPTS)).checks.schema.ok).toBe(false);
  });
});

describe("segment anchoring unit behavior", () => {
  it("reports a signed-but-not-yet-anchored tail", () => {
    const env = segmentEnvelope();
    // Re-anchor at entry 2 instead of the head.
    const foldThrough2 = foldFrom(env.entries.slice(0, 2).map((e) => e.hash));
    const tree = buildTree([foldThrough2], 4);
    env.verification.segment_anchor_chain = [
      {
        ...env.verification.segment_anchor_chain[0],
        checkpoint_after_entry: 2,
        fold_state: foldThrough2,
        merkle_path: tree.paths[0],
        merkle_root: tree.root,
        anchored_entry_id: env.entries[1].id,
      },
    ];
    const result = checkSegmentAnchoring(env);
    expect(result.ok).toBe(true);
    expect(result.coverage.attested_through_seq).toBe(2);
    expect(result.coverage.unattested_from_seq).toBe(3);
  });

  it("path depth is constant for the batch width regardless of leaf count", () => {
    const leafA = createHash("sha256").update("a", "ascii").digest("hex");
    const solo = buildTree([leafA], 8);
    expect(solo.paths[0]).toHaveLength(3);
    expect(rootFromPath(leafA, solo.paths[0])).toBe(solo.root);
  });
});

describe("committed customer-scoped sample fixture", () => {
  it("verifies the committed segment fixture end-to-end (offline; TSA path gated in CI)", async () => {
    const here = dirname(fileURLToPath(import.meta.url));
    const fixture = JSON.parse(
      readFileSync(resolve(here, "fixtures", "valid-segment.json"), "utf8"),
    );
    const result = await verifyExport(fixture, {
      skipTsa: true,
      keysFile: resolve(here, "fixtures", "published-keys.json"),
    });
    expect(result.checks.schema.ok).toBe(true);
    expect(result.checks.chain.ok).toBe(true);
    expect(result.checks.signatures.ok).toBe(true);
    expect(result.checks.anchoring.ok).toBe(true);
    expect(result.ok).toBe(true);
  });
});
