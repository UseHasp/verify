/**
 * Check 0: schema sanity.
 *
 * Validates the top-level shape and required fields of the platform
 * audit-export envelope (produced by `AuditExportEnvelopeBuilder`). Does not
 * validate cryptographic content — that's the job of the other checks. The
 * goal here is to fail loudly and early on malformed input, so later checks can
 * assume the fields exist.
 *
 * Supported schema_version: "1.0" (org-grain envelope, no variant key) and
 * "1.1" with `variant: "customer_segment"` (the customer-scoped segment
 * export — one end-customer's entries, segment linkage instead of org-chain
 * linkage, Merkle-batched segment anchors).
 */

const SUPPORTED_SCHEMA = "1.0";
const SEGMENT_SCHEMA = "1.1";
const SEGMENT_VARIANT = "customer_segment";
const HEX64 = /^[0-9a-f]{64}$/;

/**
 * Flat entry columns emitted by the platform (no nested actor/resource/timestamp
 * objects). Presence is required for every entry; nullable columns may hold null.
 */
const ENTRY_KEYS = [
  "seq",
  "id",
  "user_id",
  "org_id",
  "project_id",
  "action",
  "entity_type",
  "entity_id",
  "metadata",
  "ip_address",
  "created_at",
  "phi_disposition",
  "subject_type",
  "subject_id_hmac",
  "prev_hash",
  "hash",
  "signature",
];

/**
 * @param {any} data parsed export JSON
 * @returns {{ok: true} | {ok: false, error: string}}
 */
export function checkSchema(data) {
  if (!data || typeof data !== "object") {
    return fail("export is not a JSON object");
  }
  if (data.schema_version === SEGMENT_SCHEMA || "variant" in data) {
    return checkSegmentSchema(data);
  }
  if (data.schema_version !== SUPPORTED_SCHEMA) {
    return fail(
      `unsupported schema_version: ${JSON.stringify(data.schema_version)} (this tool supports "${SUPPORTED_SCHEMA}" and "${SEGMENT_SCHEMA}" — see https://github.com/UseHasp/verify#versioning--support for the compatibility table)`,
    );
  }

  const e = data.export;
  if (!e || typeof e !== "object") return fail("missing .export object");
  for (const k of ["tenant", "tenant_id", "range", "exported_at", "exported_by", "entry_count"]) {
    if (!(k in e)) return fail(`missing .export.${k}`);
  }
  if (typeof e.entry_count !== "number") {
    return fail(".export.entry_count must be a number");
  }
  if (!e.range || typeof e.range !== "object" || Array.isArray(e.range)) {
    return fail(".export.range must be an object");
  }
  // The platform emits null from/to for an unbounded export window.
  for (const k of ["from", "to"]) {
    if (!(k in e.range)) return fail(`missing .export.range.${k}`);
    if (e.range[k] !== null && typeof e.range[k] !== "string") {
      return fail(`.export.range.${k} must be an ISO8601 string or null`);
    }
  }

  const v = data.verification;
  if (!v || typeof v !== "object") return fail("missing .verification object");
  if (v.algo !== "ed25519") {
    return fail(`unsupported .verification.algo: ${JSON.stringify(v.algo)} (expected "ed25519")`);
  }
  for (const k of ["chain_head_hash", "tsa_anchor_chain"]) {
    if (!(k in v)) return fail(`missing .verification.${k}`);
  }
  if (typeof v.chain_head_hash !== "string" || !HEX64.test(v.chain_head_hash)) {
    return fail(".verification.chain_head_hash must be 64 hex chars (SHA-256)");
  }

  // Multi-key envelopes: `verification.keys[]` is emitted ONLY
  // when the export window spans more than one signing key (a rotation
  // occurred inside the window) — a single-key export keeps the exact
  // pre-multi-key shape (singular public_key_pem/key_id/key_published_at,
  // no per-entry key_id), so the committed sample and the anti-drift
  // contract stay byte-identical. When `keys` IS present, every entry must
  // carry its own `key_id` selecting which published key signed it.
  const multiKeyResult = validateMultiKeyEnvelope(v);
  if (!multiKeyResult.ok) return multiKeyResult;
  const hasMultipleKeys = multiKeyResult.hasMultipleKeys;
  // `fold_base` is optional: absent/null means the history fold starts from
  // GENESIS. When present it is the fold state the retained chain starts
  // from (the platform's retention purge rebases the fold at the retention
  // boundary). The anchoring check consumes it; here we only bound the type.
  if ("fold_base" in v && v.fold_base !== undefined && v.fold_base !== null) {
    if (typeof v.fold_base !== "string" || !HEX64.test(v.fold_base)) {
      return fail(".verification.fold_base must be 64 hex chars (SHA-256 fold state) or null");
    }
  }

  // `lineage_reset_at` is optional: present (a non-empty string) only when the
  // platform force-reset this org's chain lineage because a prefix was
  // truncated outside retention maintenance. Its presence means pre-reset
  // history is absent and unverifiable — the verifier surfaces it loudly, but
  // it is not a shape error. Here we only bound the type.
  if ("lineage_reset_at" in v && v.lineage_reset_at !== undefined && v.lineage_reset_at !== null) {
    if (typeof v.lineage_reset_at !== "string" || v.lineage_reset_at.length === 0) {
      return fail(".verification.lineage_reset_at must be an ISO 8601 string or null");
    }
  }
  if (!Array.isArray(v.tsa_anchor_chain)) {
    return fail(".verification.tsa_anchor_chain must be an array");
  }
  // Empty is legal: an org with no anchors yet, or a range containing none.
  // The (always-on) anchoring check enforces whether that's acceptable.
  for (const [i, a] of v.tsa_anchor_chain.entries()) {
    for (const k of [
      "checkpoint_after_entry",
      "tsa_url",
      "tsa_cacert_url",
      "tsa_tsr_base64",
      "anchored_data",
    ]) {
      if (!(k in a)) return fail(`missing .verification.tsa_anchor_chain[${i}].${k}`);
    }
    for (const [k, validate] of ANCHOR_URL_FIELDS) {
      const urlErr = validate(a[k]);
      if (urlErr) return fail(`.verification.tsa_anchor_chain[${i}].${k}: ${urlErr}`);
    }
    // The platform anchors this value directly (hex2bin of it is the raw 32
    // bytes placed in the RFC 3161 messageImprint) — a single row's hash (v1)
    // or a history-fold state (v2). Which entry(ies) it actually attests to
    // is a binding question, not a shape question — see checks/anchoring.js.
    if (typeof a.anchored_data !== "string" || !HEX64.test(a.anchored_data)) {
      return fail(
        `.verification.tsa_anchor_chain[${i}].anchored_data must be 64 hex chars (got ${JSON.stringify(a.anchored_data)})`,
      );
    }
    // `algo` is optional: absent means the legacy v1 (row-hash) anchor. When
    // present it must be one of the two recognised anchor versions.
    if ("algo" in a && a.algo !== undefined) {
      if (a.algo !== "row-hash-v1" && a.algo !== "sha256-fold-v2") {
        return fail(
          `.verification.tsa_anchor_chain[${i}].algo must be "row-hash-v1" or "sha256-fold-v2" (got ${JSON.stringify(a.algo)})`,
        );
      }
    }
    const algo = a.algo ?? "row-hash-v1";
    if (algo === "sha256-fold-v2") {
      // v2 anchors attest a specific entry's position in the fold; the
      // binding check needs it, so it's required whenever algo is v2.
      if (typeof a.anchored_entry_id !== "string" || a.anchored_entry_id.length === 0) {
        return fail(
          `.verification.tsa_anchor_chain[${i}].anchored_entry_id is required when algo is "sha256-fold-v2"`,
        );
      }
    } else if (
      "anchored_entry_id" in a &&
      a.anchored_entry_id !== undefined &&
      a.anchored_entry_id !== null &&
      typeof a.anchored_entry_id !== "string"
    ) {
      // v1 anchors may carry a null anchored_entry_id (legacy rows have no
      // latest_entry_id) or omit it; if present and non-null it must be a string.
      return fail(
        `.verification.tsa_anchor_chain[${i}].anchored_entry_id must be a string or null when present`,
      );
    }
  }

  if (!Array.isArray(data.entries)) return fail("missing .entries array");
  if (data.entries.length !== e.entry_count) {
    return fail(
      `entry count mismatch: .export.entry_count = ${e.entry_count}, .entries.length = ${data.entries.length}`,
    );
  }
  for (const [i, entry] of data.entries.entries()) {
    if (!entry || typeof entry !== "object") return fail(`entry[${i}] not an object`);
    for (const k of ENTRY_KEYS) {
      if (!(k in entry)) return fail(`entry[${i}] missing .${k}`);
    }
    if (entry.seq !== i + 1) {
      return fail(`entry[${i}].seq must be ${i + 1} (1-indexed, contiguous), got ${entry.seq}`);
    }
    if (typeof entry.signature !== "string" || !entry.signature.startsWith("ed25519:")) {
      return fail(`entry[${i}].signature must be "ed25519:<base64>"`);
    }
    if (typeof entry.hash !== "string" || !HEX64.test(entry.hash)) {
      return fail(`entry[${i}].hash must be 64 hex chars`);
    }
    // The first entry has a null prev_hash (chain genesis); every other entry's
    // prev_hash is the previous entry's hash. Linkage is enforced by the chain
    // check; here we only bound the type.
    if (
      entry.prev_hash !== null &&
      (typeof entry.prev_hash !== "string" || !HEX64.test(entry.prev_hash))
    ) {
      return fail(`entry[${i}].prev_hash must be 64 hex chars or null`);
    }
    const extensionsError = validateSharedEntryExtensions(entry, i, hasMultipleKeys);
    if (extensionsError) return fail(extensionsError);
  }

  return { ok: true };
}

/**
 * Segment-variant entry columns: org-chain `prev_hash` is deliberately
 * ABSENT (it references entries outside the export); `segment_prev_hash`
 * carries the segment linkage and `customer_id` the sealed attribution.
 */
const SEGMENT_ENTRY_KEYS = [
  "seq",
  "id",
  "user_id",
  "org_id",
  "project_id",
  "customer_id",
  "action",
  "entity_type",
  "entity_id",
  "metadata",
  "ip_address",
  "created_at",
  "phi_disposition",
  "subject_type",
  "subject_id_hmac",
  "segment_prev_hash",
  "hash",
  "signature",
];

/**
 * Shape check for the customer-segment envelope variant (schema 1.1).
 *
 * @param {any} data
 * @returns {{ok: true} | {ok: false, error: string}}
 */
function checkSegmentSchema(data) {
  if (data.schema_version !== SEGMENT_SCHEMA) {
    return fail(
      `unsupported schema_version for a variant envelope: ${JSON.stringify(data.schema_version)} (expected "${SEGMENT_SCHEMA}")`,
    );
  }
  if (data.variant !== SEGMENT_VARIANT) {
    return fail(
      `unsupported variant: ${JSON.stringify(data.variant)} (this tool supports "${SEGMENT_VARIANT}")`,
    );
  }

  const e = data.export;
  if (!e || typeof e !== "object") return fail("missing .export object");
  for (const k of [
    "tenant",
    "tenant_id",
    "customer_id",
    "customer_name",
    "range",
    "exported_at",
    "exported_by",
    "entry_count",
  ]) {
    if (!(k in e)) return fail(`missing .export.${k}`);
  }
  if (typeof e.entry_count !== "number") {
    return fail(".export.entry_count must be a number");
  }
  if (typeof e.customer_id !== "string" || e.customer_id.length === 0) {
    return fail(".export.customer_id must be a non-empty string");
  }

  const v = data.verification;
  if (!v || typeof v !== "object") return fail("missing .verification object");
  if (v.algo !== "ed25519") {
    return fail(`unsupported .verification.algo: ${JSON.stringify(v.algo)} (expected "ed25519")`);
  }
  for (const k of ["segment_head_hash", "segment_anchor_chain"]) {
    if (!(k in v)) return fail(`missing .verification.${k}`);
  }

  // Multi-key envelopes — mirrors the org-grain check above.
  const multiKeyResult = validateMultiKeyEnvelope(v);
  if (!multiKeyResult.ok) return multiKeyResult;
  const hasMultipleKeys = multiKeyResult.hasMultipleKeys;
  if (
    v.segment_head_hash !== null &&
    (typeof v.segment_head_hash !== "string" || !HEX64.test(v.segment_head_hash))
  ) {
    return fail(".verification.segment_head_hash must be 64 hex chars (SHA-256) or null");
  }
  if (
    "segment_fold_base" in v &&
    v.segment_fold_base !== undefined &&
    v.segment_fold_base !== null
  ) {
    if (typeof v.segment_fold_base !== "string" || !HEX64.test(v.segment_fold_base)) {
      return fail(
        ".verification.segment_fold_base must be 64 hex chars (SHA-256 fold state) or null",
      );
    }
  }
  if ("lineage_reset_at" in v && v.lineage_reset_at !== undefined && v.lineage_reset_at !== null) {
    if (typeof v.lineage_reset_at !== "string" || v.lineage_reset_at.length === 0) {
      return fail(".verification.lineage_reset_at must be an ISO 8601 string or null");
    }
  }
  if (!Array.isArray(v.segment_anchor_chain)) {
    return fail(".verification.segment_anchor_chain must be an array");
  }
  for (const [i, a] of v.segment_anchor_chain.entries()) {
    for (const k of [
      "checkpoint_after_entry",
      "fold_state",
      "merkle_path",
      "merkle_root",
      "tsa_url",
      "tsa_cacert_url",
      "tsa_tsr_base64",
      "algo",
      "anchored_entry_id",
    ]) {
      if (!(k in a)) return fail(`missing .verification.segment_anchor_chain[${i}].${k}`);
    }
    if (a.algo !== "sha256-fold-merkle-v1") {
      return fail(
        `.verification.segment_anchor_chain[${i}].algo must be "sha256-fold-merkle-v1" (got ${JSON.stringify(a.algo)})`,
      );
    }
    for (const k of ["fold_state", "merkle_root"]) {
      if (typeof a[k] !== "string" || !HEX64.test(a[k])) {
        return fail(`.verification.segment_anchor_chain[${i}].${k} must be 64 hex chars`);
      }
    }
    for (const [k, validate] of ANCHOR_URL_FIELDS) {
      const urlErr = validate(a[k]);
      if (urlErr) return fail(`.verification.segment_anchor_chain[${i}].${k}: ${urlErr}`);
    }
    if (typeof a.anchored_entry_id !== "string" || a.anchored_entry_id.length === 0) {
      return fail(
        `.verification.segment_anchor_chain[${i}].anchored_entry_id must be a non-empty string`,
      );
    }
    if (!Array.isArray(a.merkle_path)) {
      return fail(`.verification.segment_anchor_chain[${i}].merkle_path must be an array`);
    }
    for (const [j, step] of a.merkle_path.entries()) {
      if (
        !step ||
        typeof step !== "object" ||
        (step.position !== "left" && step.position !== "right")
      ) {
        return fail(
          `.verification.segment_anchor_chain[${i}].merkle_path[${j}].position must be "left" or "right"`,
        );
      }
      if (typeof step.hash !== "string" || !HEX64.test(step.hash)) {
        return fail(
          `.verification.segment_anchor_chain[${i}].merkle_path[${j}].hash must be 64 hex chars`,
        );
      }
    }
  }

  if (!Array.isArray(data.entries)) return fail("missing .entries array");
  if (data.entries.length !== e.entry_count) {
    return fail(
      `entry count mismatch: .export.entry_count = ${e.entry_count}, .entries.length = ${data.entries.length}`,
    );
  }
  for (const [i, entry] of data.entries.entries()) {
    if (!entry || typeof entry !== "object") return fail(`entry[${i}] not an object`);
    for (const k of SEGMENT_ENTRY_KEYS) {
      if (!(k in entry)) return fail(`entry[${i}] missing .${k}`);
    }
    if ("prev_hash" in entry) {
      return fail(
        `entry[${i}] carries org-chain .prev_hash — segment-variant entries must omit it (it references entries outside this export)`,
      );
    }
    if (entry.seq !== i + 1) {
      return fail(`entry[${i}].seq must be ${i + 1} (1-indexed, contiguous), got ${entry.seq}`);
    }
    if (entry.customer_id !== e.customer_id) {
      return fail(
        `entry[${i}].customer_id ${JSON.stringify(entry.customer_id)} does not match .export.customer_id — a scoped export carries exactly one segment`,
      );
    }
    if (typeof entry.signature !== "string" || !entry.signature.startsWith("ed25519:")) {
      return fail(`entry[${i}].signature must be "ed25519:<base64>"`);
    }
    if (typeof entry.hash !== "string" || !HEX64.test(entry.hash)) {
      return fail(`entry[${i}].hash must be 64 hex chars`);
    }
    if (
      entry.segment_prev_hash !== null &&
      (typeof entry.segment_prev_hash !== "string" || !HEX64.test(entry.segment_prev_hash))
    ) {
      return fail(`entry[${i}].segment_prev_hash must be 64 hex chars or null`);
    }
    const extensionsError = validateSharedEntryExtensions(entry, i, hasMultipleKeys);
    if (extensionsError) return fail(extensionsError);
  }

  return { ok: true };
}

/**
 * Validates the `verification.keys[]` multi-key envelope shape,
 * or the singular `public_key_pem`/`key_id`/`key_published_at` fields when
 * only one signing key is in scope. Shared between the org-grain and
 * customer-segment schema checks — the shape rule is identical in both.
 *
 * @param {any} v the `.verification` object
 * @returns {{ok: true, hasMultipleKeys: boolean} | {ok: false, error: string}}
 */
function validateMultiKeyEnvelope(v) {
  const hasMultipleKeys = "keys" in v && v.keys !== undefined;
  if (!hasMultipleKeys) {
    for (const k of ["public_key_pem", "key_id", "key_published_at"]) {
      if (!(k in v)) return fail(`missing .verification.${k}`);
    }
    return { ok: true, hasMultipleKeys };
  }
  if (!Array.isArray(v.keys) || v.keys.length < 2) {
    return fail(".verification.keys must be an array of at least 2 entries when present");
  }
  // Fail closed on an ambiguous trust root: a shape carrying BOTH `keys[]`
  // and any singular key field has two disagreeing sources of truth for
  // which key(s) to trust — reject rather than guess which one governs.
  for (const k of ["public_key_pem", "key_id", "key_published_at"]) {
    if (k in v && v[k] !== undefined) {
      return fail(
        `.verification carries both .keys[] and .${k} — ambiguous trust root, refusing to guess which governs`,
      );
    }
  }
  for (const [i, k] of v.keys.entries()) {
    if (!k || typeof k !== "object") return fail(`.verification.keys[${i}] must be an object`);
    for (const kk of ["key_id", "public_key_pem", "published_at"]) {
      if (!(kk in k)) return fail(`missing .verification.keys[${i}].${kk}`);
    }
    if (typeof k.key_id !== "string" || k.key_id.length === 0) {
      return fail(`.verification.keys[${i}].key_id must be a non-empty string`);
    }
    if (typeof k.public_key_pem !== "string" || k.public_key_pem.length === 0) {
      return fail(`.verification.keys[${i}].public_key_pem must be a non-empty string`);
    }
    if (typeof k.published_at !== "string" || k.published_at.length === 0) {
      return fail(`.verification.keys[${i}].published_at must be a non-empty string`);
    }
  }
  return { ok: true, hasMultipleKeys };
}

/**
 * Per-entry checks shared by the org-grain and customer-segment schemas:
 * the presence-conditional `asserted_actor_hmac` / `caller_attribution` /
 * `user_agent` extension slots (see checks/chain.js) and the `key_id`
 * requirement that follows from whether the envelope carries multiple keys.
 *
 * @param {any} entry
 * @param {number} i index, for error messages
 * @param {boolean} hasMultipleKeys
 * @returns {string | null} error message, or null if valid
 */
function validateSharedEntryExtensions(entry, i, hasMultipleKeys) {
  // `asserted_actor_hmac` (ADR-PEQ4XT) is presence-conditional: the key is
  // absent on entries without an integrator-asserted actor and, when
  // present, must be the 64-hex HMAC (it participates in the entry digest —
  // see checks/chain.js).
  if ("asserted_actor_hmac" in entry && entry.asserted_actor_hmac !== undefined) {
    if (typeof entry.asserted_actor_hmac !== "string" || !HEX64.test(entry.asserted_actor_hmac)) {
      return `entry[${i}].asserted_actor_hmac must be 64 hex chars when present`;
    }
  }
  // `caller_attribution` / `user_agent` (extension slots 15/16)
  // are presence-conditional the same way: absent on any row sealed before
  // this change (regardless of what the raw column holds), present only
  // when the row was sealed under digest_version >= 2 with a non-null
  // value. Shape-checked only when present; chain.js recomputes the digest.
  if ("caller_attribution" in entry && entry.caller_attribution !== undefined) {
    if (
      entry.caller_attribution === null ||
      typeof entry.caller_attribution !== "object" ||
      Array.isArray(entry.caller_attribution)
    ) {
      return `entry[${i}].caller_attribution must be an object when present`;
    }
  }
  if ("user_agent" in entry && entry.user_agent !== undefined && entry.user_agent !== null) {
    if (typeof entry.user_agent !== "string") {
      return `entry[${i}].user_agent must be a string when present`;
    }
  }
  // Multi-key envelopes: every entry carries its own `key_id`
  // exactly when the export spans more than one signing key
  // (`verification.keys` present) — required in that case (there is no
  // single `verification.key_id` to fall back to), optional otherwise.
  if (hasMultipleKeys) {
    if (typeof entry.key_id !== "string" || entry.key_id.length === 0) {
      return `entry[${i}].key_id is required (non-empty string) when the export carries multiple signing keys`;
    }
  } else if ("key_id" in entry && entry.key_id !== undefined) {
    if (typeof entry.key_id !== "string" || entry.key_id.length === 0) {
      return `entry[${i}].key_id must be a non-empty string when present`;
    }
  }
  return null;
}

/**
 * @param {unknown} value
 * @param {string[]} protocols allowed URL schemes, e.g. ["https:"]
 * @returns {string | null} error message, or null if valid
 */
function validateUrl(value, protocols) {
  if (typeof value !== "string") return "must be a string URL";
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    return `not a valid URL: ${JSON.stringify(value)}`;
  }
  if (!protocols.includes(parsed.protocol)) {
    return `must use ${protocols.join(" or ")} scheme (got ${JSON.stringify(parsed.protocol)})`;
  }
  return null;
}

/**
 * URL fields on every anchor, with the schemes each may use.
 *
 * `tsa_cacert_url` is fetched (under `--allow-untrusted-tsa`), so it must be
 * `https:`. `tsa_url` only names which TSA issued the token — the verifier
 * never fetches it and never trusts it (trust comes from the bundled roots,
 * and the RFC 3161 token is itself signed) — so `http:` is accepted: some
 * public TSAs, including one HASP anchors with, serve RFC 3161 over plain
 * HTTP only.
 *
 * @type {Array<[string, (value: unknown) => string | null]>}
 */
const ANCHOR_URL_FIELDS = [
  ["tsa_url", (value) => validateUrl(value, ["https:", "http:"])],
  ["tsa_cacert_url", (value) => validateUrl(value, ["https:"])],
];

/**
 * @param {string} msg
 * @returns {{ok: false, error: string}}
 */
function fail(msg) {
  return { ok: false, error: msg };
}
