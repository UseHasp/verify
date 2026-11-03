/**
 * Exhaustive negative tests for the customer-segment envelope shape check
 * (schema 1.1, variant "customer_segment") — the same doctrine as
 * schema.test.js: every fail branch is exercised so the failure paths are
 * not dead code. Each test mutates a deep clone of the valid segment fixture.
 */
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { checkSchema } from "../src/checks/schema.js";

const here = dirname(fileURLToPath(import.meta.url));
const VALID = JSON.parse(readFileSync(resolve(here, "fixtures", "valid-segment.json"), "utf8"));
const clone = () => JSON.parse(JSON.stringify(VALID));

function expectFail(data, pattern) {
  const r = checkSchema(data);
  expect(r.ok).toBe(false);
  if (pattern) expect(r.error).toMatch(pattern);
}

describe("checkSchema — segment variant, top-level", () => {
  it("passes on the valid segment fixture", () => {
    expect(checkSchema(VALID)).toEqual({ ok: true });
  });

  it("routes to the segment check when a variant key is present, even on schema 1.0", () => {
    const d = clone();
    d.schema_version = "1.0";
    expectFail(d, /unsupported schema_version for a variant envelope/);
  });

  it("rejects an unknown variant", () => {
    const d = clone();
    d.variant = "regulator_bundle";
    expectFail(d, /unsupported variant/);
  });
});

describe("checkSchema — segment .export object", () => {
  it("missing .export", () => {
    const d = clone();
    delete d.export;
    expectFail(d, /\.export object/);
  });
  it(".export not an object", () => {
    const d = clone();
    d.export = "nope";
    expectFail(d, /\.export object/);
  });
  for (const key of [
    "tenant",
    "tenant_id",
    "customer_id",
    "customer_name",
    "range",
    "exported_at",
    "exported_by",
    "entry_count",
  ]) {
    it(`missing .export.${key}`, () => {
      const d = clone();
      delete d.export[key];
      expectFail(d, new RegExp(`\\.export\\.${key}`));
    });
  }
  it(".export.entry_count not a number", () => {
    const d = clone();
    d.export.entry_count = "2";
    expectFail(d, /entry_count must be a number/);
  });
  it(".export.customer_id empty string rejected", () => {
    const d = clone();
    d.export.customer_id = "";
    expectFail(d, /customer_id must be a non-empty string/);
  });
  it(".export.customer_id non-string rejected", () => {
    const d = clone();
    d.export.customer_id = 42;
    expectFail(d, /customer_id must be a non-empty string/);
  });
});

describe("checkSchema — segment .verification object", () => {
  it("missing .verification", () => {
    const d = clone();
    delete d.verification;
    expectFail(d, /\.verification object/);
  });
  it(".verification not an object", () => {
    const d = clone();
    d.verification = 42;
    expectFail(d, /\.verification object/);
  });
  it("unsupported algo", () => {
    const d = clone();
    d.verification.algo = "rsa";
    expectFail(d, /algo/);
  });
  for (const key of [
    "public_key_pem",
    "key_id",
    "key_published_at",
    "segment_head_hash",
    "segment_anchor_chain",
  ]) {
    it(`missing .verification.${key}`, () => {
      const d = clone();
      delete d.verification[key];
      expectFail(d, new RegExp(`\\.verification\\.${key}`));
    });
  }
  it("segment_head_hash null is legal (empty segment)", () => {
    const d = clone();
    d.verification.segment_head_hash = null;
    // An empty segment has no head; entry-level checks are separate.
    d.entries = [];
    d.export.entry_count = 0;
    d.verification.segment_anchor_chain = [];
    expect(checkSchema(d)).toEqual({ ok: true });
  });
  it("segment_head_hash not 64 hex rejected", () => {
    const d = clone();
    d.verification.segment_head_hash = "abc";
    expectFail(d, /segment_head_hash must be 64 hex/);
  });
  it("segment_head_hash non-string rejected", () => {
    const d = clone();
    d.verification.segment_head_hash = 42;
    expectFail(d, /segment_head_hash must be 64 hex/);
  });
  it("segment_fold_base absent/null/64-hex are legal", () => {
    const absent = clone();
    delete absent.verification.segment_fold_base;
    expect(checkSchema(absent)).toEqual({ ok: true });
    const withNull = clone();
    withNull.verification.segment_fold_base = null;
    expect(checkSchema(withNull)).toEqual({ ok: true });
    const withHex = clone();
    withHex.verification.segment_fold_base = "ab".repeat(32);
    expect(checkSchema(withHex)).toEqual({ ok: true });
  });
  it("segment_fold_base not 64 hex rejected", () => {
    const d = clone();
    d.verification.segment_fold_base = "abc";
    expectFail(d, /segment_fold_base must be 64 hex/);
  });
  it("segment_fold_base non-string rejected", () => {
    const d = clone();
    d.verification.segment_fold_base = 42;
    expectFail(d, /segment_fold_base must be 64 hex/);
  });
  it("lineage_reset_at absent/null/ISO-string are legal", () => {
    const withNull = clone();
    withNull.verification.lineage_reset_at = null;
    expect(checkSchema(withNull)).toEqual({ ok: true });
    const withStr = clone();
    withStr.verification.lineage_reset_at = "2026-07-19T12:00:00+00:00";
    expect(checkSchema(withStr)).toEqual({ ok: true });
  });
  it("lineage_reset_at empty string / non-string rejected", () => {
    const empty = clone();
    empty.verification.lineage_reset_at = "";
    expectFail(empty, /lineage_reset_at must be an ISO 8601 string or null/);
    const num = clone();
    num.verification.lineage_reset_at = 42;
    expectFail(num, /lineage_reset_at must be an ISO 8601 string or null/);
  });
  it("segment_anchor_chain not array rejected", () => {
    const d = clone();
    d.verification.segment_anchor_chain = {};
    expectFail(d, /segment_anchor_chain must be an array/);
  });
});

describe("checkSchema — segment .verification multi-key trust root", () => {
  function multiKeyClone() {
    const d = clone();
    d.verification.keys = [
      {
        key_id: "key-a",
        public_key_pem: d.verification.public_key_pem,
        published_at: d.verification.key_published_at,
      },
      {
        key_id: "key-b",
        public_key_pem: d.verification.public_key_pem,
        published_at: d.verification.key_published_at,
      },
    ];
    delete d.verification.public_key_pem;
    delete d.verification.key_id;
    delete d.verification.key_published_at;
    for (const e of d.entries) e.key_id = "key-a";
    return d;
  }

  it("accepts a well-formed multi-key verification block", () => {
    expect(checkSchema(multiKeyClone())).toEqual({ ok: true });
  });

  it("rejects keys[] with fewer than 2 entries", () => {
    const d = multiKeyClone();
    d.verification.keys = [d.verification.keys[0]];
    expectFail(d, /at least 2/);
  });

  for (const field of ["public_key_pem", "key_id", "key_published_at"]) {
    it(`rejects keys[] carried alongside singular .verification.${field} (ambiguous trust root)`, () => {
      const d = multiKeyClone();
      d.verification[field] = "leftover-value";
      expectFail(d, /ambiguous trust root/);
    });
  }

  it("rejects a multi-key entry missing key_id", () => {
    const d = multiKeyClone();
    delete d.entries[1].key_id;
    expectFail(d, /entry\[1\]\.key_id is required/);
  });
});

describe("checkSchema — segment anchor chain entries", () => {
  for (const key of [
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
    it(`missing anchor field ${key}`, () => {
      const d = clone();
      delete d.verification.segment_anchor_chain[0][key];
      expectFail(d, new RegExp(`segment_anchor_chain\\[0\\]\\.${key}`));
    });
  }
  it("unrecognised anchor algo rejected", () => {
    const d = clone();
    d.verification.segment_anchor_chain[0].algo = "sha256-fold-v2";
    expectFail(d, /algo must be "sha256-fold-merkle-v1"/);
  });
  for (const key of ["fold_state", "merkle_root"]) {
    it(`anchor ${key} not 64 hex rejected`, () => {
      const d = clone();
      d.verification.segment_anchor_chain[0][key] = "abc";
      expectFail(d, new RegExp(`${key} must be 64 hex chars`));
    });
  }
  it("anchor tsa_cacert_url non-https rejected (it is fetched under --allow-untrusted-tsa)", () => {
    const d = clone();
    d.verification.segment_anchor_chain[0].tsa_cacert_url = "http://freetsa.org/files/cacert.pem";
    expectFail(d, /tsa_cacert_url: must use https: scheme/);
  });
  it("anchor tsa_url accepts http: (identifies the TSA only; some TSAs serve RFC 3161 over HTTP)", () => {
    const d = clone();
    d.verification.segment_anchor_chain[0].tsa_url = "http://timestamp.digicert.com";
    expect(checkSchema(d).ok).toBe(true);
  });
  it("anchor tsa_url rejects schemes other than http:/https:", () => {
    const d = clone();
    d.verification.segment_anchor_chain[0].tsa_url = "ftp://freetsa.org/tsr";
    expectFail(d, /tsa_url: must use https: or http: scheme/);
  });
  it("anchor anchored_entry_id empty string rejected", () => {
    const d = clone();
    d.verification.segment_anchor_chain[0].anchored_entry_id = "";
    expectFail(d, /anchored_entry_id must be a non-empty string/);
  });
  it("anchor anchored_entry_id non-string rejected", () => {
    const d = clone();
    d.verification.segment_anchor_chain[0].anchored_entry_id = 42;
    expectFail(d, /anchored_entry_id must be a non-empty string/);
  });
  it("anchor merkle_path not array rejected", () => {
    const d = clone();
    d.verification.segment_anchor_chain[0].merkle_path = "up-then-left";
    expectFail(d, /merkle_path must be an array/);
  });
  it("merkle_path step with bad position rejected", () => {
    const d = clone();
    d.verification.segment_anchor_chain[0].merkle_path[0].position = "up";
    expectFail(d, /position must be "left" or "right"/);
  });
  it("merkle_path step not an object rejected", () => {
    const d = clone();
    d.verification.segment_anchor_chain[0].merkle_path[0] = null;
    expectFail(d, /position must be "left" or "right"/);
  });
  it("merkle_path step with non-hex hash rejected", () => {
    const d = clone();
    d.verification.segment_anchor_chain[0].merkle_path[0].hash = "xyz";
    expectFail(d, /merkle_path\[0\]\.hash must be 64 hex chars/);
  });
});

describe("checkSchema — segment .entries", () => {
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

  it("missing entries", () => {
    const d = clone();
    delete d.entries;
    expectFail(d, /\.entries array/);
  });
  it("entry_count mismatch", () => {
    const d = clone();
    d.export.entry_count = 99;
    expectFail(d, /entry count mismatch/);
  });
  it("entry not an object", () => {
    const d = clone();
    d.entries[0] = null;
    expectFail(d, /entry\[0\] not an object/);
  });
  for (const key of SEGMENT_ENTRY_KEYS) {
    it(`entry missing .${key}`, () => {
      const d = clone();
      delete d.entries[0][key];
      expectFail(d, new RegExp(`entry\\[0\\] missing \\.${key}`));
    });
  }
  it("entry carrying org-chain prev_hash rejected (segment entries must omit it)", () => {
    const d = clone();
    d.entries[0].prev_hash = "ab".repeat(32);
    expectFail(d, /carries org-chain \.prev_hash/);
  });
  it("entry seq not 1-indexed", () => {
    const d = clone();
    d.entries[0].seq = 5;
    expectFail(d, /seq must be 1/);
  });
  it("entry customer_id differing from the export's customer rejected", () => {
    const d = clone();
    d.entries[1].customer_id = "01HKSOMEOTHERCUSTOMER00000";
    expectFail(d, /does not match \.export\.customer_id/);
  });
  it("entry signature not ed25519: prefix", () => {
    const d = clone();
    d.entries[0].signature = "rsa:abc";
    expectFail(d, /ed25519/);
  });
  it("entry hash not 64 hex", () => {
    const d = clone();
    d.entries[0].hash = "xyz";
    expectFail(d, /hash must be 64 hex/);
  });
  it("first entry segment_prev_hash null accepted (segment genesis)", () => {
    expect(VALID.entries[0].segment_prev_hash).toBeNull();
    expect(checkSchema(VALID)).toEqual({ ok: true });
  });
  it("entry segment_prev_hash non-hex rejected", () => {
    const d = clone();
    d.entries[1].segment_prev_hash = "not-a-hash";
    expectFail(d, /segment_prev_hash must be 64 hex chars or null/);
  });
  it("entry segment_prev_hash wrong type rejected", () => {
    const d = clone();
    d.entries[1].segment_prev_hash = 42;
    expectFail(d, /segment_prev_hash must be 64 hex chars or null/);
  });
});
