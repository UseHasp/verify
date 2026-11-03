/**
 * Exhaustive negative tests for checkSchema.
 *
 * Every fail branch should be exercised so coverage shows the failure paths
 * are not dead code. Each test mutates a deep clone of the valid fixture.
 */
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { checkSchema } from "../src/checks/schema.js";

const here = dirname(fileURLToPath(import.meta.url));
const VALID = JSON.parse(readFileSync(resolve(here, "fixtures", "valid.json"), "utf8"));
const clone = () => JSON.parse(JSON.stringify(VALID));

function expectFail(data, pattern) {
  const r = checkSchema(data);
  expect(r.ok).toBe(false);
  if (pattern) expect(r.error).toMatch(pattern);
}

describe("checkSchema — top-level", () => {
  it("passes on the valid fixture", () => {
    expect(checkSchema(VALID)).toEqual({ ok: true });
  });

  it("rejects null", () => expectFail(null, /not a JSON object/));
  it("rejects non-object", () => expectFail("string", /not a JSON object/));
  it("rejects unsupported schema_version", () => {
    const d = clone();
    d.schema_version = "2.0";
    expectFail(d, /schema_version/);
  });
});

describe("checkSchema — .export object", () => {
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
  for (const key of ["tenant", "tenant_id", "range", "exported_at", "exported_by", "entry_count"]) {
    it(`missing .export.${key}`, () => {
      const d = clone();
      delete d.export[key];
      expectFail(d, new RegExp(`\\.export\\.${key}`));
    });
  }
  it(".export.entry_count not a number", () => {
    const d = clone();
    d.export.entry_count = "4";
    expectFail(d, /entry_count must be a number/);
  });
  it(".export.range not an object", () => {
    const d = clone();
    d.export.range = "yesterday";
    expectFail(d, /\.export\.range must be an object/);
  });
  it(".export.range as array rejected", () => {
    const d = clone();
    d.export.range = [];
    expectFail(d, /\.export\.range must be an object/);
  });
  for (const k of ["from", "to"]) {
    it(`missing .export.range.${k}`, () => {
      const d = clone();
      delete d.export.range[k];
      expectFail(d, new RegExp(`missing \\.export\\.range\\.${k}`));
    });
    it(`.export.range.${k} wrong type`, () => {
      const d = clone();
      d.export.range[k] = 42;
      expectFail(d, new RegExp(`\\.export\\.range\\.${k} must be an ISO8601 string or null`));
    });
    it(`.export.range.${k} null accepted (unbounded window)`, () => {
      const d = clone();
      d.export.range[k] = null;
      expect(checkSchema(d)).toEqual({ ok: true });
    });
  }
});

describe("checkSchema — .verification object", () => {
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
    "chain_head_hash",
    "tsa_anchor_chain",
  ]) {
    it(`missing .verification.${key}`, () => {
      const d = clone();
      delete d.verification[key];
      expectFail(d, new RegExp(`\\.verification\\.${key}`));
    });
  }
  it("chain_head_hash not 64 hex", () => {
    const d = clone();
    d.verification.chain_head_hash = "abc";
    expectFail(d, /64 hex/);
  });
  it("chain_head_hash not a string", () => {
    const d = clone();
    d.verification.chain_head_hash = 42;
    expectFail(d, /64 hex/);
  });
  it("fold_base absent is legal (fold starts from GENESIS)", () => {
    const d = clone();
    delete d.verification.fold_base;
    expect(checkSchema(d)).toEqual({ ok: true });
  });
  it("fold_base null is legal (same as absent)", () => {
    const d = clone();
    d.verification.fold_base = null;
    expect(checkSchema(d)).toEqual({ ok: true });
  });
  it("fold_base 64-hex is legal (retention-rebased export)", () => {
    const d = clone();
    d.verification.fold_base = "ab".repeat(32);
    expect(checkSchema(d)).toEqual({ ok: true });
  });
  it("fold_base not 64 hex rejected", () => {
    const d = clone();
    d.verification.fold_base = "abc";
    expectFail(d, /fold_base must be 64 hex/);
  });
  it("fold_base not a string rejected", () => {
    const d = clone();
    d.verification.fold_base = 42;
    expectFail(d, /fold_base must be 64 hex/);
  });
  it("lineage_reset_at absent/null/ISO-string are legal", () => {
    const base = clone();
    delete base.verification.lineage_reset_at;
    expect(checkSchema(base)).toEqual({ ok: true });
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
  it("tsa_anchor_chain not array", () => {
    const d = clone();
    d.verification.tsa_anchor_chain = {};
    expectFail(d, /tsa_anchor_chain must be an array/);
  });
  it("tsa_anchor_chain empty is legal (anchoring check decides if that's acceptable)", () => {
    const d = clone();
    d.verification.tsa_anchor_chain = [];
    expect(checkSchema(d)).toEqual({ ok: true });
  });
  for (const key of [
    "checkpoint_after_entry",
    "tsa_url",
    "tsa_cacert_url",
    "tsa_tsr_base64",
    "anchored_data",
  ]) {
    it(`missing tsa anchor field ${key}`, () => {
      const d = clone();
      delete d.verification.tsa_anchor_chain[0][key];
      expectFail(d, new RegExp(`tsa_anchor_chain\\[0\\]\\.${key}`));
    });
  }
  it("tsa anchor tsa_cacert_url non-https rejected (it is fetched under --allow-untrusted-tsa)", () => {
    const d = clone();
    d.verification.tsa_anchor_chain[0].tsa_cacert_url = "http://freetsa.org/files/cacert.pem";
    expectFail(d, /tsa_cacert_url: must use https: scheme/);
  });
  it("tsa anchor tsa_url accepts http: (identifies the TSA only; some TSAs serve RFC 3161 over HTTP)", () => {
    const d = clone();
    d.verification.tsa_anchor_chain[0].tsa_url = "http://timestamp.digicert.com";
    expect(checkSchema(d).ok).toBe(true);
  });
  it("tsa anchor tsa_url rejects schemes other than http:/https:", () => {
    const d = clone();
    d.verification.tsa_anchor_chain[0].tsa_url = "ftp://freetsa.org/tsr";
    expectFail(d, /tsa_url: must use https: or http: scheme/);
  });
  for (const key of ["tsa_url", "tsa_cacert_url"]) {
    it(`tsa anchor ${key} non-URL rejected`, () => {
      const d = clone();
      d.verification.tsa_anchor_chain[0][key] = "not a url";
      expectFail(d, /not a valid URL/);
    });
    it(`tsa anchor ${key} non-string rejected`, () => {
      const d = clone();
      d.verification.tsa_anchor_chain[0][key] = 42;
      expectFail(d, /must be a string URL/);
    });
  }
  it("tsa anchor anchored_data not 64-hex rejected", () => {
    const d = clone();
    d.verification.tsa_anchor_chain[0].anchored_data = "chain_head_hash";
    expectFail(d, /anchored_data must be 64 hex chars/);
  });
  it("tsa anchor anchored_data not a string rejected", () => {
    const d = clone();
    d.verification.tsa_anchor_chain[0].anchored_data = 42;
    expectFail(d, /anchored_data must be 64 hex chars/);
  });
  it("tsa anchor anchored_data need not equal chain_head_hash (binding is the anchoring check's job)", () => {
    const d = clone();
    d.verification.tsa_anchor_chain[0].anchored_data = "f".repeat(64);
    expect(checkSchema(d)).toEqual({ ok: true });
  });
  it("tsa anchor algo absent is legal (implicit row-hash-v1)", () => {
    const d = clone();
    delete d.verification.tsa_anchor_chain[0].algo;
    delete d.verification.tsa_anchor_chain[0].anchored_entry_id;
    expect(checkSchema(d)).toEqual({ ok: true });
  });
  it('tsa anchor algo "row-hash-v1" accepted', () => {
    const d = clone();
    d.verification.tsa_anchor_chain[0].algo = "row-hash-v1";
    expect(checkSchema(d)).toEqual({ ok: true });
  });
  it('tsa anchor algo "sha256-fold-v2" accepted when anchored_entry_id is present', () => {
    const d = clone();
    d.verification.tsa_anchor_chain[0].algo = "sha256-fold-v2";
    d.verification.tsa_anchor_chain[0].anchored_entry_id = "some-entry-id";
    expect(checkSchema(d)).toEqual({ ok: true });
  });
  it("tsa anchor unrecognised algo rejected", () => {
    const d = clone();
    d.verification.tsa_anchor_chain[0].algo = "sha512-something";
    expectFail(d, /algo must be "row-hash-v1" or "sha256-fold-v2"/);
  });
  it('tsa anchor algo "sha256-fold-v2" without anchored_entry_id rejected', () => {
    const d = clone();
    d.verification.tsa_anchor_chain[0].algo = "sha256-fold-v2";
    delete d.verification.tsa_anchor_chain[0].anchored_entry_id;
    expectFail(d, /anchored_entry_id is required when algo is "sha256-fold-v2"/);
  });
  it('tsa anchor algo "sha256-fold-v2" with empty-string anchored_entry_id rejected', () => {
    const d = clone();
    d.verification.tsa_anchor_chain[0].algo = "sha256-fold-v2";
    d.verification.tsa_anchor_chain[0].anchored_entry_id = "";
    expectFail(d, /anchored_entry_id is required when algo is "sha256-fold-v2"/);
  });
  it("tsa anchor anchored_entry_id optional and nullable for v1 (legacy row, no latest_entry_id)", () => {
    const d = clone();
    delete d.verification.tsa_anchor_chain[0].algo;
    d.verification.tsa_anchor_chain[0].anchored_entry_id = null;
    expect(checkSchema(d)).toEqual({ ok: true });
  });
  it("tsa anchor anchored_entry_id wrong type rejected for v1", () => {
    const d = clone();
    delete d.verification.tsa_anchor_chain[0].algo;
    d.verification.tsa_anchor_chain[0].anchored_entry_id = 42;
    expectFail(d, /anchored_entry_id must be a string or null/);
  });
});

describe("checkSchema — .verification multi-key trust root", () => {
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

  it("rejects keys[] that is not an array", () => {
    const d = multiKeyClone();
    d.verification.keys = "not-an-array";
    expectFail(d, /at least 2/);
  });

  it("rejects a keys[] entry that is not an object", () => {
    const d = multiKeyClone();
    d.verification.keys[0] = "nope";
    expectFail(d, /\.verification\.keys\[0\] must be an object/);
  });

  for (const field of ["key_id", "public_key_pem", "published_at"]) {
    it(`rejects a keys[] entry missing ${field}`, () => {
      const d = multiKeyClone();
      delete d.verification.keys[0][field];
      expectFail(d, new RegExp(`missing \\.verification\\.keys\\[0\\]\\.${field}`));
    });
    it(`rejects a keys[] entry with an empty-string ${field}`, () => {
      const d = multiKeyClone();
      d.verification.keys[0][field] = "";
      expectFail(
        d,
        new RegExp(`\\.verification\\.keys\\[0\\]\\.${field} must be a non-empty string`),
      );
    });
  }

  for (const field of ["public_key_pem", "key_id", "key_published_at"]) {
    it(`rejects keys[] carried alongside singular .verification.${field} (ambiguous trust root)`, () => {
      const d = multiKeyClone();
      d.verification[field] = "leftover-value";
      expectFail(d, /ambiguous trust root/);
    });
  }

  it("rejects a multi-key entry missing key_id", () => {
    const d = multiKeyClone();
    delete d.entries[2].key_id;
    expectFail(d, /entry\[2\]\.key_id is required/);
  });

  it("rejects an entry key_id that is not a non-empty string", () => {
    const d = multiKeyClone();
    d.entries[0].key_id = "";
    expectFail(d, /entry\[0\]\.key_id is required/);
  });
});

describe("checkSchema — .entries", () => {
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

  it("missing entries", () => {
    const d = clone();
    delete d.entries;
    expectFail(d, /\.entries array/);
  });
  it("entries not array", () => {
    const d = clone();
    d.entries = {};
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
    d.export.entry_count = d.entries.length;
    expectFail(d, /entry\[0\] not an object/);
  });
  for (const key of ENTRY_KEYS) {
    it(`entry missing .${key}`, () => {
      const d = clone();
      delete d.entries[0][key];
      expectFail(d, new RegExp(`entry\\[0\\] missing \\.${key}`));
    });
  }
  it("entry seq not 1-indexed", () => {
    const d = clone();
    d.entries[0].seq = 5;
    expectFail(d, /seq must be 1/);
  });
  it("entry signature not ed25519: prefix", () => {
    const d = clone();
    d.entries[0].signature = "rsa:abc";
    expectFail(d, /ed25519/);
  });
  it("entry signature not a string", () => {
    const d = clone();
    d.entries[0].signature = 42;
    expectFail(d, /ed25519/);
  });
  it("entry hash not 64 hex", () => {
    const d = clone();
    d.entries[0].hash = "xyz";
    expectFail(d, /hash must be 64 hex/);
  });
  it("entry hash not a string", () => {
    const d = clone();
    d.entries[0].hash = 42;
    expectFail(d, /hash must be 64 hex/);
  });
  it("first entry prev_hash null accepted", () => {
    // The fixture already has entries[0].prev_hash === null; assert it passes.
    expect(VALID.entries[0].prev_hash).toBeNull();
    expect(checkSchema(VALID)).toEqual({ ok: true });
  });
  it("entry prev_hash non-hex string rejected", () => {
    const d = clone();
    d.entries[1].prev_hash = "not-a-hash";
    expectFail(d, /prev_hash must be 64 hex chars or null/);
  });
  it("entry prev_hash wrong type rejected", () => {
    const d = clone();
    d.entries[1].prev_hash = 42;
    expectFail(d, /prev_hash must be 64 hex chars or null/);
  });
  it("entry asserted_actor_hmac 64-hex accepted when present (shape only)", () => {
    const d = clone();
    d.entries[0].asserted_actor_hmac = "ab".repeat(32);
    expect(checkSchema(d)).toEqual({ ok: true });
  });
  it("entry asserted_actor_hmac non-hex rejected", () => {
    const d = clone();
    d.entries[0].asserted_actor_hmac = "not-an-hmac";
    expectFail(d, /asserted_actor_hmac must be 64 hex chars when present/);
  });
  it("entry asserted_actor_hmac wrong type rejected", () => {
    const d = clone();
    d.entries[0].asserted_actor_hmac = 42;
    expectFail(d, /asserted_actor_hmac must be 64 hex chars when present/);
  });
});
