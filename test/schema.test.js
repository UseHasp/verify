/**
 * Exhaustive negative tests for checkSchema.
 *
 * Every fail branch should be exercised so coverage shows the failure paths
 * are not dead code. Each test mutates a deep clone of the valid fixture.
 */
import { describe, expect, it } from "vitest";
import { checkSchema } from "../src/checks/schema.js";
import { loadFixture } from "./helpers.js";

const VALID = loadFixture("valid.json");
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
  it(".export.tenant_id not a string", () => {
    const d = clone();
    d.export.tenant_id = 42;
    expectFail(d, /tenant_id must be a string/);
  });
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
    it(`.export.range.${k} not a string`, () => {
      const d = clone();
      d.export.range[k] = 42;
      expectFail(d, new RegExp(`\\.export\\.range\\.${k} must be an ISO8601 string`));
    });
  }
  it(".export.exported_by null is allowed", () => {
    const d = clone();
    d.export.exported_by = null;
    expect(checkSchema(d)).toEqual({ ok: true });
  });
  it(".export.exported_by non-string non-null rejected", () => {
    const d = clone();
    d.export.exported_by = 42;
    expectFail(d, /exported_by must be a string or null/);
  });
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
  it("public_key_pem not a string", () => {
    const d = clone();
    d.verification.public_key_pem = 42;
    expectFail(d, /public_key_pem must be a string/);
  });
  it("key_id not a string", () => {
    const d = clone();
    d.verification.key_id = 42;
    expectFail(d, /key_id must be a string/);
  });
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
  it("tsa_anchor_chain not array", () => {
    const d = clone();
    d.verification.tsa_anchor_chain = {};
    expectFail(d, /non-empty array/);
  });
  it("tsa_anchor_chain empty", () => {
    const d = clone();
    d.verification.tsa_anchor_chain = [];
    expectFail(d, /non-empty array/);
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
  for (const key of ["tsa_url", "tsa_cacert_url"]) {
    it(`tsa anchor ${key} non-https rejected`, () => {
      const d = clone();
      d.verification.tsa_anchor_chain[0][key] = "http://freetsa.org/tsr";
      expectFail(d, /must use https: scheme/);
    });
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
  it("tsa anchor tsa_tsr_base64 empty rejected", () => {
    const d = clone();
    d.verification.tsa_anchor_chain[0].tsa_tsr_base64 = "";
    expectFail(d, /tsa_tsr_base64 must be a non-empty string/);
  });
  it("tsa anchor anchored_data non-hex literal rejected", () => {
    const d = clone();
    d.verification.tsa_anchor_chain[0].anchored_data = "chain_head_hash";
    expectFail(d, /anchored_data must be 64 hex/);
  });
  it("tsa anchor anchored_data wrong length rejected", () => {
    const d = clone();
    d.verification.tsa_anchor_chain[0].anchored_data = "abcd";
    expectFail(d, /anchored_data must be 64 hex/);
  });
});

describe("checkSchema — .entries", () => {
  const ENTRY_FIELDS = [
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
  for (const key of ENTRY_FIELDS) {
    it(`entry missing .${key}`, () => {
      const d = clone();
      delete d.entries[0][key];
      expectFail(d, new RegExp(`entry\\[0\\] missing \\.${key}`));
    });
  }
  for (const key of [
    "user_id",
    "project_id",
    "entity_type",
    "entity_id",
    "ip_address",
    "phi_disposition",
    "subject_type",
    "subject_id_hmac",
  ]) {
    it(`entry ${key} null is allowed by schema`, () => {
      const d = clone();
      d.entries[0][key] = null;
      expect(checkSchema(d)).toEqual({ ok: true });
    });
    it(`entry ${key} non-string non-null rejected`, () => {
      const d = clone();
      d.entries[0][key] = 42;
      expectFail(d, new RegExp(`entry\\[0\\]\\.${key} must be a string or null`));
    });
  }
  for (const key of ["org_id", "action", "created_at"]) {
    it(`entry ${key} non-string rejected`, () => {
      const d = clone();
      d.entries[0][key] = null;
      expectFail(d, new RegExp(`entry\\[0\\]\\.${key} must be a string`));
    });
  }
  it("entry metadata as array rejected", () => {
    const d = clone();
    d.entries[0].metadata = [];
    expectFail(d, /metadata must be an object or null/);
  });
  it("entry metadata null allowed by schema", () => {
    const d = clone();
    d.entries[0].metadata = null;
    expect(checkSchema(d)).toEqual({ ok: true });
  });
  it("entry prev_hash null allowed (genesis)", () => {
    const d = clone();
    d.entries[0].prev_hash = null;
    expect(checkSchema(d)).toEqual({ ok: true });
  });
  it("entry prev_hash bad hex rejected", () => {
    const d = clone();
    d.entries[1].prev_hash = "xyz";
    expectFail(d, /prev_hash must be 64 hex chars or null/);
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
});
