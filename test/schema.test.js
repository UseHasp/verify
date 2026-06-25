/**
 * Exhaustive negative tests for checkSchema (schema_version 1.0 envelope).
 *
 * Every fail branch should be exercised so coverage shows the failure paths
 * are not dead code. Each test mutates a deep clone of the valid fixture.
 */
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { checkSchema } from "../src/checks/schema.js";
import { INTEGRITY_FIELDS } from "../src/hash.js";

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
    it(`.export.range.${k} not a string`, () => {
      const d = clone();
      d.export.range[k] = 42;
      expectFail(d, new RegExp(`\\.export\\.range\\.${k} must be an ISO8601 string`));
    });
  }
  it(".export.tenant_id empty string rejected", () => {
    const d = clone();
    d.export.tenant_id = "";
    expectFail(d, /tenant_id must be a non-empty string/);
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
  it("key_id empty string rejected", () => {
    const d = clone();
    d.verification.key_id = "";
    expectFail(d, /key_id must be a non-empty string/);
  });
  it("public_key_pem not a PEM rejected", () => {
    const d = clone();
    d.verification.public_key_pem = "not a pem";
    expectFail(d, /public_key_pem must be a PEM/);
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
  it("keys_url non-https rejected when present", () => {
    const d = clone();
    d.verification.keys_url = "http://app.usehasp.com/trust/keys/x";
    expectFail(d, /keys_url: must use https/);
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
      d.verification.tsa_anchor_chain[0][key] = "http://tsa.example/tsr";
      expectFail(d, /must use https: scheme/);
    });
    it(`tsa anchor ${key} non-URL rejected`, () => {
      const d = clone();
      d.verification.tsa_anchor_chain[0][key] = "not a url";
      expectFail(d, /not a valid URL/);
    });
  }
  it("tsa anchor anchored_data not 64 hex rejected", () => {
    const d = clone();
    d.verification.tsa_anchor_chain[0].anchored_data = "chain_head_hash";
    expectFail(d, /anchored_data must be 64 hex/);
  });
  it("tsa anchor tsa_tsr_base64 empty rejected", () => {
    const d = clone();
    d.verification.tsa_anchor_chain[0].tsa_tsr_base64 = "";
    expectFail(d, /tsa_tsr_base64 must be a base64 string/);
  });
});

describe("checkSchema — .entries", () => {
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
  it("entries empty", () => {
    const d = clone();
    d.entries = [];
    d.export.entry_count = 0;
    expectFail(d, /non-empty array/);
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
  it("entry is an array rejected", () => {
    const d = clone();
    d.entries[0] = [];
    expectFail(d, /entry\[0\] not an object/);
  });
  for (const key of INTEGRITY_FIELDS) {
    it(`entry missing integrity field .${key}`, () => {
      const d = clone();
      delete d.entries[0][key];
      expectFail(d, new RegExp(`entry\\[0\\] missing \\.${key}`));
    });
  }
  for (const key of ["prev_hash", "hash", "signature"]) {
    it(`entry missing .${key}`, () => {
      const d = clone();
      delete d.entries[0][key];
      expectFail(d, new RegExp(`entry\\[0\\].*\\.${key}`));
    });
  }
  it("entry action empty string rejected", () => {
    const d = clone();
    d.entries[0].action = "";
    expectFail(d, /action must be a non-empty string/);
  });
  it("entry created_at not a string rejected", () => {
    const d = clone();
    d.entries[0].created_at = 1700000000;
    expectFail(d, /created_at must be a non-empty string/);
  });
  it("entry prev_hash not 64 hex", () => {
    const d = clone();
    d.entries[0].prev_hash = "abc";
    expectFail(d, /prev_hash must be 64 hex/);
  });
  it("entry hash not 64 hex", () => {
    const d = clone();
    d.entries[0].hash = "xyz";
    expectFail(d, /hash must be 64 hex/);
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
});
