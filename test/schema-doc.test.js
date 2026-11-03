/**
 * Validates the published JSON Schema document (`schema/v1.0.json`) against
 * the test fixtures. The JS validator in src/checks/schema.js is authoritative;
 * this test prevents the published JSON Schema from silently drifting away from it.
 */
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import Ajv from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import { describe, expect, it } from "vitest";

const here = dirname(fileURLToPath(import.meta.url));
const load = (p) => JSON.parse(readFileSync(resolve(here, p), "utf8"));

const SCHEMA = load("../schema/v1.0.json");
const VALID = load("fixtures/valid.json");
const BROKEN_SCHEMA = load("fixtures/broken-schema.json");
const VALID_V2 = load("fixtures/valid-v2.json");
const NO_ANCHORS = load("fixtures/no-anchors.json");
const VALID_MULTIKEY = load("fixtures/valid-multikey.json");

const ajv = new Ajv({ strict: false, allErrors: true });
addFormats(ajv);
const validate = ajv.compile(SCHEMA);

describe("published JSON Schema schema/v1.0.json", () => {
  it("accepts the valid fixture (v1 anchor, algo absent)", () => {
    const ok = validate(VALID);
    if (!ok) console.error(validate.errors);
    expect(ok).toBe(true);
  });

  it("accepts the valid-v2 fixture (two sha256-fold-v2 anchors with anchored_entry_id)", () => {
    const ok = validate(VALID_V2);
    if (!ok) console.error(validate.errors);
    expect(ok).toBe(true);
  });

  it("accepts an empty tsa_anchor_chain (no-anchors fixture)", () => {
    const ok = validate(NO_ANCHORS);
    if (!ok) console.error(validate.errors);
    expect(ok).toBe(true);
  });

  it("rejects the broken-schema fixture (mismatched schema_version)", () => {
    expect(validate(BROKEN_SCHEMA)).toBe(false);
  });

  it("rejects a sha256-fold-v2 anchor missing anchored_entry_id", () => {
    const d = JSON.parse(JSON.stringify(VALID_V2));
    delete d.verification.tsa_anchor_chain[0].anchored_entry_id;
    expect(validate(d)).toBe(false);
  });

  it("accepts the multi-key fixture (verification.keys[], no singular public_key_pem/key_id)", () => {
    const ok = validate(VALID_MULTIKEY);
    if (!ok) console.error(validate.errors);
    expect(ok).toBe(true);
  });

  it("rejects a multi-key export whose keys[] array has fewer than 2 entries", () => {
    const d = JSON.parse(JSON.stringify(VALID_MULTIKEY));
    d.verification.keys = [d.verification.keys[0]];
    expect(validate(d)).toBe(false);
  });

  it("rejects a verification object with neither public_key_pem/key_id/key_published_at nor keys[]", () => {
    const d = JSON.parse(JSON.stringify(VALID));
    delete d.verification.public_key_pem;
    delete d.verification.key_id;
    delete d.verification.key_published_at;
    expect(validate(d)).toBe(false);
  });

  it("rejects a verification object carrying BOTH the singular key fields and keys[]", () => {
    const d = JSON.parse(JSON.stringify(VALID_MULTIKEY));
    d.verification.public_key_pem = VALID.verification.public_key_pem;
    d.verification.key_id = VALID.verification.key_id;
    d.verification.key_published_at = VALID.verification.key_published_at;
    expect(validate(d)).toBe(false);
  });

  it("declares $id and draft 2020-12 $schema", () => {
    expect(SCHEMA.$id).toMatch(/audit-export\/v1\.0\.json$/);
    expect(SCHEMA.$schema).toBe("https://json-schema.org/draft/2020-12/schema");
  });
});
