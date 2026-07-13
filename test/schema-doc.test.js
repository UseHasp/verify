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
const clone = () => JSON.parse(JSON.stringify(VALID));

const ajv = new Ajv({ strict: false, allErrors: true });
addFormats(ajv);
const validate = ajv.compile(SCHEMA);

describe("published JSON Schema schema/v1.0.json", () => {
  it("accepts the valid fixture", () => {
    const ok = validate(VALID);
    if (!ok) console.error(validate.errors);
    expect(ok).toBe(true);
  });

  it("accepts null nullable columns (genesis prev_hash, null actor)", () => {
    const d = clone();
    d.entries[0].prev_hash = null;
    d.entries[0].user_id = null;
    d.entries[0].subject_type = null;
    expect(validate(d)).toBe(true);
  });

  it("rejects a mismatched schema_version", () => {
    const d = clone();
    d.schema_version = "99.0";
    expect(validate(d)).toBe(false);
  });

  it("rejects a non-hex anchored_data", () => {
    const d = clone();
    d.verification.tsa_anchor_chain[0].anchored_data = "chain_head_hash";
    expect(validate(d)).toBe(false);
  });

  it("rejects an entry missing a required flat field", () => {
    const d = clone();
    delete d.entries[0].subject_id_hmac;
    expect(validate(d)).toBe(false);
  });

  it("declares $id and draft 2020-12 $schema", () => {
    expect(SCHEMA.$id).toMatch(/audit-export\/v1\.0\.json$/);
    expect(SCHEMA.$schema).toBe("https://json-schema.org/draft/2020-12/schema");
  });
});
