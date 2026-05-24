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

const ajv = new Ajv({ strict: false, allErrors: true });
addFormats(ajv);
const validate = ajv.compile(SCHEMA);

describe("published JSON Schema schema/v1.0.json", () => {
  it("accepts the valid fixture", () => {
    const ok = validate(VALID);
    if (!ok) console.error(validate.errors);
    expect(ok).toBe(true);
  });

  it("rejects the broken-schema fixture (mismatched schema_version)", () => {
    expect(validate(BROKEN_SCHEMA)).toBe(false);
  });

  it("declares $id and draft 2020-12 $schema", () => {
    expect(SCHEMA.$id).toMatch(/audit-export\/v1\.0\.json$/);
    expect(SCHEMA.$schema).toBe("https://json-schema.org/draft/2020-12/schema");
  });
});
