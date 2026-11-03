/**
 * Cross-language crypto parity: pin this verifier's hash + signature semantics
 * to a frozen known-answer vector that the platform emitter's own test pins to
 * as well (fixtures/hash-vectors.json). The vector's `expected_hash` and
 * `signature` were produced by the platform's `computeHashFromAttributes()` +
 * per-tenant Ed25519 signer.
 *
 * These tests drive the REAL production checks (checkChain / checkSignatures) —
 * not a re-implementation — so if the verifier's field order, metadata
 * canonicalization, JSON encoding, or "signed message = hash hex string"
 * definition drifts from the platform, it fails here against the frozen answer
 * instead of at a customer's verification of a real export. The platform side
 * fails symmetrically against the same vector if IT drifts. Neither side can
 * move the crypto without the other following in the same change.
 */
import { createPublicKey } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { checkChain } from "../src/checks/chain.js";
import { checkSignatures } from "../src/checks/signature.js";

const here = dirname(fileURLToPath(import.meta.url));
const VECTOR = JSON.parse(readFileSync(resolve(here, "fixtures", "hash-vectors.json"), "utf8"));
const trustedKey = () => createPublicKey(VECTOR.public_key_pem);

/** Build a single-entry envelope whose declared hash/signature are the vector's answers. */
function envelopeFrom(input, { hash = VECTOR.expected_hash, signature = VECTOR.signature } = {}) {
  return {
    entries: [{ seq: 1, ...input, prev_hash: null, hash, signature }],
    verification: { chain_head_hash: hash, public_key_pem: VECTOR.public_key_pem },
  };
}

describe("hash + signature parity with the platform emitter", () => {
  it("recomputes the frozen integrity hash byte-for-byte", () => {
    // checkChain returns ok only if its own SHA-256 of the 12-field array
    // equals the vector's expected_hash — i.e. the JS hashing matches PHP.
    const r = checkChain(envelopeFrom(VECTOR.input));
    expect(r.ok).toBe(true);
  });

  it("verifies the frozen Ed25519 signature over the hash hex string", () => {
    const r = checkSignatures(envelopeFrom(VECTOR.input), { publicKey: trustedKey() });
    expect(r.ok).toBe(true);
  });

  it("is invariant to metadata key order (recursive key-sort parity)", () => {
    // Reordering metadata keys must NOT change the digest — the whole point of
    // the canonicalization. Same expected_hash, keys shuffled at both levels.
    const shuffled = {
      ...VECTOR.input,
      metadata: { list: [3, 1, 2], alpha: { x: "café", y: 1 }, zeta: "a/b" },
    };
    expect(checkChain(envelopeFrom(shuffled)).ok).toBe(true);
  });

  it("fails closed when a hashed field changes", () => {
    const tampered = { ...VECTOR.input, action: "record.deleted" };
    // hash stays the frozen answer, but the input changed → recompute mismatches.
    expect(checkChain(envelopeFrom(tampered)).ok).toBe(false);
  });

  it("fails closed when metadata list order changes (arrays are order-significant)", () => {
    const reordered = { ...VECTOR.input, metadata: { ...VECTOR.input.metadata, list: [1, 2, 3] } };
    expect(checkChain(envelopeFrom(reordered)).ok).toBe(false);
  });
});

describe("extended composition parity (digest-preserving extension rule)", () => {
  // asserted_actor_hmac is extension slot 13, customer_id slot 14; the
  // asserted slot is encoded as an explicit null whenever the customer slot
  // is present. The three frozen vectors pin every extended form.
  const EXTENDED = ["asserted", "attributed", "asserted_and_attributed"];

  for (const name of EXTENDED) {
    const V = () => VECTOR[name];
    const env = (input) =>
      envelopeFrom(input, { hash: V().expected_hash, signature: V().signature });

    it(`recomputes the frozen ${name} integrity hash byte-for-byte`, () => {
      expect(checkChain(env(V().input)).ok).toBe(true);
    });

    it(`verifies the frozen Ed25519 signature over the ${name} hash hex string`, () => {
      expect(checkSignatures(env(V().input), { publicKey: trustedKey() }).ok).toBe(true);
    });
  }

  it("fails closed when the attribution is stripped from an attributed entry", () => {
    const stripped = { ...VECTOR.attributed.input };
    delete stripped.customer_id;
    const env = envelopeFrom(stripped, {
      hash: VECTOR.attributed.expected_hash,
      signature: VECTOR.attributed.signature,
    });
    expect(checkChain(env).ok).toBe(false);
  });

  it("fails closed when the attribution is re-homed to a different customer", () => {
    const rehomed = { ...VECTOR.attributed.input, customer_id: "01HKOTHERCUSTOMER000000000" };
    const env = envelopeFrom(rehomed, {
      hash: VECTOR.attributed.expected_hash,
      signature: VECTOR.attributed.signature,
    });
    expect(checkChain(env).ok).toBe(false);
  });

  it("fails closed when attribution is forged onto an unattributed entry", () => {
    const forged = { ...VECTOR.input, customer_id: "01HKCUSTOMER00000000000000" };
    expect(checkChain(envelopeFrom(forged)).ok).toBe(false);
  });

  it("fails closed when an assertion is RELABELED as attribution (injectivity)", () => {
    // Take the asserted entry, strip the assertion, and present its value as
    // customer attribution instead. Under a naive both-are-13th-element rule
    // the digest would recompute; under the explicit-null slot rule the
    // attributed form is 14 elements and the digest changes.
    const relabeled = { ...VECTOR.asserted.input };
    delete relabeled.asserted_actor_hmac;
    relabeled.customer_id = VECTOR.asserted.input.asserted_actor_hmac;
    const env = envelopeFrom(relabeled, {
      hash: VECTOR.asserted.expected_hash,
      signature: VECTOR.asserted.signature,
    });
    expect(checkChain(env).ok).toBe(false);
  });

  it("fails closed when attribution is RELABELED as an assertion (injectivity)", () => {
    const relabeled = { ...VECTOR.attributed.input };
    delete relabeled.customer_id;
    relabeled.asserted_actor_hmac = VECTOR.attributed.input.customer_id;
    const env = envelopeFrom(relabeled, {
      hash: VECTOR.attributed.expected_hash,
      signature: VECTOR.attributed.signature,
    });
    expect(checkChain(env).ok).toBe(false);
  });
});

describe("caller_attribution / user_agent extension slots (15/16)", () => {
  // A legacy (digest_version=1) row's export entry never carries these keys —
  // AuditExportEnvelopeBuilder omits them regardless of the raw column data —
  // so this suite only exercises the shapes an export can actually produce.
  const HASP620 = [
    "caller_attribution",
    "user_agent",
    "caller_attribution_and_user_agent",
    "all_extension_slots",
  ];

  for (const name of HASP620) {
    const V = () => VECTOR[name];
    const env = (input) =>
      envelopeFrom(input, { hash: V().expected_hash, signature: V().signature });

    it(`recomputes the frozen ${name} integrity hash byte-for-byte`, () => {
      expect(checkChain(env(V().input)).ok).toBe(true);
    });

    it(`verifies the frozen Ed25519 signature over the ${name} hash hex string`, () => {
      expect(checkSignatures(env(V().input), { publicKey: trustedKey() }).ok).toBe(true);
    });
  }

  it("is invariant to caller_attribution key order (recursive key-sort parity)", () => {
    const V = VECTOR.caller_attribution;
    const shuffled = {
      ...V.input,
      caller_attribution: {
        delegation_chain: V.input.caller_attribution.delegation_chain,
        agent_id: V.input.caller_attribution.agent_id,
        caller_type: V.input.caller_attribution.caller_type,
        caller_id: V.input.caller_attribution.caller_id,
        org_id: V.input.caller_attribution.org_id,
        delegating_user_id: V.input.caller_attribution.delegating_user_id,
        personal_access_token_id: V.input.caller_attribution.personal_access_token_id,
        agent_credential_id: V.input.caller_attribution.agent_credential_id,
      },
    };
    expect(
      checkChain(envelopeFrom(shuffled, { hash: V.expected_hash, signature: V.signature })).ok,
    ).toBe(true);
  });

  it("fails closed when caller_attribution is stripped from an entry that carries it", () => {
    const stripped = { ...VECTOR.caller_attribution.input };
    delete stripped.caller_attribution;
    const env = envelopeFrom(stripped, {
      hash: VECTOR.caller_attribution.expected_hash,
      signature: VECTOR.caller_attribution.signature,
    });
    expect(checkChain(env).ok).toBe(false);
  });

  it("fails closed when caller_attribution is tampered (delegated agent swapped)", () => {
    const tampered = {
      ...VECTOR.caller_attribution.input,
      caller_attribution: {
        ...VECTOR.caller_attribution.input.caller_attribution,
        agent_id: "01HKOTHERAGENT00000000000",
      },
    };
    const env = envelopeFrom(tampered, {
      hash: VECTOR.caller_attribution.expected_hash,
      signature: VECTOR.caller_attribution.signature,
    });
    expect(checkChain(env).ok).toBe(false);
  });

  it("fails closed when user_agent is forged onto an entry that never carried it", () => {
    const forged = { ...VECTOR.input, user_agent: "forged-agent/1.0" };
    expect(checkChain(envelopeFrom(forged)).ok).toBe(false);
  });

  it("fails closed when caller_attribution is RELABELED as user_agent (injectivity)", () => {
    const relabeled = { ...VECTOR.caller_attribution.input };
    delete relabeled.caller_attribution;
    relabeled.user_agent = JSON.stringify(VECTOR.caller_attribution.input.caller_attribution);
    const env = envelopeFrom(relabeled, {
      hash: VECTOR.caller_attribution.expected_hash,
      signature: VECTOR.caller_attribution.signature,
    });
    expect(checkChain(env).ok).toBe(false);
  });
});
