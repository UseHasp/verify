/**
 * Unit tests for checkAnchoring — the anchor-v2 contract's binding check
 * (anchor-v2 contract §4a). Runs unconditionally, after signatures: proves
 * every anchor in `tsa_anchor_chain` is actually evidence for THIS export,
 * not just a syntactically valid RFC 3161 token (that's checkTsa's job).
 */
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { checkAnchoring } from "../src/checks/anchoring.js";

const here = dirname(fileURLToPath(import.meta.url));
const load = (name) => JSON.parse(readFileSync(resolve(here, "fixtures", name), "utf8"));
const clone = (x) => JSON.parse(JSON.stringify(x));

// The committed sample (valid.json) now carries a v2 (history-fold) anchor.
// The v1 tests need a genuine v1 export, so derive one: strip the version
// fields and re-point anchored_data at the head entry's row hash — exactly the
// shape a legacy row-hash anchor has.
const VALID_V1 = (() => {
  const d = JSON.parse(JSON.stringify(load("valid.json")));
  const anchor = d.verification.tsa_anchor_chain[0];
  delete anchor.algo;
  delete anchor.anchored_entry_id;
  anchor.anchored_data = d.entries[d.entries.length - 1].hash;
  return d;
})();
const VALID_V2 = load("valid-v2.json");

describe("checkAnchoring — v1 (row-hash) binding", () => {
  it("binds a v1 anchor (algo absent) to the entry whose hash it matches", () => {
    const r = checkAnchoring(VALID_V1);
    expect(r.ok).toBe(true);
    expect(r.bindings).toHaveLength(1);
    expect(r.bindings[0]).toMatchObject({ algo: "row-hash-v1", bound_seq: 4 });
    expect(r.coverage.row_level_attestations).toEqual([4]);
    // No v2 anchor bound, so no fold-based coverage.
    expect(r.coverage.attested_through_seq).toBeNull();
    expect(r.coverage.unattested_from_seq).toBe(1);
    expect(r.coverage.total_entries).toBe(4);
  });

  it("binds a v1 anchor with an explicit algo: row-hash-v1", () => {
    const d = clone(VALID_V1);
    d.verification.tsa_anchor_chain[0].algo = "row-hash-v1";
    const r = checkAnchoring(d);
    expect(r.ok).toBe(true);
  });

  it("fails closed when a v1 anchor's anchored_data matches no exported entry", () => {
    const d = clone(VALID_V1);
    d.verification.tsa_anchor_chain[0].anchored_data = "f".repeat(64);
    const r = checkAnchoring(d);
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/anchor 0 \(row-hash-v1\) anchored_data does not match/);
    expect(r.error).toMatch(/request a full export/);
  });
});

describe("checkAnchoring — v2 (history-fold) binding", () => {
  it("binds both the interior and head v2 anchors, reporting full coverage", () => {
    const r = checkAnchoring(VALID_V2);
    expect(r.ok).toBe(true);
    expect(r.bindings).toHaveLength(2);
    expect(r.bindings[0]).toMatchObject({
      algo: "sha256-fold-v2",
      bound_seq: 2,
      bound_position: 2,
    });
    expect(r.bindings[1]).toMatchObject({
      algo: "sha256-fold-v2",
      bound_seq: 4,
      bound_position: 4,
    });
    expect(r.coverage).toEqual({
      attested_through_seq: 4,
      row_level_attestations: [],
      unattested_from_seq: null,
      total_entries: 4,
    });
  });

  it("reports partial coverage when only the interior v2 anchor is present", () => {
    const d = clone(VALID_V2);
    d.verification.tsa_anchor_chain = [d.verification.tsa_anchor_chain[0]];
    const r = checkAnchoring(d);
    expect(r.ok).toBe(true);
    expect(r.coverage.attested_through_seq).toBe(2);
    expect(r.coverage.unattested_from_seq).toBe(3);
  });

  it("fails closed when a v2 anchor's anchored_entry_id is not among the exported entries (unbindable-anchor fixture)", () => {
    const r = checkAnchoring(load("unbindable-anchor.json"));
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/anchor 1 \(sha256-fold-v2\)/);
    expect(r.error).toMatch(/is not among the exported entries/);
  });

  it("fails closed when the recomputed fold does not match anchored_data (insider-rewrite fixture)", () => {
    const r = checkAnchoring(load("insider-rewrite.json"));
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/anchor 0 \(sha256-fold-v2\) fold mismatch/);
  });

  it("fails closed when the export is not genesis-rooted (range-bounded-v2 fixture)", () => {
    const r = checkAnchoring(load("range-bounded-v2.json"));
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/not genesis-rooted/);
    expect(r.error).toMatch(/request a full export/);
  });

  it("mixes v1 row-level and v2 fold bindings in the same export", () => {
    // A legacy v1 anchor over entry 3's hash, alongside the existing interior
    // v2 anchor (bound through entry 2). Exercises both binding kinds landing
    // in the same coverage report.
    const d = clone(VALID_V2);
    d.verification.tsa_anchor_chain = [
      d.verification.tsa_anchor_chain[0], // v2, bound through seq 2
      {
        checkpoint_after_entry: 3,
        tsa_url: "https://tsa.v2fixture.test/tsr",
        tsa_cacert_url: "https://tsa.v2fixture.test/cacert.pem",
        tsa_tsr_base64: "cGxhY2Vob2xkZXI=",
        anchored_data: d.entries[2].hash,
        anchored_at: "2026-07-20T00:00:02+00:00",
        // no algo — legacy v1 shape
      },
    ];
    const r = checkAnchoring(d);
    expect(r.ok).toBe(true);
    expect(r.coverage.attested_through_seq).toBe(2);
    expect(r.coverage.row_level_attestations).toEqual([3]);
    expect(r.coverage.unattested_from_seq).toBe(3);
  });
});

describe("checkAnchoring — fold_base (retention-rebased exports)", () => {
  const REBASED = load("purge-rebased-v2.json");

  it("binds a pre-purge v2 anchor by folding the retained entries from fold_base", () => {
    const r = checkAnchoring(REBASED);
    expect(r.ok).toBe(true);
    expect(r.bindings).toHaveLength(1);
    expect(r.bindings[0]).toMatchObject({
      algo: "sha256-fold-v2",
      bound_seq: 2,
      bound_position: 2,
    });
    expect(r.coverage).toEqual({
      attested_through_seq: 2,
      row_level_attestations: [],
      unattested_from_seq: null,
      total_entries: 2,
    });
  });

  it("fails closed when fold_base is missing for a rebased export (fold cannot recompute from GENESIS)", () => {
    const d = clone(REBASED);
    delete d.verification.fold_base;
    const r = checkAnchoring(d);
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/fold mismatch/);
  });

  it("fails closed when fold_base is tampered — a fabricated base cannot reproduce the anchored fold", () => {
    const d = clone(REBASED);
    d.verification.fold_base = "f".repeat(64);
    const r = checkAnchoring(d);
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/fold mismatch/);
  });

  it("fails closed when a retained entry is rewritten, even with a correct fold_base", () => {
    const d = clone(REBASED);
    // Swap the two retained entries' hashes in the fold's eyes by tampering
    // the first entry's hash; chain/signature checks would also catch this,
    // but the anchoring check must fail independently.
    d.entries[0].hash = "a".repeat(64);
    const r = checkAnchoring(d);
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/fold mismatch/);
  });

  it("treats an explicit null fold_base as GENESIS (pre-purge envelopes unchanged)", () => {
    const d = clone(VALID_V2);
    d.verification.fold_base = null;
    const r = checkAnchoring(d);
    expect(r.ok).toBe(true);
    expect(r.coverage.attested_through_seq).toBe(4);
  });
});

describe("checkAnchoring — zero anchors", () => {
  it("fails closed by default (no-anchors fixture)", () => {
    const r = checkAnchoring(load("no-anchors.json"));
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/export is not time-attested/);
    expect(r.error).toMatch(/--allow-unanchored/);
  });

  it("passes with a warning when allowUnanchored is set", () => {
    const r = checkAnchoring(load("no-anchors.json"), { allowUnanchored: true });
    expect(r.ok).toBe(true);
    expect(r.attested).toBe("none");
    // No coverage detail for a pass-with-warning — there's nothing to attest to.
    expect("coverage" in r).toBe(false);
  });
});
