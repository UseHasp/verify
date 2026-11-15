/**
 * Public type surface for @usehasp/verify.
 *
 * Hand-written to mirror the JSDoc in src/*.js. The runtime is plain
 * JavaScript; this file exists only so TypeScript consumers get
 * autocomplete and type-checking. There is no build step — what ships
 * to npm is the .js source plus this .d.ts.
 */

export const VERSION: string;
export const SCHEMA_VERSION: string;

export interface VerifyOptions {
  /** Skip the RFC 3161 TSA anchor check (offline mode). */
  skipTsa?: boolean;
  /**
   * Trust this local PEM file as the TSA CA instead of the bundled FreeTSA
   * root. Useful for air-gapped or long-term archival verification against a
   * separately-obtained cert.
   */
  caFile?: string;
  /**
   * Fetch each anchor's own `tsa_cacert_url` (a URL embedded in the export
   * under test) instead of trusting the bundled FreeTSA root. Opt-in only —
   * without it, an export naming its own attacker-controlled CA cannot pass.
   * Mirrors the CLI's `--allow-untrusted-tsa` flag.
   */
  allowUntrustedTsa?: boolean;
  /** Inject a fetch implementation (for testing). */
  fetcher?: typeof fetch;
  /** Override the `openssl` binary path. */
  opensslPath?: string;
  /**
   * PEM of the independently-published tenant key, supplied directly. Highest-
   * priority trust root for the published-key check (fully offline).
   */
  expectedKey?: string;
  /**
   * Local published-keys JSON document (the `/trust/keys/{tenant}` shape)
   * used to establish the published-key trust root offline, matched on
   * the export's `key_id`. Required to verify the published sample, whose
   * throwaway tenant has no live `/trust/keys` endpoint.
   */
  keysFile?: string;
  /**
   * Base URL for the `/trust/keys/{tenant}` endpoint the published-key check
   * fetches when no offline key source is given. Defaults to
   * `https://app.usehasp.com`.
   */
  keysBaseUrl?: string;
  /**
   * Accept an export with zero TSA anchors as a pass-with-warning
   * (`anchoring.attested === "none"`) instead of failing the anchoring check.
   * Mirrors the CLI's `--allow-unanchored` flag. An anchor that IS present
   * but cannot be bound to this export still fails the check regardless of
   * this option.
   */
  allowUnanchored?: boolean;
  /**
   * Fail when any attested entry was first time-attested more than this many
   * hours after its `created_at`. Unset: a lag over 48 hours is reported in
   * `VerifyResult.late_anchoring` but does not fail. Mirrors the CLI's
   * `--max-anchor-lag` flag.
   */
  maxAnchorLagHours?: number;
}

export interface LateAnchoring {
  /** The lag, in hours, beyond which an entry is counted. */
  threshold_hours: number;
  /** How many attested entries exceeded it. */
  entries: number;
  /** The first such entry's seq. */
  first_seq: number;
  /** The longest lag between an entry's created_at and its earliest covering anchor's genTime. */
  max_lag_hours: number;
}

export type CheckOk = { ran: true; ok: true } & Record<string, unknown>;
export type CheckFail = { ran: true; ok: false; error: string };
export type CheckSkipped = { ran: false; skipped: true };
export type CheckNotRun = { ran: false };
export type CheckResult = CheckOk | CheckFail | CheckSkipped | CheckNotRun;

export interface TsaAnchorResult {
  tsa_url: string;
  output: string;
  /** The token's parsed `genTime`, as an ISO 8601 string. */
  genTime: string;
}

/** One anchor from `verification.tsa_anchor_chain`, bound to this export. */
export interface AnchorBinding {
  /** Index into `verification.tsa_anchor_chain`. */
  index: number;
  algo: "row-hash-v1" | "sha256-fold-v2";
  anchored_data: string;
  /** The `seq` of the entry this anchor is bound to. */
  bound_seq: number;
  /** v2 only — the entry id the anchor declares (`anchor.anchored_entry_id`). */
  anchored_entry_id?: string;
  /** v2 only — 1-indexed position of the bound entry within the exported entries. */
  bound_position?: number;
}

/** Attested coverage of the export's entries, per the anchoring check. */
export interface AnchoringCoverage {
  /** Highest `seq` covered by a bound v2 (history-fold) anchor, or null if none. */
  attested_through_seq: number | null;
  /** `seq`s individually attested by a bound v1 (row-hash) anchor. */
  row_level_attestations: number[];
  /** First `seq` after `attested_through_seq` that is signed but not yet anchored, or null if full coverage. */
  unattested_from_seq: number | null;
  total_entries: number;
}

export type AnchoringResult =
  | CheckNotRun
  | { ran: true; ok: true; attested: "none" }
  | { ran: true; ok: true; bindings: AnchorBinding[]; coverage: AnchoringCoverage }
  | { ran: true; ok: false; error: string };

export interface VerifyResult {
  /** Overall pass/fail. True iff every ran check passed. */
  ok: boolean;
  /**
   * Set when entries were first time-attested long after the time recorded on
   * them. A token proves an entry existed BY its genTime, not AT its
   * created_at. Null when every attested entry was anchored promptly, or when
   * the TSA check was skipped.
   */
  late_anchoring: LateAnchoring | null;
  checks: {
    schema: CheckResult;
    chain: CheckResult;
    publishedKey: CheckResult;
    signatures: CheckResult;
    anchoring: AnchoringResult;
    tsa: CheckResult;
  };
  /**
   * ISO timestamp when this org's chain lineage was force-reset (a prefix was
   * truncated outside retention maintenance), or null when intact.
   */
  lineage_reset_at: string | null;
  /**
   * The retained chain's fold base when a retention purge removed a prefix
   * ahead of this export's window, or null when the export is fold-complete
   * from genesis. Never fails verification — a lawful purge is expected.
   */
  fold_base: string | null;
}

/**
 * Verify a parsed Hasp audit export. Runs schema, chain, published-key,
 * signature, anchoring, and TSA-anchor checks in order; short-circuits on
 * first failure.
 *
 * @param data Parsed audit-export JSON — the result of {@link parseExport}
 *   (preferred: exact for 64-bit integers) or of `JSON.parse`.
 * @param opts Optional overrides — skip TSA, accept unanchored exports, inject
 *   fetch, override openssl path, and supply the published-key trust root
 *   (expectedKey / keysFile / keysBaseUrl).
 */
export function verifyExport(data: unknown, opts?: VerifyOptions): Promise<VerifyResult>;

/**
 * Parse audit-export JSON text without losing integers above 2^53: such
 * tokens come back as `bigint`, everything else exactly as `JSON.parse`
 * returns it. `JSON.parse` rounds those integers, so an entry whose metadata
 * holds one could not be re-hashed.
 */
export function parseExport(text: string): unknown;
