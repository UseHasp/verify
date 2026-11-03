#!/usr/bin/env node
/**
 * hasp-verify — CLI entrypoint.
 *
 * Usage: hasp-verify <export.json> [--json] [--skip-tsa] [--verbose]
 *
 * Exit codes:
 *   0  VERIFIED
 *   1  FAILED (any check)
 *   2  USAGE error (bad args, missing file)
 */
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { text as readStream } from "node:stream/consumers";
import { VERSION, verifyExport } from "./verify.js";

const HELP = `hasp-verify ${VERSION}

Usage:
  hasp-verify <export.json> [options]

Options:
  --json             Emit machine-readable JSON instead of a human report.
  --skip-tsa         Skip the RFC 3161 TSA anchor check (offline mode).
  --allow-unanchored Accept an export with zero TSA anchors as a
                     pass-with-warning instead of failing the anchoring
                     check. An anchor that IS present but doesn't bind to
                     this export still fails regardless of this flag.
  --ca-file <p>      Trust this local PEM file as the TSA CA instead of the
                     bundled FreeTSA root (no network).
  --allow-untrusted-tsa
                     Fetch each anchor's own tsa_cacert_url (a URL embedded in
                     the export under test) instead of the bundled FreeTSA
                     root. Opt-in only — without it, an export naming its own
                     attacker-controlled CA cannot pass.
  --keys-file <p>    Read the published tenant keys from a local JSON document
                     (the /trust/keys/{tenant_id} shape) instead of
                     fetching /trust/keys — offline / air-gapped, and required
                     for the published sample (its tenant has no live endpoint).
  --keys-base-url <u> Base URL for the /trust/keys endpoint
                     (default https://app.usehasp.com).
  --verbose          Print extra detail.
  -h, --help         Show this help.
  -v, --version      Show version.

Read export from stdin by passing '-' as the file argument:
  cat export.json | hasp-verify - --skip-tsa

Verify the published sample offline (its key is co-published next to it):
  hasp-verify audit-export-sample.json --keys-file audit-keys.json

Exit codes: 0 verified, 1 failed, 2 usage error.

Docs: https://usehasp.com/trust/verify
`;

/** @param {string[]} argv */
async function main(argv) {
  const args = parseArgs(argv);
  if (args.help) {
    process.stdout.write(HELP);
    return 0;
  }
  if (args.version) {
    process.stdout.write(`${VERSION}\n`);
    return 0;
  }
  if (!args.file) {
    process.stderr.write("error: missing required argument <export.json>\n\n");
    process.stderr.write(HELP);
    return 2;
  }

  let data;
  try {
    const raw =
      args.file === "-"
        ? await readStream(process.stdin)
        : await readFile(resolve(args.file), "utf8");
    data = JSON.parse(raw);
  } catch (err) {
    const source = args.file === "-" ? "stdin" : args.file;
    process.stderr.write(`error: could not read or parse ${source}: ${errMessage(err)}\n`);
    return 2;
  }

  let result;
  try {
    result = await verifyExport(data, {
      skipTsa: args.skipTsa,
      allowUnanchored: args.allowUnanchored,
      caFile: args.caFile ?? undefined,
      allowUntrustedTsa: args.allowUntrustedTsa,
      keysFile: args.keysFile ?? undefined,
      keysBaseUrl: args.keysBaseUrl ?? undefined,
    });
  } catch (err) {
    process.stderr.write(`error: ${errMessage(err)}\n`);
    return 1;
  }

  if (args.json) {
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  } else {
    printHuman(result, args.verbose, data);
  }
  return result.ok ? 0 : 1;
}

/** @param {string[]} argv */
function parseArgs(argv) {
  /** @type {{file: string | null, json: boolean, skipTsa: boolean, allowUnanchored: boolean, caFile: string | null, allowUntrustedTsa: boolean, keysFile: string | null, keysBaseUrl: string | null, verbose: boolean, help: boolean, version: boolean}} */
  const out = {
    file: null,
    json: false,
    skipTsa: false,
    allowUnanchored: false,
    caFile: null,
    allowUntrustedTsa: false,
    keysFile: null,
    keysBaseUrl: null,
    verbose: false,
    help: false,
    version: false,
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--help" || a === "-h") out.help = true;
    else if (a === "--version" || a === "-v") out.version = true;
    else if (a === "--json") out.json = true;
    else if (a === "--skip-tsa") out.skipTsa = true;
    else if (a === "--allow-unanchored") out.allowUnanchored = true;
    else if (a === "--allow-untrusted-tsa") out.allowUntrustedTsa = true;
    else if (a === "--verbose") out.verbose = true;
    else if (a === "--ca-file") {
      const next = argv[i + 1];
      if (!next || next.startsWith("-")) {
        process.stderr.write(`error: --ca-file requires a path argument\n`);
        process.exit(2);
      }
      out.caFile = next;
      i++;
    } else if (a.startsWith("--ca-file=")) {
      out.caFile = a.slice("--ca-file=".length);
    } else if (a === "--keys-file") {
      const next = argv[i + 1];
      if (!next || next.startsWith("-")) {
        process.stderr.write(`error: --keys-file requires a path argument\n`);
        process.exit(2);
      }
      out.keysFile = next;
      i++;
    } else if (a.startsWith("--keys-file=")) {
      out.keysFile = a.slice("--keys-file=".length);
    } else if (a === "--keys-base-url") {
      const next = argv[i + 1];
      if (!next || next.startsWith("-")) {
        process.stderr.write(`error: --keys-base-url requires a URL argument\n`);
        process.exit(2);
      }
      out.keysBaseUrl = next;
      i++;
    } else if (a.startsWith("--keys-base-url=")) {
      out.keysBaseUrl = a.slice("--keys-base-url=".length);
    } else if (a === "-") {
      if (out.file) {
        process.stderr.write(`error: unexpected positional argument -\n`);
        process.exit(2);
      }
      out.file = "-";
    } else if (a.startsWith("-")) {
      process.stderr.write(`error: unknown flag ${a}\n`);
      process.exit(2);
    } else if (!out.file) {
      out.file = a;
    } else {
      process.stderr.write(`error: unexpected positional argument ${a}\n`);
      process.exit(2);
    }
  }
  return out;
}

/**
 * @param {import("./verify.js").VerifyResult} result
 * @param {boolean} verbose
 * @param {any} data parsed export, used to enrich --verbose success output
 */
function printHuman(result, verbose, data) {
  const c = result.checks;
  line(c.schema, "schema valid");
  line(c.chain, (ok) => `chain intact (${ok.count} / ${ok.count} entries)`);
  line(c.publishedKey, (ok) =>
    ok.key_ids
      ? `published keys match (${ok.key_ids.length} keys: ${ok.key_ids.join(", ")})`
      : `published key matches (key_id ${ok.key_id})`,
  );
  line(c.signatures, (ok) => `signatures verified (${ok.count} / ${ok.count})`);
  printAnchoringLine(c.anchoring);
  if ("skipped" in c.tsa && c.tsa.skipped) {
    process.stdout.write("⚠ TSA anchor check skipped (--skip-tsa)\n");
  } else {
    line(c.tsa, (ok) => {
      const lines = [`TSA anchor valid`];
      const anchors = /** @type {Array<{tsa_url: string, genTime: string}>} */ (ok.anchors);
      for (const a of anchors) {
        lines.push(`  — ${a.tsa_url} (genTime ${a.genTime})`);
      }
      return lines.join("\n");
    });
  }
  if (c.keyRevocation.ran && !c.keyRevocation.ok) {
    process.stdout.write(`✗ ${c.keyRevocation.error}\n`);
  } else if (c.keyRevocation.ran) {
    const notices = /** @type {Array<{entry_seq: number, key_id: string, revoked_at: string}>} */ (
      c.keyRevocation.notices ?? []
    );
    if (notices.length === 0) {
      process.stdout.write("✓ no revoked signing keys in this export\n");
    } else {
      for (const n of notices) {
        process.stdout.write(
          `⚠ entry seq=${n.entry_seq} was signed under key ${n.key_id}, later revoked at ${n.revoked_at} — ` +
            "a covering anchor proves it predates the revocation\n",
        );
      }
    }
  }

  process.stdout.write("\n");
  process.stdout.write(result.ok ? "VERIFIED.\n" : "FAILED.\n");

  // A lineage reset is a loud caveat printed regardless of pass/fail: the
  // retained rows may verify, but this export represents only history since
  // the reset — pre-reset entries were truncated outside retention
  // maintenance and are absent and unverifiable here.
  if (result.lineage_reset_at) {
    process.stdout.write(
      `\n⚠ CHAIN LINEAGE WAS RESET at ${result.lineage_reset_at}.\n` +
        "  This export represents only history AFTER that point. Entries before it were\n" +
        "  removed outside retention maintenance and cannot be verified from this export.\n" +
        "  If you did not expect a reset, treat this as a finding and investigate.\n",
    );
  }

  // A retention-purged prefix is a loud caveat too, symmetrical to the
  // lineage-reset notice above — but it is the LAWFUL path (fold_base is the
  // platform's own record of what it purged under normal retention), so it
  // never implies tampering the way a lineage reset does.
  if (result.fold_base) {
    process.stdout.write(
      `\n⚠ RETENTION PURGE: this export's chain does not start at genesis.\n` +
        `  fold_base ${result.fold_base} carries the fold state over a prefix removed by normal\n` +
        "  retention maintenance. The retained rows above verify fully; the purged prefix's own\n" +
        "  content is no longer attested by this export.\n",
    );
  }

  if (verbose) {
    if (result.ok) {
      printSuccessDetail(data, c.anchoring);
    } else {
      process.stdout.write("\nDetail:\n");
      process.stdout.write(`${JSON.stringify(result.checks, null, 2)}\n`);
    }
  }
}

/**
 * Anchoring has three outcomes the generic `line()` helper doesn't fit: pass
 * with full/partial coverage, pass-with-warning (zero anchors, allowed via
 * --allow-unanchored), and fail.
 * @param {import("./verify.js").AnchoringCheckResult} check
 */
function printAnchoringLine(check) {
  if (!check.ran) return;
  if (!check.ok) {
    process.stdout.write(`✗ ${check.error}\n`);
    return;
  }
  if (check.attested === "none") {
    process.stdout.write("⚠ export is not time-attested (allowed via --allow-unanchored)\n");
    return;
  }
  process.stdout.write("✓ time-attested\n");
  for (const l of describeCoverage(check.coverage)) {
    process.stdout.write(`  — ${l}\n`);
  }
  // The bullet above already names the unattested range; also surface it as a
  // prominent, un-indented warning so it can't be missed by skimming past the
  // bulleted detail — these entries are signature-protected only, not yet
  // proven to have existed at any particular time.
  if (check.coverage.unattested_from_seq !== null) {
    process.stdout.write(
      `⚠ UNANCHORED TAIL: entries ${check.coverage.unattested_from_seq}..${check.coverage.total_entries} ` +
        "are signed but not yet covered by a time-attestation — protected by hash chain + signature\n" +
        "  only, until the next anchor.\n",
    );
  }
}

/**
 * Turn the anchoring check's coverage object into human-readable lines.
 * @param {import("./checks/anchoring.js").AnchoringCoverage} coverage
 * @returns {string[]}
 */
function describeCoverage(coverage) {
  const lines = [];
  if (coverage.attested_through_seq !== null) {
    lines.push(`entries 1..${coverage.attested_through_seq} time-attested (history commitment)`);
  }
  for (const seq of coverage.row_level_attestations) {
    lines.push(`entry ${seq} row-level attested (legacy anchor)`);
  }
  if (coverage.unattested_from_seq !== null) {
    lines.push(
      `entries ${coverage.unattested_from_seq}..${coverage.total_entries} signed, not covered by a history commitment`,
    );
  }
  return lines;
}

/**
 * @param {any} data parsed export
 * @param {import("./verify.js").AnchoringCheckResult} anchoring
 */
function printSuccessDetail(data, anchoring) {
  if (!data || typeof data !== "object") return;
  const e = data.export ?? {};
  const v = data.verification ?? {};
  const entries = Array.isArray(data.entries) ? data.entries : [];
  const anchors = Array.isArray(v.tsa_anchor_chain) ? v.tsa_anchor_chain : [];
  const seqFirst = entries[0]?.seq ?? "?";
  const seqLast = entries[entries.length - 1]?.seq ?? "?";
  const range = e.range ? `${e.range.from} → ${e.range.to}` : "(unspecified)";

  process.stdout.write("\nDetail:\n");
  process.stdout.write(`  schema_version: ${data.schema_version ?? "(unknown)"}\n`);
  process.stdout.write(`  tenant_id:      ${e.tenant_id ?? "(unknown)"}\n`);
  process.stdout.write(`  range:          ${range}\n`);
  process.stdout.write(`  entries:        ${entries.length} (seq ${seqFirst} → ${seqLast})\n`);
  if (Array.isArray(v.keys)) {
    const keys = /** @type {Array<{key_id: string}>} */ (v.keys);
    process.stdout.write(
      `  keys:           ${keys.length} (${keys.map((k) => k.key_id).join(", ")})\n`,
    );
  } else {
    process.stdout.write(`  key_id:         ${v.key_id ?? "(unknown)"}\n`);
  }
  process.stdout.write(`  anchors:        ${anchors.length}\n`);
  for (const a of anchors) {
    process.stdout.write(`    — ${a.tsa_url}\n`);
  }
  if (anchoring.ran && anchoring.ok) {
    if (anchoring.attested === "none") {
      process.stdout.write(`  attested:       none (--allow-unanchored)\n`);
    } else {
      const through = anchoring.coverage.attested_through_seq;
      const summary = through !== null ? `through seq ${through}` : "row-level only";
      process.stdout.write(`  attested:       ${summary}\n`);
      for (const l of describeCoverage(anchoring.coverage)) {
        process.stdout.write(`    - ${l}\n`);
      }
    }
  }
}

/**
 * @param {import("./verify.js").CheckResult} check
 * @param {string | ((ok: Record<string, any>) => string)} msg
 */
function line(check, msg) {
  if (!check.ran) return;
  if (check.ok) {
    const text = typeof msg === "function" ? msg(check) : msg;
    process.stdout.write(`✓ ${text}\n`);
  } else {
    process.stdout.write(`✗ ${check.error}\n`);
  }
}

/** @param {unknown} err */
function errMessage(err) {
  if (err instanceof Error) return err.message;
  return String(err);
}

/** @param {unknown} err */
function errStack(err) {
  if (err instanceof Error) return err.stack || err.message;
  return String(err);
}

main(process.argv.slice(2)).then(
  (code) => process.exit(code),
  (err) => {
    process.stderr.write(`internal error: ${errStack(err)}\n`);
    process.exit(1);
  },
);
