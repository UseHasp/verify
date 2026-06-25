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
  --skip-key-check   Skip the published-key fetch + match; verify signatures
                     against the export's embedded key (provenance unconfirmed).
  --ca-file <p>      Read TSA CA cert from local PEM file (no network).
  --keys-file <p>    Read the published-keys document from a local JSON file
                     instead of fetching GET /trust/keys/{tenant_id}.
  --keys-url <u>     Override the published-keys URL.
  --verbose          Print extra detail.
  -h, --help         Show this help.
  -v, --version      Show version.

Read export from stdin by passing '-' as the file argument:
  cat export.json | hasp-verify - --skip-tsa --skip-key-check

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
      skipKeyCheck: args.skipKeyCheck,
      caFile: args.caFile ?? undefined,
      keysFile: args.keysFile ?? undefined,
      keysUrl: args.keysUrl ?? undefined,
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
  /** @type {{file: string | null, json: boolean, skipTsa: boolean, skipKeyCheck: boolean, caFile: string | null, keysFile: string | null, keysUrl: string | null, verbose: boolean, help: boolean, version: boolean}} */
  const out = {
    file: null,
    json: false,
    skipTsa: false,
    skipKeyCheck: false,
    caFile: null,
    keysFile: null,
    keysUrl: null,
    verbose: false,
    help: false,
    version: false,
  };
  /**
   * Consume the value for a `--flag <value>` / `--flag=value` option.
   * @param {string} a @param {string} name @param {number} i
   */
  const valueFor = (a, name, i) => {
    if (a === `--${name}`) {
      const next = argv[i + 1];
      if (next === undefined || next.startsWith("-")) {
        process.stderr.write(`error: --${name} requires an argument\n`);
        process.exit(2);
      }
      return { value: next, consumed: 2 };
    }
    return { value: a.slice(`--${name}=`.length), consumed: 1 };
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--help" || a === "-h") out.help = true;
    else if (a === "--version" || a === "-v") out.version = true;
    else if (a === "--json") out.json = true;
    else if (a === "--skip-tsa") out.skipTsa = true;
    else if (a === "--skip-key-check") out.skipKeyCheck = true;
    else if (a === "--verbose") out.verbose = true;
    else if (a === "--ca-file" || a.startsWith("--ca-file=")) {
      const { value, consumed } = valueFor(a, "ca-file", i);
      out.caFile = value;
      i += consumed - 1;
    } else if (a === "--keys-file" || a.startsWith("--keys-file=")) {
      const { value, consumed } = valueFor(a, "keys-file", i);
      out.keysFile = value;
      i += consumed - 1;
    } else if (a === "--keys-url" || a.startsWith("--keys-url=")) {
      const { value, consumed } = valueFor(a, "keys-url", i);
      out.keysUrl = value;
      i += consumed - 1;
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
  if ("skipped" in c.key && c.key.skipped) {
    process.stdout.write("⚠ published-key check skipped (--skip-key-check)\n");
  } else {
    line(c.key, (ok) => `published key matched (${ok.key_id})`);
  }
  line(c.signatures, (ok) => `signatures verified (${ok.count} / ${ok.count})`);
  if ("skipped" in c.tsa && c.tsa.skipped) {
    process.stdout.write("⚠ TSA anchor check skipped (--skip-tsa)\n");
  } else {
    line(c.tsa, (ok) => {
      const lines = [`TSA anchor valid`];
      const anchors = /** @type {Array<{tsa_url: string}>} */ (ok.anchors);
      for (const a of anchors) {
        lines.push(`  — ${a.tsa_url}`);
      }
      return lines.join("\n");
    });
  }

  process.stdout.write("\n");
  process.stdout.write(result.ok ? "VERIFIED.\n" : "FAILED.\n");

  if (verbose) {
    if (result.ok) {
      printSuccessDetail(data);
    } else {
      process.stdout.write("\nDetail:\n");
      process.stdout.write(`${JSON.stringify(result.checks, null, 2)}\n`);
    }
  }
}

/** @param {any} data parsed export */
function printSuccessDetail(data) {
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
  process.stdout.write(`  key_id:         ${v.key_id ?? "(unknown)"}\n`);
  process.stdout.write(`  anchors:        ${anchors.length}\n`);
  for (const a of anchors) {
    process.stdout.write(`    — ${a.tsa_url}\n`);
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
