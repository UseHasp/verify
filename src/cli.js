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
  --json           Emit machine-readable JSON instead of a human report.
  --skip-tsa       Skip the RFC 3161 TSA anchor check (offline mode).
  --ca-file <p>    Read TSA CA cert from local PEM file (no network).
  --key-file <p>   Read the independently-published signing key from a local PEM
                   file instead of fetching /trust/keys (offline trust root).
  --keys-url <u>   Base URL for the /trust/keys/{tenant_id} endpoint
                   (default https://app.usehasp.com).
  --verbose        Print extra detail.
  -h, --help       Show this help.
  -v, --version    Show version.

Read export from stdin by passing '-' as the file argument:
  cat export.json | hasp-verify - --skip-tsa

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
      caFile: args.caFile ?? undefined,
      keyFile: args.keyFile ?? undefined,
      keysBaseUrl: args.keysUrl ?? undefined,
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
  /** @type {{file: string | null, json: boolean, skipTsa: boolean, caFile: string | null, keyFile: string | null, keysUrl: string | null, verbose: boolean, help: boolean, version: boolean}} */
  const out = {
    file: null,
    json: false,
    skipTsa: false,
    caFile: null,
    keyFile: null,
    keysUrl: null,
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
    } else if (a === "--key-file") {
      const next = argv[i + 1];
      if (!next || next.startsWith("-")) {
        process.stderr.write(`error: --key-file requires a path argument\n`);
        process.exit(2);
      }
      out.keyFile = next;
      i++;
    } else if (a.startsWith("--key-file=")) {
      out.keyFile = a.slice("--key-file=".length);
    } else if (a === "--keys-url") {
      const next = argv[i + 1];
      if (!next || next.startsWith("-")) {
        process.stderr.write(`error: --keys-url requires a URL argument\n`);
        process.exit(2);
      }
      out.keysUrl = next;
      i++;
    } else if (a.startsWith("--keys-url=")) {
      out.keysUrl = a.slice("--keys-url=".length);
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
  line(
    c.publishedKey,
    (ok) => `published key matched (key_id ${ok.key_id}\n  — trust root: ${ok.source})`,
  );
  line(c.signatures, (ok) => `signatures verified (${ok.count} / ${ok.count})`);
  if ("skipped" in c.tsa && c.tsa.skipped) {
    process.stdout.write("⚠ TSA anchor check skipped (--skip-tsa)\n");
  } else {
    line(c.tsa, (ok) => {
      const lines = [`TSA anchor valid`];
      const anchors = /** @type {Array<{tsa_url: string, anchored_data: string}>} */ (ok.anchors);
      for (const a of anchors) {
        lines.push(`  — ${a.tsa_url} (anchored ${a.anchored_data})`);
      }
      return lines.join("\n");
    });
  }

  process.stdout.write("\n");
  process.stdout.write(result.ok ? "VERIFIED.\n" : "FAILED.\n");

  if (verbose) {
    if (result.ok) {
      printSuccessDetail(data, result);
    } else {
      process.stdout.write("\nDetail:\n");
      process.stdout.write(`${JSON.stringify(result.checks, null, 2)}\n`);
    }
  }
}

/**
 * @param {any} data parsed export
 * @param {import("./verify.js").VerifyResult} result verified result (for key source)
 */
function printSuccessDetail(data, result) {
  if (!data || typeof data !== "object") return;
  const e = data.export ?? {};
  const v = data.verification ?? {};
  const entries = Array.isArray(data.entries) ? data.entries : [];
  const anchors = Array.isArray(v.tsa_anchor_chain) ? v.tsa_anchor_chain : [];
  const range = e.range ? `${e.range.from} → ${e.range.to}` : "(unspecified)";
  const firstCreated = entries[0]?.created_at ?? "?";
  const lastCreated = entries[entries.length - 1]?.created_at ?? "?";
  const pk = result.checks.publishedKey;
  const keySource = pk?.ran && pk.ok ? /** @type {any} */ (pk).source : "(unknown)";

  process.stdout.write("\nDetail:\n");
  process.stdout.write(`  schema_version: ${data.schema_version ?? "(unknown)"}\n`);
  process.stdout.write(`  tenant:         ${e.tenant ?? "(unknown)"}\n`);
  process.stdout.write(`  tenant_id:      ${e.tenant_id ?? "(unknown)"}\n`);
  process.stdout.write(`  range:          ${range}\n`);
  process.stdout.write(`  exported_by:    ${e.exported_by ?? "(none)"}\n`);
  process.stdout.write(`  entries:        ${entries.length} (${firstCreated} → ${lastCreated})\n`);
  process.stdout.write(`  key_id:         ${v.key_id ?? "(unknown)"}\n`);
  process.stdout.write(`  trust root:     ${keySource}\n`);
  process.stdout.write(`  anchors:        ${anchors.length}\n`);
  for (const a of anchors) {
    process.stdout.write(`    — ${a.tsa_url} (anchored_data ${a.anchored_data})\n`);
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
