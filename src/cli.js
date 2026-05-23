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
import { VERSION, verifyExport } from "./verify.js";

const HELP = `hasp-verify ${VERSION}

Usage:
  hasp-verify <export.json> [options]

Options:
  --json         Emit machine-readable JSON instead of a human report.
  --skip-tsa     Skip the RFC 3161 TSA anchor check (offline mode).
  --verbose      Print extra detail on failure.
  -h, --help     Show this help.
  -v, --version  Show version.

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
    const raw = await readFile(resolve(args.file), "utf8");
    data = JSON.parse(raw);
  } catch (err) {
    process.stderr.write(`error: could not read or parse ${args.file}: ${errMessage(err)}\n`);
    return 2;
  }

  let result;
  try {
    result = await verifyExport(data, { skipTsa: args.skipTsa });
  } catch (err) {
    process.stderr.write(`error: ${errMessage(err)}\n`);
    return 1;
  }

  if (args.json) {
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  } else {
    printHuman(result, args.verbose);
  }
  return result.ok ? 0 : 1;
}

/** @param {string[]} argv */
function parseArgs(argv) {
  /** @type {{file: string | null, json: boolean, skipTsa: boolean, verbose: boolean, help: boolean, version: boolean}} */
  const out = {
    file: null,
    json: false,
    skipTsa: false,
    verbose: false,
    help: false,
    version: false,
  };
  for (const a of argv) {
    if (a === "--help" || a === "-h") out.help = true;
    else if (a === "--version" || a === "-v") out.version = true;
    else if (a === "--json") out.json = true;
    else if (a === "--skip-tsa") out.skipTsa = true;
    else if (a === "--verbose") out.verbose = true;
    else if (a.startsWith("-")) {
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
 */
function printHuman(result, verbose) {
  const c = result.checks;
  line(c.schema, "schema valid");
  line(c.chain, (ok) => `chain intact (${ok.count} / ${ok.count} entries)`);
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

  if (!result.ok && verbose) {
    process.stdout.write("\nDetail:\n");
    process.stdout.write(`${JSON.stringify(result.checks, null, 2)}\n`);
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
