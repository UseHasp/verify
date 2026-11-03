/**
 * Check: RFC 3161 TSA anchor.
 *
 * For each anchor in tsa_anchor_chain:
 *  1. Decode the base64 TSR.
 *  2. Read the TSA CA certificate(s) to trust, in priority order:
 *       a. `--ca-file` — an explicit local PEM (offline, fully caller-controlled).
 *       b. The bundled root trust bundle (every `*.pem` file directly under
 *          `../../roots/`) — the default. Each configured
 *          production TSA has its root pinned here, so a genuine export
 *          verifies against this with no network fetch regardless of which
 *          configured TSA actually anchored it. The anchor verifies if it
 *          matches ANY bundled root — an anchor names its own `tsa_url` but
 *          not which root signs it, so every bundled root is tried in turn.
 *       c. `--allow-untrusted-tsa` — fetch `tsa_cacert_url`, a URL embedded in
 *          the export under test. Opt-in only: without it, an attacker who
 *          mints their own TSA and points `tsa_cacert_url` at their own CA
 *          cannot pass, because the default trust bundle never reads that URL.
 *  3. Shell out to
 *       `openssl ts -verify -in <tsr> -CAfile <cacert> -digest <anchor.anchored_data>`.
 *  4. Parse the token's `genTime` via `openssl ts -reply -in <tsr> -text` —
 *     surfaced in the result for human/JSON output and for the backdating
 *     check the orchestrator (`../verify.js`) runs against the bound entry's
 *     `created_at`.
 *
 * This check only proves the TSR is a valid RFC 3161 token, signed by a
 * trusted TSA, over its own `anchored_data` — whether that `anchored_data` is
 * actually evidence for THIS export (a row it contains, or a fold over its
 * history) is the anchoring check's job (`./anchoring.js`), which runs first
 * in the pipeline.
 *
 * Returns OK only if every anchor verifies. `--skip-tsa` bypasses this check.
 *
 * Digest convention (differs from a data-file verify): the platform builds the
 * RFC 3161 request by placing the RAW 32 bytes `hex2bin(anchored_data)` directly
 * as the messageImprint `hashedMessage` (SHA-256 OID) — it does NOT hash
 * anything again at request time. So the TSR must be verified with the digest
 * passed directly (`-digest <anchored_data-hex>`), NOT by feeding a data file to
 * `-data` (which would make openssl hash the file first).
 */
import { execFile } from "node:child_process";
import { mkdtemp, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const execFileP = promisify(execFile);

// Defensive caps on attacker-controlled TSA cacert URLs.
const FETCH_TIMEOUT_MS = 15000;
const MAX_CACERT_BYTES = 1024 * 1024; // 1 MB — a real CA cert is < 10 KB.

const ROOTS_DIR = fileURLToPath(new URL("../../roots/", import.meta.url));

/** @type {Promise<Array<{name: string, bytes: Buffer}>> | null} */
let bundledRootsCache = null;

/**
 * Every pinned root in the bundle: each `*.pem` file
 * directly under `roots/`, read once per process and cached thereafter — the
 * bundle is static for the lifetime of an installed package version, so
 * re-reading the directory and every file on each `checkTsa()` call (an
 * export can carry many anchors, and a caller may verify many exports in one
 * process) is avoidable I/O. A new TSA is trusted by dropping its root cert
 * into `roots/` — no code change. See `roots/README.md` for the current
 * bundle and how to add one.
 *
 * @returns {Promise<Array<{name: string, bytes: Buffer}>>}
 */
function loadBundledRoots() {
  if (!bundledRootsCache) {
    bundledRootsCache = (async () => {
      const names = (await readdir(ROOTS_DIR)).filter((n) => n.endsWith(".pem")).sort();

      if (names.length === 0) {
        throw new Error(`no bundled TSA root certs found under ${ROOTS_DIR}`);
      }

      return Promise.all(
        names.map(async (name) => ({ name, bytes: await readFile(resolve(ROOTS_DIR, name)) })),
      );
    })().catch((err) => {
      // Don't cache a rejection — a transient read failure (e.g. a locked
      // file mid-write) shouldn't permanently poison every later call in
      // this process.
      bundledRootsCache = null;
      throw err;
    });
  }

  return bundledRootsCache;
}

/**
 * @param {{verification: {tsa_anchor_chain: any[]}}} data
 * @param {{fetcher?: typeof fetch, opensslPath?: string, caFile?: string, allowUntrustedTsa?: boolean}} [opts]
 * @returns {Promise<{ok: true, anchors: Array<{tsa_url: string, output: string, genTime: string}>} | {ok: false, error: string}>}
 */
export async function checkTsa(data, opts = {}) {
  const fetcher = opts.fetcher ?? fetch;
  const openssl = opts.opensslPath ?? "openssl";
  const caFile = opts.caFile;
  const allowUntrustedTsa = opts.allowUntrustedTsa ?? false;
  // The default path (no --ca-file, no --allow-untrusted-tsa) is the only one
  // where a verification failure warrants the "untrusted TSA" hint — the
  // other two paths are the caller explicitly choosing a trust root.
  const usingDefaultBundledRoot = !caFile && !allowUntrustedTsa;

  /** @type {Buffer | null} */
  let caFileBytes = null;
  if (caFile) {
    try {
      caFileBytes = await readFile(caFile);
    } catch (err) {
      return {
        ok: false,
        error: `failed to read --ca-file ${caFile}: ${errMessage(err)}`,
      };
    }
    if (caFileBytes.byteLength > MAX_CACERT_BYTES) {
      return {
        ok: false,
        error: `--ca-file ${caFile} exceeds ${MAX_CACERT_BYTES}-byte cap (got ${caFileBytes.byteLength})`,
      };
    }
  } else if (usingDefaultBundledRoot) {
    // Concatenate every pinned root into one CAfile — `openssl ts -verify
    // -CAfile` accepts a multi-cert PEM bundle natively and picks whichever
    // cert completes the chain, so an anchor verifies if it matches ANY
    // bundled root without this check needing to know which TSA (and thus
    // which root) actually signed it.
    const roots = await loadBundledRoots();
    caFileBytes = Buffer.concat(roots.map((r) => r.bytes));
  }
  // else (--allow-untrusted-tsa, no --ca-file): caFileBytes stays null — each
  // anchor's own tsa_cacert_url is fetched below.

  await assertOpenssl(openssl);

  const tmp = await mkdtemp(resolve(tmpdir(), "hasp-verify-"));
  const results = [];
  try {
    for (const [i, anchor] of data.verification.tsa_anchor_chain.entries()) {
      const tsrPath = resolve(tmp, `anchor-${i}.tsr`);
      const caPath = resolve(tmp, `cacert-${i}.pem`);
      await writeFile(tsrPath, Buffer.from(anchor.tsa_tsr_base64, "base64"));

      let anchorCaBytes = caFileBytes;
      if (!anchorCaBytes) {
        const fetched = await fetchCacert(fetcher, anchor.tsa_cacert_url);
        if (!fetched.ok) return { ok: false, error: fetched.error };
        anchorCaBytes = fetched.bytes;
      }
      await writeFile(caPath, anchorCaBytes);

      try {
        const { stdout, stderr } = await execFileP(openssl, [
          "ts",
          "-verify",
          "-in",
          tsrPath,
          "-CAfile",
          caPath,
          "-digest",
          anchor.anchored_data,
        ]);
        // openssl ts -verify writes "Verification: OK" to stderr on success,
        // but newer builds occasionally route it to stdout. Inspect both.
        const out = [stdout, stderr].filter(Boolean).join("\n").trim();
        if (!/Verification:\s*OK/i.test(out)) {
          return {
            ok: false,
            error: describeFailure(
              usingDefaultBundledRoot,
              `TSA anchor ${i} verification did not return OK: ${out}`,
            ),
          };
        }

        const genTime = await parseGenTime(execFileP, openssl, tsrPath);
        if (!genTime) {
          return {
            ok: false,
            error: `TSA anchor ${i} verified but its token's genTime could not be parsed`,
          };
        }

        results.push({ tsa_url: anchor.tsa_url, output: out, genTime });
      } catch (err) {
        const e = /** @type {{stderr?: unknown, stdout?: unknown, message?: unknown}} */ (
          err ?? {}
        );
        const detail = (e.stderr || e.stdout || e.message || "").toString().trim();
        return {
          ok: false,
          error: describeFailure(
            usingDefaultBundledRoot,
            `openssl ts -verify failed for anchor ${i}: ${detail}`,
          ),
        };
      }
    }
    return { ok: true, anchors: results };
  } finally {
    await rm(tmp, { recursive: true, force: true });
  }
}

/**
 * @param {boolean} usingDefaultBundledRoot
 * @param {string} detail
 */
function describeFailure(usingDefaultBundledRoot, detail) {
  if (!usingDefaultBundledRoot) return detail;
  return (
    `${detail} — did not verify against any bundled trusted root. This can mean an untrusted ` +
    "TSA (the export's real signer isn't one of the bundled roots) or simply an invalid/corrupted token — the " +
    "openssl output above says which. If this export was genuinely minted by a different, legitimate " +
    "TSA, pass --ca-file <path> to trust its CA cert explicitly, or --allow-untrusted-tsa to fetch and " +
    "trust the export's own declared tsa_cacert_url (re-admits the trust-root circularity this default " +
    "closes — only for sources you already trust)."
  );
}

/**
 * Parse the token's `genTime` via `openssl ts -reply -in <tsr> -text`, which
 * prints a "Time stamp: <RFC 2822-ish date>" line for a valid TSR. Returns an
 * ISO 8601 string, or null if the line is missing or unparseable.
 *
 * @param {typeof execFileP} exec
 * @param {string} openssl
 * @param {string} tsrPath
 * @returns {Promise<string | null>}
 */
async function parseGenTime(exec, openssl, tsrPath) {
  let stdout;
  try {
    ({ stdout } = await exec(openssl, ["ts", "-reply", "-in", tsrPath, "-text"]));
  } catch {
    return null;
  }
  // Anchored to line start: several fields earlier in -text output (e.g. the
  // TSA certificate's Subject DirName) are attacker-controlled in a forged-TSA
  // scenario, so an unanchored match could in principle be spoofed by a field
  // value that happens to contain the literal text "Time stamp:".
  const match = /^Time stamp:\s*(.+)$/m.exec(stdout);
  if (!match) return null;
  const parsed = new Date(match[1].trim());
  if (Number.isNaN(parsed.getTime())) return null;
  return parsed.toISOString();
}

/**
 * @param {typeof fetch} fetcher
 * @param {string} url
 * @returns {Promise<{ok: true, bytes: Buffer} | {ok: false, error: string}>}
 */
async function fetchCacert(fetcher, url) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), FETCH_TIMEOUT_MS);
  try {
    const res = await fetcher(url, { signal: ctrl.signal });
    if (!res.ok) {
      return { ok: false, error: `failed to fetch TSA CA cert from ${url}: HTTP ${res.status}` };
    }
    const buf = Buffer.from(await res.arrayBuffer());
    if (buf.byteLength > MAX_CACERT_BYTES) {
      return {
        ok: false,
        error: `TSA CA cert from ${url} exceeds ${MAX_CACERT_BYTES}-byte cap (got ${buf.byteLength})`,
      };
    }
    return { ok: true, bytes: buf };
  } catch (err) {
    return { ok: false, error: `failed to fetch TSA CA cert from ${url}: ${errMessage(err)}` };
  } finally {
    clearTimeout(timer);
  }
}

/** @param {string} openssl */
async function assertOpenssl(openssl) {
  try {
    await execFileP(openssl, ["version"]);
  } catch {
    throw new Error(
      `openssl not found on PATH (looked for '${openssl}'). Install OpenSSL 1.1+ or pass --skip-tsa.`,
    );
  }
}

/** @param {unknown} err */
function errMessage(err) {
  return err instanceof Error ? err.message : String(err);
}
