/**
 * Check: RFC 3161 TSA anchor.
 *
 * For each anchor in `tsa_anchor_chain`:
 *   1. Decode the base64 TSR (the RFC 3161 TimeStampResp).
 *   2. Obtain the TSA CA certificate — fetch `tsa_cacert_url`, or read a local
 *      PEM passed via `--ca-file`.
 *   3. Write the anchor's `anchored_data` (the covered hash, as ASCII bytes)
 *      to a file and run
 *        openssl ts -verify -in <tsr> -CAfile <cacert> -data <anchored_data>
 *      requiring `Verification: OK`.
 *
 * The chain check has already confirmed `anchored_data` equals the hash of the
 * entry at the anchor's checkpoint, so a verified token proves that checkpoint
 * existed no later than the TSA's timestamp. Returns OK only if every anchor
 * verifies. `--skip-tsa` bypasses this check.
 */
import { execFile } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { promisify } from "node:util";

const execFileP = promisify(execFile);

// Defensive caps on attacker-controlled TSA cacert URLs.
const FETCH_TIMEOUT_MS = 15000;
const MAX_CACERT_BYTES = 1024 * 1024; // 1 MB — a real CA cert is < 10 KB.

/**
 * @param {{verification: {tsa_anchor_chain: any[]}}} data
 * @param {{fetcher?: typeof fetch, opensslPath?: string, caFile?: string}} [opts]
 * @returns {Promise<{ok: true, anchors: Array<{tsa_url: string, anchored_data: string, output: string}>} | {ok: false, error: string}>}
 */
export async function checkTsa(data, opts = {}) {
  const fetcher = opts.fetcher ?? fetch;
  const openssl = opts.opensslPath ?? "openssl";
  const caFile = opts.caFile;

  /** @type {Buffer | null} */
  let caFileBytes = null;
  if (caFile) {
    try {
      caFileBytes = await readFile(caFile);
    } catch (err) {
      return { ok: false, error: `failed to read --ca-file ${caFile}: ${errMessage(err)}` };
    }
    if (caFileBytes.byteLength > MAX_CACERT_BYTES) {
      return {
        ok: false,
        error: `--ca-file ${caFile} exceeds ${MAX_CACERT_BYTES}-byte cap (got ${caFileBytes.byteLength})`,
      };
    }
  }

  await assertOpenssl(openssl);

  const tmp = await mkdtemp(resolve(tmpdir(), "hasp-verify-"));
  const results = [];
  try {
    for (const [i, anchor] of data.verification.tsa_anchor_chain.entries()) {
      const tsrPath = resolve(tmp, `anchor-${i}.tsr`);
      const caPath = resolve(tmp, `cacert-${i}.pem`);
      const dataPath = resolve(tmp, `anchored-${i}.bin`);
      await writeFile(tsrPath, Buffer.from(anchor.tsa_tsr_base64, "base64"));
      await writeFile(dataPath, Buffer.from(anchor.anchored_data, "utf8"));

      if (caFileBytes) {
        await writeFile(caPath, caFileBytes);
      } else {
        const fetched = await fetchCacert(fetcher, anchor.tsa_cacert_url);
        if (!fetched.ok) return { ok: false, error: fetched.error };
        await writeFile(caPath, fetched.bytes);
      }

      try {
        const { stdout, stderr } = await execFileP(openssl, [
          "ts",
          "-verify",
          "-in",
          tsrPath,
          "-CAfile",
          caPath,
          "-data",
          dataPath,
        ]);
        // openssl ts -verify writes "Verification: OK" to stderr on success,
        // but newer builds occasionally route it to stdout. Inspect both.
        const out = [stdout, stderr].filter(Boolean).join("\n").trim();
        if (!/Verification:\s*OK/i.test(out)) {
          return { ok: false, error: `TSA anchor ${i} verification did not return OK: ${out}` };
        }
        results.push({ tsa_url: anchor.tsa_url, anchored_data: anchor.anchored_data, output: out });
      } catch (err) {
        const e = /** @type {{stderr?: unknown, stdout?: unknown, message?: unknown}} */ (
          err ?? {}
        );
        const detail = (e.stderr || e.stdout || e.message || "").toString().trim();
        return { ok: false, error: `openssl ts -verify failed for anchor ${i}: ${detail}` };
      }
    }
    return { ok: true, anchors: results };
  } finally {
    await rm(tmp, { recursive: true, force: true });
  }
}

/**
 * @param {typeof fetch} fetcher
 * @param {string} url
 * @returns {Promise<{ok: true, bytes: Buffer} | {ok: false, error: string}>}
 */
async function fetchCacert(fetcher, url) {
  try {
    const res = await fetcher(url, { signal: AbortSignal.timeout(FETCH_TIMEOUT_MS) });
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
