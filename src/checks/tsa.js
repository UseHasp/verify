/**
 * Check 3: RFC 3161 TSA anchor.
 *
 * For each anchor in tsa_anchor_chain:
 *  1. Decode the base64 TSR.
 *  2. Fetch the TSA CA certificate from `tsa_cacert_url`.
 *  3. Shell out to `openssl ts -verify -in tsr -CAfile cacert -data <chain_head_hash_ascii>`.
 *
 * Returns OK only if every anchor verifies. `--skip-tsa` bypasses this check.
 *
 * Note: the data file passed to openssl is the ASCII hex string of the chain
 * head (matches the generator, which writes `Buffer.from(chainHead, "utf8")`).
 */
import { execFile } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { promisify } from "node:util";

const execFileP = promisify(execFile);

// Defensive caps on attacker-controlled TSA cacert URLs.
const FETCH_TIMEOUT_MS = 15000;
const MAX_CACERT_BYTES = 1024 * 1024; // 1 MB — a real CA cert is < 10 KB.

/**
 * @param {{verification: {chain_head_hash: string, tsa_anchor_chain: any[]}}} data
 * @param {{fetcher?: typeof fetch, opensslPath?: string}} [opts]
 * @returns {Promise<{ok: true, anchors: Array<{tsa_url: string, output: string}>} | {ok: false, error: string}>}
 */
export async function checkTsa(data, opts = {}) {
  const fetcher = opts.fetcher ?? fetch;
  const openssl = opts.opensslPath ?? "openssl";
  const chainHead = data.verification.chain_head_hash;

  await assertOpenssl(openssl);

  const tmp = await mkdtemp(resolve(tmpdir(), "hasp-verify-"));
  const results = [];
  try {
    const dataPath = resolve(tmp, "chainhead.bin");
    await writeFile(dataPath, Buffer.from(chainHead, "utf8"));

    for (const [i, anchor] of data.verification.tsa_anchor_chain.entries()) {
      const tsrPath = resolve(tmp, `anchor-${i}.tsr`);
      const caPath = resolve(tmp, `cacert-${i}.pem`);
      await writeFile(tsrPath, Buffer.from(anchor.tsa_tsr_base64, "base64"));

      const fetched = await fetchCacert(fetcher, anchor.tsa_cacert_url);
      if (!fetched.ok) return { ok: false, error: fetched.error };
      await writeFile(caPath, fetched.bytes);

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
        results.push({ tsa_url: anchor.tsa_url, output: out });
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
