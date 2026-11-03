/**
 * Unit tests for checkTsa.
 *
 * The committed fixture's TSA token is a PLACEHOLDER (freetsa.org is
 * egress-blocked where the real-crypto fixture is minted), so the live
 * `openssl ts -verify` path cannot pass against it. Instead we mock
 * `node:child_process`'s `execFile` and inject a fake `fetch`, then assert
 * `checkTsa` shells out to `openssl ts -verify ... -digest <anchor.anchored_data>`
 * — the digest convention (NOT `-data <file>`), using each anchor's OWN
 * `anchored_data` (not `chain_head_hash` — whether `anchored_data` is
 * evidence for this export is the anchoring check's job, not this one's) —
 * and to `openssl ts -reply -in <tsr> -text` to parse `genTime`.
 *
 * Default trust root is the bundled FreeTSA cert (`roots/freetsa-cacert.pem`,
 * a real file on disk — no mocking needed to read it); the CA-cert fetch only
 * happens when `--allow-untrusted-tsa` opts into trusting the export's own
 * declared `tsa_cacert_url`. All child-process calls are mocked, so the tests
 * are fully offline either way.
 */
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { beforeEach, describe, expect, it, vi } from "vitest";

const hoisted = vi.hoisted(() => {
  const state = {
    /** @type {Array<{cmd: string, args: string[]}>} */
    calls: [],
    /** @type {{stdout: string, stderr: string} | null} */
    tsResult: null,
    /** @type {any} */
    tsError: null,
    /** @type {{stdout: string, stderr: string} | null} */
    replyResult: null,
    /** @type {any} */
    replyError: null,
  };
  return {
    state,
    handle(/** @type {string} */ cmd, /** @type {string[]} */ args) {
      state.calls.push({ cmd, args });
      if (args[0] === "version") {
        // Simulate a missing binary when the caller points at a bogus path.
        if (cmd.includes("nonexistent")) throw new Error("spawn ENOENT");
        return { stdout: "OpenSSL 3.0.13 30 Jan 2024\n", stderr: "" };
      }
      if (args.includes("-reply")) {
        if (state.replyError) throw state.replyError;
        return (
          state.replyResult ?? { stdout: "Time stamp: Aug  2 19:52:03 2026 GMT\n", stderr: "" }
        );
      }
      // `ts -verify`
      if (state.tsError) throw state.tsError;
      return state.tsResult ?? { stdout: "", stderr: "Verification: OK\n" };
    },
  };
});

vi.mock("node:child_process", async () => {
  const { promisify } = await import("node:util");
  const execFile = () => {
    throw new Error("callback form of execFile is not used by tsa.js");
  };
  execFile[promisify.custom] = (/** @type {string} */ cmd, /** @type {string[]} */ args) =>
    Promise.resolve().then(() => hoisted.handle(cmd, args));
  return { execFile };
});

const { checkTsa } = await import("../src/checks/tsa.js");

const here = dirname(fileURLToPath(import.meta.url));
const VALID = JSON.parse(readFileSync(resolve(here, "fixtures", "valid.json"), "utf8"));
const CACERT = readFileSync(resolve(here, "fixtures", "tsa-cacert.pem"));
const clone = () => JSON.parse(JSON.stringify(VALID));

function mockFetcher(body, ok = true, status = 200) {
  return async () => ({
    ok,
    status,
    arrayBuffer: async () => body.buffer.slice(body.byteOffset, body.byteOffset + body.byteLength),
  });
}

function throwingFetcher(label = "fetcher should not be called") {
  return async () => {
    throw new Error(label);
  };
}

/** Find the `openssl ts -verify` invocation among recorded execFile calls. */
function tsVerifyCall() {
  return hoisted.state.calls.find((c) => c.args[0] === "ts" && c.args.includes("-verify"));
}

beforeEach(() => {
  hoisted.state.calls = [];
  hoisted.state.tsResult = null;
  hoisted.state.tsError = null;
  hoisted.state.replyResult = null;
  hoisted.state.replyError = null;
});

describe("checkTsa — default trust root (bundled FreeTSA cert)", () => {
  it("verifies with `openssl ts -verify -in <tsr> -CAfile <ca> -digest <anchor.anchored_data>` and never calls the fetcher", async () => {
    const r = await checkTsa(VALID, { fetcher: throwingFetcher() });
    expect(r.ok).toBe(true);
    expect(r.anchors).toHaveLength(1);
    expect(r.anchors[0].output).toMatch(/Verification:\s*OK/);

    const call = tsVerifyCall();
    expect(call).toBeDefined();
    // Uses the digest convention — the anchor's own anchored_data passed directly.
    expect(call.args).toContain("-digest");
    const digestIdx = call.args.indexOf("-digest");
    expect(call.args[digestIdx + 1]).toBe(VALID.verification.tsa_anchor_chain[0].anchored_data);
    // Must NOT feed a data file (which would make openssl hash it first).
    expect(call.args).not.toContain("-data");
    // Standard flags still present.
    expect(call.args).toContain("-in");
    expect(call.args).toContain("-CAfile");
  });

  it("verifies each anchor over its OWN anchored_data, not chain_head_hash", async () => {
    // A mutated anchored_data must flow straight through to -digest — checkTsa
    // no longer asserts it equals chain_head_hash (that's the anchoring check).
    const d = clone();
    d.verification.tsa_anchor_chain[0].anchored_data = "a".repeat(64);
    const r = await checkTsa(d, { fetcher: throwingFetcher() });
    expect(r.ok).toBe(true);
    const call = tsVerifyCall();
    const digestIdx = call.args.indexOf("-digest");
    expect(call.args[digestIdx + 1]).toBe("a".repeat(64));
  });

  it("parses the token's genTime and surfaces it as ISO 8601", async () => {
    const r = await checkTsa(VALID, { fetcher: throwingFetcher() });
    expect(r.ok).toBe(true);
    expect(r.anchors[0].genTime).toBe("2026-08-02T19:52:03.000Z");
  });

  it("fails when genTime cannot be parsed from the -reply -text output", async () => {
    hoisted.state.replyResult = { stdout: "no time stamp line here\n", stderr: "" };
    const r = await checkTsa(VALID, { fetcher: throwingFetcher() });
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/genTime could not be parsed/);
  });

  it("fails when the -reply -text call itself errors", async () => {
    hoisted.state.replyError = new Error("openssl exploded");
    const r = await checkTsa(VALID, { fetcher: throwingFetcher() });
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/genTime could not be parsed/);
  });

  it("genTime parsing is anchored to line start — a mid-line 'Time stamp:' substring (e.g. an attacker-controlled certificate field) cannot spoof it", async () => {
    hoisted.state.replyResult = {
      stdout:
        "TSA: DirName:/O=Evil injected Time stamp: Jan  1 2000 GMT/CN=Attacker\n" +
        "Time stamp: Aug  2 19:52:03 2026 GMT\n",
      stderr: "",
    };
    const r = await checkTsa(VALID, { fetcher: throwingFetcher() });
    expect(r.ok).toBe(true);
    expect(r.anchors[0].genTime).toBe("2026-08-02T19:52:03.000Z");
  });

  it("fails with an 'untrusted TSA' hint when openssl reports a non-OK verification", async () => {
    hoisted.state.tsResult = { stdout: "", stderr: "Verification: FAILED\n" };
    const r = await checkTsa(VALID, { fetcher: throwingFetcher() });
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/did not return OK/);
    expect(r.error).toMatch(/untrusted TSA/);
    expect(r.error).toMatch(/--ca-file/);
    expect(r.error).toMatch(/--allow-untrusted-tsa/);
  });

  it("fails with an 'untrusted TSA' hint when openssl ts -verify exits non-zero", async () => {
    hoisted.state.tsError = Object.assign(new Error("exit 1"), {
      stderr: "Verification: FAILED\nmessage imprint mismatch\n",
    });
    const r = await checkTsa(VALID, { fetcher: throwingFetcher() });
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/openssl ts -verify failed/);
    expect(r.error).toMatch(/message imprint mismatch/);
    expect(r.error).toMatch(/untrusted TSA/);
  });

  it("throws when the openssl binary is missing", async () => {
    await expect(
      checkTsa(VALID, { fetcher: throwingFetcher(), opensslPath: "/nonexistent/openssl-xyz" }),
    ).rejects.toThrow(/openssl not found/);
  });
});

describe("checkTsa — multi-root trust bundle", () => {
  it("builds the default -CAfile from every *.pem file under roots/, concatenated", async () => {
    // Capture the exact bytes written to the -CAfile path at the moment
    // openssl is invoked (before checkTsa's own tmpdir cleanup). Proves the
    // check reads every bundled root generically — not a single hardcoded
    // file path — so adding a second pinned root (roots/*.pem) is picked up
    // with no code change.
    /** @type {Buffer | null} */
    let capturedCaFileBytes = null;
    const { readFileSync: readSync } = await import("node:fs");
    const origHandle = hoisted.handle;
    hoisted.handle = (cmd, args) => {
      if (args.includes("-CAfile")) {
        capturedCaFileBytes = readSync(args[args.indexOf("-CAfile") + 1]);
      }
      return origHandle(cmd, args);
    };

    const { readdir } = await import("node:fs/promises");
    const rootsDir = resolve(here, "..", "roots");
    const rootFiles = (await readdir(rootsDir)).filter((n) => n.endsWith(".pem")).sort();
    const expected = Buffer.concat(rootFiles.map((f) => readSync(resolve(rootsDir, f))));

    let r;
    try {
      r = await checkTsa(VALID, { fetcher: throwingFetcher() });
    } finally {
      // Restore even if checkTsa throws, so a failure here can't leak the
      // override into later tests and cause cascading failures.
      hoisted.handle = origHandle;
    }

    expect(r.ok).toBe(true);
    expect(rootFiles.length).toBeGreaterThan(0);
    expect(capturedCaFileBytes?.equals(expected)).toBe(true);
  });
});

describe("checkTsa — --ca-file (explicit trust root)", () => {
  it("uses the local cert and never invokes the fetcher", async () => {
    const r = await checkTsa(VALID, {
      fetcher: throwingFetcher(),
      caFile: resolve(here, "fixtures", "tsa-cacert.pem"),
    });
    expect(r.ok).toBe(true);
  });

  it("does NOT add the 'untrusted TSA' hint on failure — the caller made an explicit choice", async () => {
    hoisted.state.tsResult = { stdout: "", stderr: "Verification: FAILED\n" };
    const r = await checkTsa(VALID, {
      fetcher: throwingFetcher(),
      caFile: resolve(here, "fixtures", "tsa-cacert.pem"),
    });
    expect(r.ok).toBe(false);
    expect(r.error).not.toMatch(/untrusted TSA/);
  });

  it("pointing at a missing path returns a clear error", async () => {
    const r = await checkTsa(VALID, { caFile: "/nonexistent/ca-xyz.pem" });
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/failed to read --ca-file/);
  });

  it("rejects an oversized --ca-file", async () => {
    const dir = mkdtempSync(resolve(tmpdir(), "hasp-verify-catest-"));
    const big = resolve(dir, "big.pem");
    writeFileSync(big, Buffer.alloc(1024 * 1024 + 1, 0x41));
    const r = await checkTsa(VALID, { caFile: big });
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/exceeds .*byte cap/);
  });
});

describe("checkTsa — --allow-untrusted-tsa (opt-in fetch of the export's own tsa_cacert_url)", () => {
  it("fetches the CA cert from the export's tsa_cacert_url", async () => {
    let fetchedUrl = null;
    const fetcher = async (url) => {
      fetchedUrl = url;
      return {
        ok: true,
        status: 200,
        arrayBuffer: async () =>
          CACERT.buffer.slice(CACERT.byteOffset, CACERT.byteOffset + CACERT.byteLength),
      };
    };
    const r = await checkTsa(VALID, { fetcher, allowUntrustedTsa: true });
    expect(r.ok).toBe(true);
    expect(fetchedUrl).toBe(VALID.verification.tsa_anchor_chain[0].tsa_cacert_url);
  });

  it("does NOT add the 'untrusted TSA' hint on failure — the caller opted in", async () => {
    hoisted.state.tsResult = { stdout: "", stderr: "Verification: FAILED\n" };
    const r = await checkTsa(VALID, { fetcher: mockFetcher(CACERT), allowUntrustedTsa: true });
    expect(r.ok).toBe(false);
    expect(r.error).not.toMatch(/untrusted TSA/);
  });

  it("--ca-file still wins over --allow-untrusted-tsa (never calls the fetcher)", async () => {
    const r = await checkTsa(VALID, {
      fetcher: throwingFetcher(),
      allowUntrustedTsa: true,
      caFile: resolve(here, "fixtures", "tsa-cacert.pem"),
    });
    expect(r.ok).toBe(true);
  });

  it("fails when cacert fetch returns non-OK HTTP", async () => {
    const r = await checkTsa(VALID, {
      fetcher: mockFetcher(Buffer.alloc(0), false, 503),
      allowUntrustedTsa: true,
    });
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/HTTP 503/);
  });

  it("fails when cacert fetch throws", async () => {
    const r = await checkTsa(VALID, {
      fetcher: async () => {
        throw new Error("network down");
      },
      allowUntrustedTsa: true,
    });
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/network down/);
  });

  it("rejects an oversized cacert response", async () => {
    const huge = Buffer.alloc(1024 * 1024 + 1, 0x41);
    const r = await checkTsa(VALID, { fetcher: mockFetcher(huge), allowUntrustedTsa: true });
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/exceeds .*byte cap/);
  });

  it("aborts the cacert fetch when the 15s timeout elapses", async () => {
    vi.useFakeTimers();
    try {
      let markFetchStarted;
      const fetchStarted = new Promise((r) => {
        markFetchStarted = r;
      });
      const fetcher = (_url, init) => {
        // By the time fetchCacert calls the fetcher, its timeout is registered.
        markFetchStarted();
        return new Promise((_resolve, reject) => {
          init.signal.addEventListener("abort", () => reject(new Error("aborted by signal")));
        });
      };
      const p = checkTsa(VALID, { fetcher, allowUntrustedTsa: true });
      await fetchStarted; // real fs (mkdtemp/writeFile) has settled; timer is armed
      await vi.advanceTimersByTimeAsync(15001);
      const r = await p;
      expect(r.ok).toBe(false);
      expect(r.error).toMatch(/aborted by signal/);
    } finally {
      vi.useRealTimers();
    }
  });

  it("passes an AbortSignal to the fetcher (so the 15s timeout can fire)", async () => {
    let receivedSignal = null;
    const fetcher = async (_url, init) => {
      receivedSignal = init?.signal ?? null;
      return {
        ok: true,
        status: 200,
        arrayBuffer: async () =>
          CACERT.buffer.slice(CACERT.byteOffset, CACERT.byteOffset + CACERT.byteLength),
      };
    };
    await checkTsa(VALID, { fetcher, allowUntrustedTsa: true });
    expect(receivedSignal).not.toBeNull();
    expect(typeof receivedSignal.aborted).toBe("boolean");
  });
});
