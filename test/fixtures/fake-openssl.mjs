#!/usr/bin/env node
/**
 * Fake `openssl` binary for the backdated-genTime test (test/backdating.test.js).
 * The backdating check compares a TSA token's parsed `genTime` against
 * the entry it's bound to — that comparison is pure date-arithmetic, not
 * cryptography, so exercising it doesn't need a genuine forged TSA chain
 * (unlike test/forged-tsa.test.js, which does). This stub always reports a
 * successful `ts -verify` and lets the caller control the reported `genTime`
 * via the FAKE_GEN_TIME env var — checkTsa spawns it via `opensslPath`, which
 * inherits the current process env like any child_process call.
 */
const args = process.argv.slice(2);

if (args[0] === "version") {
  process.stdout.write("fake-openssl 0.0.0 (test/fixtures/fake-openssl.mjs)\n");
  process.exit(0);
}
if (args.includes("-verify")) {
  process.stderr.write("Verification: OK\n");
  process.exit(0);
}
if (args.includes("-reply") && args.includes("-text")) {
  const genTime = process.env.FAKE_GEN_TIME ?? "Aug  2 19:52:03 2026 GMT";
  process.stdout.write(`Time stamp: ${genTime}\n`);
  process.exit(0);
}
process.stderr.write(`fake-openssl: unhandled args ${JSON.stringify(args)}\n`);
process.exit(1);
