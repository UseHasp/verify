#!/usr/bin/env node
/**
 * Builds the four broken fixtures from valid.json:
 *   broken-schema.json     — invalid schema_version
 *   broken-chain.json      — mutated entry payload (chain breaks)
 *   broken-signature.json  — mutated signature on one entry
 *   broken-tsa.json        — mutated TSR bytes
 *
 * Re-run if valid.json is updated.
 */
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const src = JSON.parse(readFileSync(resolve(here, "valid.json"), "utf8"));

function clone(x) {
  return JSON.parse(JSON.stringify(x));
}

// broken-schema: bump version to something we don't support
{
  const f = clone(src);
  f.schema_version = "99.0";
  writeFileSync(resolve(here, "broken-schema.json"), `${JSON.stringify(f, null, 2)}\n`);
}

// broken-chain: mutate an entry's metadata after the fact (hash still valid for its own object,
// but recompute would not match because we change a field without recomputing hashes)
{
  const f = clone(src);
  f.entries[1].action = "ai.chat.response.tampered";
  writeFileSync(resolve(here, "broken-chain.json"), `${JSON.stringify(f, null, 2)}\n`);
}

// broken-signature: flip a byte in the last entry's signature
{
  const f = clone(src);
  const e = f.entries[f.entries.length - 1];
  const [algo, b64] = e.signature.split(":");
  const buf = Buffer.from(b64, "base64");
  buf[0] = buf[0] ^ 0x01;
  e.signature = `${algo}:${buf.toString("base64")}`;
  // also fix the hash so chain check passes and we reach the signature check
  // (the chain hashes payload-without-signature, so a sig flip alone doesn't break chain;
  // but the schema check needs the entry well-formed — leave hash as is)
  writeFileSync(resolve(here, "broken-signature.json"), `${JSON.stringify(f, null, 2)}\n`);
}

// broken-tsa: corrupt the TSR bytes
{
  const f = clone(src);
  const a = f.verification.tsa_anchor_chain[0];
  const buf = Buffer.from(a.tsa_tsr_base64, "base64");
  buf[10] = buf[10] ^ 0xff;
  a.tsa_tsr_base64 = buf.toString("base64");
  writeFileSync(resolve(here, "broken-tsa.json"), `${JSON.stringify(f, null, 2)}\n`);
}

console.log("Wrote broken-{schema,chain,signature,tsa}.json");
