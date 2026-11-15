/**
 * Canonical JSON for the audit-row hash.
 *
 * The platform computes each entry's `hash` as SHA-256 over PHP's
 * `json_encode($fields, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE)`,
 * after recursively key-sorting `metadata` / `caller_attribution` with PHP's
 * `ksort()`. Reproducing that digest means reproducing those exact bytes, and
 * `JSON.stringify` does not: it differs from PHP on four points, each of
 * which makes a genuine export fail verification.
 *
 *   1. Floats. PHP prints a double in exponent form once its decimal exponent
 *      leaves [-4, 17] and always keeps a fraction digit in the mantissa
 *      (`1.0e-5`, `1.0e+25`); JavaScript prints `0.00001` and `1e+25`.
 *   2. Line separators. PHP escapes U+2028 / U+2029 (`\u2028`) even with
 *      `JSON_UNESCAPED_UNICODE`; JavaScript emits them raw.
 *   3. Key order. `ksort()` orders integer-like keys numerically and compares
 *      a number with a non-numeric string as strings; `Array#sort()` is plain
 *      UTF-16 code-unit order, and a JavaScript object enumerates
 *      integer-like keys first whatever order they were inserted in.
 *   4. Integers above 2^53. PHP holds 64-bit integers exactly; a JavaScript
 *      number does not. {@link parseExport} keeps them exact as BigInt.
 *
 * {@link encodeCanonical} is the encoder the chain check hashes with.
 * {@link canonicalizeForHash} is the older value transform, kept for callers
 * that only need a key-sorted plain value.
 */
import { randomBytes } from "node:crypto";

const INT64_MAX = 2n ** 63n - 1n;
const INT64_MIN = -(2n ** 63n);
const INT64_LIMIT = 2 ** 63;

// A PHP array key is an integer when the string is a canonical decimal
// integer (no leading zeros, no "+", not "-0") that fits in 64 bits.
const CANONICAL_INT = /^(?:0|-?[1-9][0-9]*)$/;
// PHP 8 "numeric string": optional surrounding whitespace, optional sign,
// decimal digits with optional fraction and exponent.
const NUMERIC_STRING =
  /^[ \t\n\r\v\f]*[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?[ \t\n\r\v\f]*$/;
const INTEGER_STRING = /^[ \t\n\r\v\f]*[+-]?[0-9]+[ \t\n\r\v\f]*$/;

/**
 * Parse export JSON without losing integers above 2^53.
 *
 * `JSON.parse` rounds any integer beyond `Number.MAX_SAFE_INTEGER`, so an
 * entry whose metadata holds one (a nanosecond timestamp, a 64-bit id) could
 * never be re-hashed. Such tokens are returned as BigInt; everything else is
 * exactly what `JSON.parse` returns.
 *
 * Works by rewriting each long integer token to a marker string before
 * parsing and reviving the marker afterwards. The marker carries a random
 * nonce that is checked not to occur in the input, so no string already in
 * the document can be mistaken for a number.
 *
 * @param {string} text
 * @returns {unknown}
 */
export function parseExport(text) {
  let nonce;
  do {
    nonce = `hasp-int-${randomBytes(12).toString("hex")}:`;
  } while (text.includes(nonce));

  let rewritten = "";
  let copiedTo = 0;
  let found = false;
  let i = 0;
  const n = text.length;
  while (i < n) {
    const ch = text.charCodeAt(i);
    if (ch === 0x22) {
      // Skip a string literal; a backslash always escapes the next character.
      i++;
      while (i < n) {
        const c = text.charCodeAt(i);
        if (c === 0x5c) i += 2;
        else if (c === 0x22) break;
        else i++;
      }
      i++;
      continue;
    }
    if (ch === 0x2d || (ch >= 0x30 && ch <= 0x39)) {
      const start = i;
      i++;
      while (i < n && isNumberChar(text.charCodeAt(i))) i++;
      const token = text.slice(start, i);
      if (/^-?[0-9]{16,}$/.test(token) && !Number.isSafeInteger(Number(token))) {
        rewritten += `${text.slice(copiedTo, start)}"${nonce}${token}"`;
        copiedTo = i;
        found = true;
      }
      continue;
    }
    i++;
  }
  if (!found) return JSON.parse(text);

  rewritten += text.slice(copiedTo);
  return JSON.parse(rewritten, (_key, value) =>
    typeof value === "string" && value.startsWith(nonce)
      ? BigInt(value.slice(nonce.length))
      : value,
  );
}

/** @param {number} c */
function isNumberChar(c) {
  // digits, ".", "e", "E", "+", "-"
  return (
    (c >= 0x30 && c <= 0x39) || c === 0x2e || c === 0x65 || c === 0x45 || c === 0x2b || c === 0x2d
  );
}

/**
 * Encode a value exactly as the platform's canonical `json_encode` does.
 *
 * Object keys are ordered one of two ways, chosen by the entry's digest
 * composition:
 *
 *   - `byteOrderedKeys` false (entries with no `digest_version`): PHP's
 *     `ksort()` order, as those entries were sealed.
 *   - `byteOrderedKeys` true (entries carrying `digest_version`): plain
 *     UTF-8 byte order — a total order with one answer in every language.
 *
 * In both, an object whose keys are exactly 0..n-1 is a list (the platform's
 * array type cannot tell the two apart) and encodes as a JSON array in
 * numeric order; that includes the empty object.
 *
 * @param {unknown} value
 * @param {boolean} [byteOrderedKeys]
 * @returns {string}
 */
export function encodeCanonical(value, byteOrderedKeys = false) {
  if (value === null || value === undefined) return "null";
  switch (typeof value) {
    case "boolean":
      return value ? "true" : "false";
    case "string":
      return encodeString(value);
    case "bigint":
      return encodeBigInt(value);
    case "number":
      return encodeNumber(value);
    case "object":
      break;
    default:
      throw new TypeError(`cannot canonicalize a value of type ${typeof value}`);
  }

  /** @param {unknown} item */
  const encode = (item) => encodeCanonical(item, byteOrderedKeys);

  if (Array.isArray(value)) {
    return `[${value.map(encode).join(",")}]`;
  }

  const record = /** @type {Record<string, unknown>} */ (value);
  const keys = Object.keys(record);

  if (byteOrderedKeys) {
    if (isListKeySet(keys)) {
      return `[${keys.map((_key, index) => encode(record[String(index)])).join(",")}]`;
    }
    const ordered = keys
      .map((key) => ({ key, bytes: Buffer.from(key, "utf8") }))
      .sort((a, b) => Buffer.compare(a.bytes, b.bytes));
    return `{${ordered.map(({ key }) => `${encodeString(key)}:${encode(record[key])}`).join(",")}}`;
  }

  const sorted = phpKsort(keys);
  if (sorted.every((key, index) => key === String(index))) {
    return `[${sorted.map((key) => encode(record[key])).join(",")}]`;
  }
  return `{${sorted.map((key) => `${encodeString(key)}:${encode(record[key])}`).join(",")}}`;
}

/**
 * Whether the keys are exactly "0".."n-1", in any order.
 *
 * @param {string[]} keys
 */
function isListKeySet(keys) {
  const wanted = new Set(keys.map((_key, index) => String(index)));
  return keys.every((key) => wanted.has(key));
}

/** @param {string} value */
function encodeString(value) {
  return JSON.stringify(value).replace(/[\u2028\u2029]/g, (c) =>
    c === "\u2028" ? "\\u2028" : "\\u2029",
  );
}

/** @param {bigint} value */
function encodeBigInt(value) {
  if (value >= INT64_MIN && value <= INT64_MAX) return value.toString();
  // Beyond 64 bits PHP reads the token as a double.
  return encodeNumber(Number(value));
}

/** @param {number} value */
function encodeNumber(value) {
  if (!Number.isFinite(value)) {
    throw new TypeError("cannot canonicalize a non-finite number");
  }
  // The platform seals an integral number that fits in 64 bits as an
  // integer, so it prints as plain digits whatever its magnitude.
  if (Number.isInteger(value) && Math.abs(value) < INT64_LIMIT) {
    return BigInt(value).toString();
  }

  // Shortest round-trip digits, the same digit string PHP produces.
  const [mantissa, exponentText] = Math.abs(value).toExponential().split("e");
  const digits = mantissa.replace(".", "");
  const pointAt = Number(exponentText) + 1; // value = 0.DIGITS x 10^pointAt
  const sign = value < 0 ? "-" : "";

  if (pointAt < -3 || pointAt > 17) {
    const exponent = pointAt - 1;
    const fraction = digits.length > 1 ? digits.slice(1) : "0";
    return `${sign}${digits[0]}.${fraction}e${exponent < 0 ? "-" : "+"}${Math.abs(exponent)}`;
  }
  if (pointAt <= 0) {
    return `${sign}0.${"0".repeat(-pointAt)}${digits}`;
  }
  if (digits.length <= pointAt) {
    return `${sign}${digits}${"0".repeat(pointAt - digits.length)}`;
  }
  return `${sign}${digits.slice(0, pointAt)}.${digits.slice(pointAt)}`;
}

/**
 * Order keys the way PHP's `ksort()` (default flags) does.
 *
 * A stable insertion sort over PHP 8's key comparison, started from the
 * stored key order. Every key set made only of integers, or only of
 * non-numeric strings, has one order and it is reproduced exactly. PHP's
 * comparison is not transitive for some mixed sets (`2 < 10 < "1a"` but
 * `"1a" < 2`); for those the result depends on the sort algorithm's exact
 * comparison sequence, which this does not claim to mirror beyond what the
 * shared vectors pin.
 *
 * @param {string[]} keys
 * @returns {string[]}
 */
function phpKsort(keys) {
  // Start from the order the platform's JSON column returns keys in (byte
  // length, then bytes), as the platform's own sort does — a JavaScript
  // object cannot be relied on to hand them over in file order.
  const typed = keys
    .map(toPhpKey)
    .sort((a, b) => a.bytes.length - b.bytes.length || Buffer.compare(a.bytes, b.bytes));
  for (let i = 1; i < typed.length; i++) {
    const item = typed[i];
    let j = i - 1;
    while (j >= 0 && comparePhpKeys(typed[j], item) > 0) {
      typed[j + 1] = typed[j];
      j--;
    }
    typed[j + 1] = item;
  }
  return typed.map((k) => k.raw);
}

/**
 * @typedef {{raw: string, bytes: Buffer, int: bigint | null}} PhpKey
 * @param {string} raw
 * @returns {PhpKey}
 */
function toPhpKey(raw) {
  const bytes = Buffer.from(raw, "utf8");
  if (CANONICAL_INT.test(raw)) {
    const int = BigInt(raw);
    if (int >= INT64_MIN && int <= INT64_MAX) return { raw, bytes, int };
  }
  return { raw, bytes, int: null };
}

/**
 * @param {PhpKey} a
 * @param {PhpKey} b
 * @returns {number}
 */
function comparePhpKeys(a, b) {
  if (a.int !== null && b.int !== null) {
    return a.int < b.int ? -1 : a.int > b.int ? 1 : 0;
  }
  if (a.int === null && b.int === null) {
    if (NUMERIC_STRING.test(a.raw) && NUMERIC_STRING.test(b.raw)) {
      return compareNumeric(a.raw, b.raw);
    }
    return Buffer.compare(a.bytes, b.bytes);
  }
  // One integer key, one string key: numeric when the string is numeric,
  // otherwise the integer is compared as its decimal string.
  const stringKey = a.int === null ? a : b;
  if (NUMERIC_STRING.test(stringKey.raw)) {
    return compareNumeric(a.raw, b.raw);
  }
  return Buffer.compare(a.bytes, b.bytes);
}

/**
 * @param {string} a
 * @param {string} b
 */
function compareNumeric(a, b) {
  const bigA = toInt64(a);
  const bigB = toInt64(b);
  if (bigA !== null && bigB !== null) {
    return bigA < bigB ? -1 : bigA > bigB ? 1 : 0;
  }
  const numA = Number(a);
  const numB = Number(b);
  return numA < numB ? -1 : numA > numB ? 1 : 0;
}

/** @param {string} text */
function toInt64(text) {
  if (!INTEGER_STRING.test(text)) return null;
  const int = BigInt(text.trim().replace(/^\+/, ""));
  return int >= INT64_MIN && int <= INT64_MAX ? int : null;
}

/**
 * Recursively key-sort a value: plain object → new object with keys sorted
 * ascending, array → order preserved, scalar → unchanged.
 *
 * This is NOT the hash input — a JavaScript object cannot hold keys in
 * `ksort()` order, and `JSON.stringify` does not match the platform's number
 * and string encoding. Hash with {@link encodeCanonical}.
 *
 * The accumulator is `Object.create(null)` so a literal `__proto__` key
 * becomes an own property instead of mutating `Object.prototype`.
 *
 * @param {unknown} value
 * @returns {unknown}
 */
export function canonicalizeForHash(value) {
  if (Array.isArray(value)) {
    return value.map(canonicalizeForHash);
  }
  if (value && typeof value === "object") {
    /** @type {Record<string, unknown>} */
    const sorted = Object.create(null);
    for (const key of Object.keys(value).sort()) {
      sorted[key] = canonicalizeForHash(/** @type {Record<string, unknown>} */ (value)[key]);
    }
    return sorted;
  }
  return value;
}
