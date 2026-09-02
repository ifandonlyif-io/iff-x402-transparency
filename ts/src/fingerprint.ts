// Every normalization rule and hash domain here is tested against the same
// conformance vectors as IFF's production evidence service.
//
// SHA-256 is computed via WebCrypto (globalThis.crypto.subtle), available
// without any package dependency in supported Node >=22 releases and in every
// browser. That is the only reason these functions are async: Go's
// ComputeFingerprint is synchronous, but crypto.subtle.digest always returns
// a Promise.

/** The x402 v2 payment option shape this SDK fingerprints. Field names are
 * idiomatic camelCase (matching the x402 wire format's `payTo`/
 * `maxTimeoutSeconds`). The canonical JSON mapping is an implementation
 * detail of canonicalOptionJson/canonicalPayeeJson below. */
export interface PaymentOption {
  scheme: string;
  network: string;
  asset: string;
  amount: string;
  payTo: string;
  maxTimeoutSeconds?: number;
}

/** Canonical IFF fingerprint format version. */
export const FINGERPRINT_VERSION = 1;

const OPTION_FINGERPRINT_DOMAIN = "iff-x402-option/v1\n";
const SET_FINGERPRINT_DOMAIN = "iff-x402-set/v1\n";
// C4 rule 4b's payee-fingerprint option-level domain. The set-level hash
// deliberately reuses SET_FINGERPRINT_DOMAIN unchanged -- see
// computePayeeFingerprint's doc comment for why that is still safe.
const PAYEE_FINGERPRINT_DOMAIN = "iff-x402-payee/v1\n";

// Only a literal lowercase "0x" prefix followed by 40 hex digits is
// case-folded (real EIP-55 checksum addresses always keep a lowercase "0x"
// prefix); anything else, including a base58 address, passes through
// trimmed but otherwise unchanged.
const EVM_ADDRESS_PATTERN = /^0x[0-9a-fA-F]{40}$/;

export interface Fingerprint {
  version: number;
  setFingerprint: string;
  optionFingerprints: string[];
}

export interface PayeeFingerprint {
  version: number;
  payeeSetFingerprint: string;
  payeeFingerprints: string[];
}

/** Implements C1's asset/pay_to normalization rule. */
function normalizeAddressLikeField(value: string): string {
  const trimmed = value.trim();
  return EVM_ADDRESS_PATTERN.test(trimmed) ? trimmed.toLowerCase() : trimmed;
}

/** Implements C1's amount normalization rule: trim, then strip leading
 * zeros only when the trimmed value is purely ASCII decimal digits. */
function normalizeAmount(value: string): string {
  const trimmed = value.trim();
  if (trimmed === "") {
    return trimmed;
  }
  if (!/^[0-9]+$/.test(trimmed)) {
    return trimmed;
  }
  const stripped = trimmed.replace(/^0+/, "");
  return stripped === "" ? "0" : stripped;
}

/** The canonical, fixed-key-order option shape. JS object literals preserve
 * string-key insertion order, and JSON.stringify does not HTML-escape
 * '<'/'>'/'&', so both contract properties require no extra configuration. */
function canonicalOptionJson(option: PaymentOption): string {
  return JSON.stringify({
    scheme: option.scheme.trim().toLowerCase(),
    network: option.network.trim().toLowerCase(),
    asset: normalizeAddressLikeField(option.asset),
    pay_to: normalizeAddressLikeField(option.payTo),
    amount: normalizeAmount(option.amount),
  });
}

/** canonicalOptionJson without amount -- C4 rule 4b's payee identity. */
function canonicalPayeeJson(option: PaymentOption): string {
  return JSON.stringify({
    scheme: option.scheme.trim().toLowerCase(),
    network: option.network.trim().toLowerCase(),
    asset: normalizeAddressLikeField(option.asset),
    pay_to: normalizeAddressLikeField(option.payTo),
  });
}

async function sha256Hex(message: string): Promise<string> {
  const bytes = new TextEncoder().encode(message);
  const digest = await globalThis.crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

/** Hashes the domain and payload as one byte sequence. */
async function domainSeparatedHash(domain: string, payload: string): Promise<string> {
  return sha256Hex(domain + payload);
}

/** Sorts and deduplicates already-computed per-option fingerprints. */
function dedupeAndSort(fingerprints: string[]): string[] {
  return Array.from(new Set(fingerprints)).sort();
}

/**
 * Derives the canonical requirement fingerprint for a set of x402 payment
 * options. The maxTimeoutSeconds transport field is deliberately excluded
 * from the hashed shape.
 *
 * Returns null when the set has no fingerprintable option (an empty
 * array).
 */
export async function computeFingerprint(options: PaymentOption[]): Promise<Fingerprint | null> {
  if (options.length === 0) {
    return null;
  }
  const optionFingerprints: string[] = [];
  for (const option of options) {
    optionFingerprints.push(await domainSeparatedHash(OPTION_FINGERPRINT_DOMAIN, canonicalOptionJson(option)));
  }
  const sorted = dedupeAndSort(optionFingerprints);
  const setFingerprint = await domainSeparatedHash(SET_FINGERPRINT_DOMAIN, sorted.join("\n"));
  return { version: FINGERPRINT_VERSION, setFingerprint, optionFingerprints: sorted };
}

/**
 * Derives an amount-blind payee fingerprint: the same options as
 * computeFingerprint, hashed without the amount field, so two option sets
 * that differ only in price share the same payeeSetFingerprint.
 *
 * The set-level hash reuses SET_FINGERPRINT_DOMAIN unchanged: it only needs
 * to separate a set-level hash from an option-level hash, which the
 * differing option-level domains (OPTION_FINGERPRINT_DOMAIN vs
 * PAYEE_FINGERPRINT_DOMAIN) already guarantee -- so a payeeSetFingerprint
 * can never collide with an ordinary setFingerprint for the same options.
 *
 * Returns null when the set has no fingerprintable option, mirroring
 * computeFingerprint.
 */
export async function computePayeeFingerprint(options: PaymentOption[]): Promise<PayeeFingerprint | null> {
  if (options.length === 0) {
    return null;
  }
  const payeeFingerprints: string[] = [];
  for (const option of options) {
    payeeFingerprints.push(await domainSeparatedHash(PAYEE_FINGERPRINT_DOMAIN, canonicalPayeeJson(option)));
  }
  const sorted = dedupeAndSort(payeeFingerprints);
  const payeeSetFingerprint = await domainSeparatedHash(SET_FINGERPRINT_DOMAIN, sorted.join("\n"));
  return { version: FINGERPRINT_VERSION, payeeSetFingerprint, payeeFingerprints: sorted };
}
