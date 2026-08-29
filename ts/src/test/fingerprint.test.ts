import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";

import { computeFingerprint, computePayeeFingerprint, FINGERPRINT_VERSION, type PaymentOption } from "../fingerprint.js";
import { repoRootFromImportMetaUrl } from "./repoRoot.js";

// Cross-language contract test (spec v1, C1 + C4 rule 4b): replays every
// public vector in spec/testdata/fingerprint_vectors.json through this SDK's
// implementation. A mismatch here means the Go and TS implementations would
// compute different fingerprints for the same x402 payment options, which
// would make verify() unusable (a wallet fingerprinting locally with this
// SDK could never match what the API observed).

interface RawVectorOption {
  scheme: string;
  network: string;
  asset: string;
  amount: string;
  pay_to: string;
  max_timeout_seconds?: number;
}

interface RawVector {
  name: string;
  notes: string;
  options: RawVectorOption[];
  ok: boolean;
  set_fingerprint?: string;
  option_fingerprints: string[];
  payee_fingerprints: string[];
  payee_set_fingerprint?: string;
  fingerprint_version?: number;
}

interface VectorFile {
  algorithm: string;
  description: string;
  vectors: RawVector[];
}

function loadVectors(): VectorFile {
  const repoRoot = repoRootFromImportMetaUrl(import.meta.url);
  const path = join(repoRoot, "spec", "testdata", "fingerprint_vectors.json");
  return JSON.parse(readFileSync(path, "utf8")) as VectorFile;
}

function toPaymentOptions(raw: RawVectorOption[]): PaymentOption[] {
  return raw.map((option) => ({
    scheme: option.scheme,
    network: option.network,
    asset: option.asset,
    amount: option.amount,
    payTo: option.pay_to,
    maxTimeoutSeconds: option.max_timeout_seconds,
  }));
}

const vectors = loadVectors();

test("fingerprint_vectors.json has at least 8 vectors (C1 requirement)", () => {
  assert.ok(vectors.vectors.length >= 8);
});

for (const vector of vectors.vectors) {
  test(`computeFingerprint: ${vector.name}`, async () => {
    const options = toPaymentOptions(vector.options);
    const result = await computeFingerprint(options);
    if (!vector.ok) {
      assert.equal(result, null, `vector ${vector.name} expects ok=false`);
      return;
    }
    assert.ok(result, `vector ${vector.name} expects ok=true`);
    assert.equal(result.version, vector.fingerprint_version ?? FINGERPRINT_VERSION);
    assert.equal(result.setFingerprint.length, 64);
    assert.equal(result.setFingerprint, vector.set_fingerprint, `set_fingerprint mismatch for ${vector.name}`);
    assert.deepEqual(result.optionFingerprints, vector.option_fingerprints, `option_fingerprints mismatch for ${vector.name}`);
  });

  test(`computePayeeFingerprint: ${vector.name}`, async () => {
    const options = toPaymentOptions(vector.options);
    const result = await computePayeeFingerprint(options);
    if (!vector.ok) {
      assert.equal(result, null, `vector ${vector.name} expects ok=false`);
      return;
    }
    assert.ok(result, `vector ${vector.name} expects ok=true`);
    assert.equal(result.version, vector.fingerprint_version ?? FINGERPRINT_VERSION);
    assert.equal(result.payeeSetFingerprint.length, 64);
    assert.equal(
      result.payeeSetFingerprint,
      vector.payee_set_fingerprint,
      `payee_set_fingerprint mismatch for ${vector.name}`,
    );
    assert.deepEqual(result.payeeFingerprints, vector.payee_fingerprints, `payee_fingerprints mismatch for ${vector.name}`);
  });
}

function findVector(name: string): RawVector {
  const vector = vectors.vectors.find((v) => v.name === name);
  assert.ok(vector, `vector ${name} not found in testdata`);
  return vector;
}

test("relationship: case/whitespace variant of a hex-addressed option fingerprints identically", () => {
  const basic = findVector("single_option_basic");
  const variant = findVector("single_option_case_and_whitespace_insensitive");
  assert.equal(basic.set_fingerprint, variant.set_fingerprint);
});

test("relationship: base58 address is case-sensitive for both fingerprint and payee fingerprint", () => {
  const original = findVector("base58_pay_to_case_sensitive");
  const lowered = findVector("base58_pay_to_case_changed_differs");
  assert.notEqual(original.set_fingerprint, lowered.set_fingerprint);
  assert.notEqual(original.payee_set_fingerprint, lowered.payee_set_fingerprint);
});

test("relationship: two options that differ only in amount share a payee fingerprint", () => {
  const basic = findVector("single_option_basic");
  const amountA = findVector("payee_fingerprint_shared_across_amount_a");
  const amountB = findVector("payee_fingerprint_shared_across_amount_b");
  assert.notEqual(basic.set_fingerprint, amountA.set_fingerprint, "amount differs, so the ordinary fingerprint must differ");
  assert.notEqual(amountA.set_fingerprint, amountB.set_fingerprint);
  assert.equal(basic.payee_set_fingerprint, amountA.payee_set_fingerprint, "payee fingerprint excludes amount");
  assert.equal(basic.payee_set_fingerprint, amountB.payee_set_fingerprint, "payee fingerprint excludes amount");
});

test("relationship: max_timeout_seconds is excluded from both fingerprint and payee fingerprint", () => {
  const t60 = findVector("max_timeout_seconds_excluded_60");
  const t600 = findVector("max_timeout_seconds_excluded_600");
  assert.equal(t60.set_fingerprint, t600.set_fingerprint);
  assert.equal(t60.payee_set_fingerprint, t600.payee_set_fingerprint);
});

test("relationship: an option fingerprint never equals its own payee fingerprint", async () => {
  const basic = findVector("single_option_basic");
  const options = toPaymentOptions(basic.options);
  const fingerprint = await computeFingerprint(options);
  const payeeFingerprint = await computePayeeFingerprint(options);
  assert.ok(fingerprint && payeeFingerprint);
  assert.notEqual(fingerprint.optionFingerprints[0], payeeFingerprint.payeeFingerprints[0]);
  assert.notEqual(fingerprint.setFingerprint, payeeFingerprint.payeeSetFingerprint);
});

test("computeFingerprint returns null for an empty option set", async () => {
  assert.equal(await computeFingerprint([]), null);
  assert.equal(await computePayeeFingerprint([]), null);
});

test("manual SHA-256 cross-check matches the public hand-verified vector", async () => {
  const option: PaymentOption = {
    scheme: "exact",
    network: "eip155:8453",
    asset: "0xab12cd34ab12cd34ab12cd34ab12cd34ab12cd34",
    payTo: "0xef56ab78ef56ab78ef56ab78ef56ab78ef56ab78",
    amount: "1000000",
    maxTimeoutSeconds: 60,
  };
  const fingerprint = await computeFingerprint([option]);
  assert.ok(fingerprint);
  assert.equal(fingerprint.optionFingerprints[0], "368387837e4883346a4479ec48d19718b432b70f7185c77b4a2150a07d61c768");
  assert.equal(fingerprint.setFingerprint, "91639af6f1dc968c3506c117712fc7830368e7cad3e2dd7cebe209cbb4f229ea");
});
