# x402 transparency signatures: ML-DSA-65 (signature profile v2)

Status: normative, 2026-10-10
License: MIT

This document replaces the Ed25519 signatures of the
[x402 Requirement Transparency v1](x402-requirement-transparency-v1.md)
observation report (§3) and signed tree head (§5) with ML-DSA-65 signatures.
It also defines the signature rules that
[Service Receipt v2](service-receipt-v2.md) uses.

The Ed25519 signatures defined in v1 are **signature profile v1**. The
signatures defined here are **signature profile v2**. Everything else in v1 is
unchanged:

- canonical report and tree-head bytes;
- `report_hash`, leaf and node hashing, and tree shape;
- proofs;
- Keccak-256 anchoring;
- API paths.

Signatures already made under profile v1 stay valid profile v1 signatures.
Nothing is re-signed, and the transparency log keeps one tree.

## 1. Why

ML-DSA-65 (FIPS 204) is a post-quantum signature scheme. Profile v1 Ed25519
signatures can be forged by an attacker with a cryptographically relevant
quantum computer, and an STH signature is meant to be checked long after it is
made. SHA-256 and Keccak-256 commitments are not changed: the best known
quantum attack on them (Grover) leaves 128-bit preimage security.

Moving to profile v2 does not change any v1 non-goal. A signature proves only
that the holder of the key signed the bytes. It is provenance and tamper
evidence, not attestation, payment safety, or a trust score.

## 2. The ML-DSA-65 primitive

Every profile v2 signature uses the same primitive:

- **Algorithm:** ML-DSA-65 from FIPS 204, in its pure form. HashML-DSA is
  not used.
- **Context:** the context string is empty. The FIPS 204 message
  representative is therefore `0x00 || 0x00 || M`, where `M` is the signed
  message.
- **Signing:** production signatures use hedged (randomized) signing.
  Deterministic signing (`rnd` = 32 zero bytes) is used only to make the
  published test vectors reproducible. A verifier must not depend on which
  mode was used.
- **Sizes:**
  - Public key: exactly 1952 bytes.
  - Signature: exactly 3309 bytes.
  - Private key: a 32-byte seed `ξ` (FIPS 204 `ML-DSA.KeyGen_internal`).
    It is never published, except for the test seeds in §8.
- **Signed message:** each artifact defines its own `M` as a UTF-8 domain line
  followed by the raw 32-byte SHA-256 digest of the artifact's canonical bytes.
  Using a separate domain line for each artifact means a signature made for one
  artifact type is never valid for another.

The three domain lines are:

| Artifact | Domain line (UTF-8, ends with one LF) |
|---|---|
| Observation report | `iff-x402-monitor-report/v2\n` |
| Signed tree head | `iff-x402-tree-head/v2\n` |
| Service Receipt v2 | `iff-service-receipt/v2\n` |

## 3. Selecting the algorithm

Observation reports and STHs carry no algorithm field inside their signed
bytes. A verifier selects the algorithm only from the exact decoded length of
the public key:

| Decoded public key | Profile | Required decoded signature length |
|---|---|---|
| 32 bytes | v1, Ed25519 (v1 §3, §5.2) | 64 bytes |
| 1952 bytes | v2, ML-DSA-65 (this document) | 3309 bytes |
| any other length | none | reject |

There is no fallback. A 1952-byte key is never tried as Ed25519, and a 32-byte
key is never tried as ML-DSA-65.

API responses also carry an informational algorithm name: `"Ed25519"` or
`"ML-DSA-65"`. It appears as `monitor_signature_algorithm` on reports,
`signature_algorithm` on STHs, and `algorithm` on key epochs. A verifier
derives the algorithm from the key length. If the informational field is
present and names a different algorithm, the verifier rejects the response.

## 4. Observation report signature (profile v2)

The canonical report JSON and `report_hash` are exactly as in v1 §3. Only one
field value changes size. `monitor_public_key` is the standard, padded base64
encoding of the raw 1952-byte ML-DSA-65 public key, which is 2604 characters.

```text
digest            = SHA-256(canonical_report_json)
report_hash       = lowercase_hex(digest)
M                 = "iff-x402-monitor-report/v2\n" || digest
monitor_signature = base64(ML-DSA-65.Sign(monitor_private_key, M, ctx = ""))
```

`monitor_signature` uses standard, padded base64. The 3309-byte signature
encodes to 4412 characters.

To check a report, a verifier:

1. recomputes `canonical_report_json` from the report's fields;
2. requires its SHA-256 digest to equal `report_hash`;
3. selects the algorithm from the key length (§3);
4. verifies `ML-DSA-65.Verify(monitor_public_key, M, monitor_signature, ctx = "")`.

A report without a monitor key is unsigned under both profiles.

## 5. Signed tree head (profile v2)

The canonical bytes are exactly as in v1 §5.1. The signature and the log
identity become:

```text
sth_sha256    = SHA-256(canonical_bytes)
sth_keccak256 = Keccak-256(canonical_bytes)          (unchanged, not signed)
M             = "iff-x402-tree-head/v2\n" || sth_sha256
signature     = base64(ML-DSA-65.Sign(log_private_key, M, ctx = ""))
log_id        = lowercase_hex(SHA-256(raw_public_key)[0:16])
```

`raw_public_key` is the 1952-byte ML-DSA-65 key, so `log_id` is still 32
lowercase hex characters. `public_key` and `signature` in the API use
standard, padded base64, as in v1.

To check an STH under either profile, a verifier:

1. rebuilds the canonical bytes. Timestamps are reformatted to exactly six
   fractional digits, as in v1 §10.1.
2. requires `sha256_hash`, when present, to equal `hex(sth_sha256)`.
3. requires `log_id` to equal the value derived from `public_key`. This check
   is new and also applies to profile v1. Every profile v1 STH the reference
   log has published already satisfies it.
4. selects the algorithm from the key length (§3) and verifies the signature.
5. still applies v1 §5.3: the expected `log_id` and full key fingerprint come
   from a source that is independent of the response being checked.

## 6. Key transition

A log or monitor that moves from profile v1 to profile v2 does so by rotating
keys. This is the existing v1 §7 mechanism. No format changes are needed.

**The log key.**

- The first STH signed by the ML-DSA-65 key starts a new log-key epoch. That
  epoch has a new `log_id`.
- The tree does not restart. A consistency proof (v1 §6.2) from any profile v1
  STH to any later profile v2 STH links the two epochs. A verifier that holds a
  profile v1 checkpoint can confirm that the profile v2 log extends it.
- After the switch, the log signs only with ML-DSA-65. Profile v1 STHs stay in
  the history and remain verifiable with Ed25519.
- §5.3's trust rule applies to the new key as well. The reference log publishes
  its profile v2 key fingerprint in this repository's
  `spec/verify_example.py` (`PRODUCTION_TRUSTED_LOG_KEYS`) and in `keys/`.
  Those reviewed copies are the independent source. `GET /api/v3/log/keys` is
  not.

**Monitor keys.** A monitor's ML-DSA-65 key appears in
`GET /api/v3/log/keys` `monitor_keys` as a new `(monitor_id, public_key)` pair.
Old reports keep their Ed25519 keys and signatures.

**Key epoch entries.** Entries in `log_keys` and `monitor_keys` gain an
informational `algorithm` field (§3). All other fields and derivation rules are
as in v1 §7.

**Key separation.** An operator must never use the same seed for two roles.
The roles are monitor reports, the log, and Service Receipts. Seeds must also
not be shared with any other system key.

## 7. Size and storage notes (informative)

The extra data per signed report is about 2.6 KB of public key and 4.4 KB of
signature, both base64. The extra data per STH is the same.

The reference deployment sequences about 2,000 reports a day and publishes at
most one STH an hour. That is roughly 14 MB a day of added row data before
compression. Each STH and report still names its full key, so verification
needs no key lookup.

## 8. Test vectors

`spec/testdata/signature_vectors_v2.json` holds the known-answer vectors for
this profile:

- one profile v2 observation report and one profile v2 STH. The STH commits to
  the same `tree_size=8` tree as `log_vectors.json`.
- each vector gives its public test seed (`test_private_key_seed_base64url`,
  never a production key), public key, canonical bytes, digest, the exact
  signed message `M` in hex, and a signature made with deterministic signing.
- negative cases that a verifier must reject:
  - a wrong domain line;
  - a profile v1 domain-less message signed with ML-DSA-65;
  - a flipped signature byte;
  - a modified canonical field;
  - a 1951-byte key;
  - a 3308-byte signature;
  - an Ed25519 signature paired with an ML-DSA-65 key;
  - a `log_id` that does not match the key;
  - an informational algorithm name that disagrees with the key.

The IFF reference implementation generates the file and re-verifies it in its
test suite. This repository verifies it independently in Go, in Python
(`spec/verify_example.py --self-test`, standard library only, including a
from-scratch ML-DSA-65 verifier), and in the browser verifier.
