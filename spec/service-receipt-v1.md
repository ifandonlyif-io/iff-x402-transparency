# IFF Service Receipt v1

Status: implementation specification, 2026-09-01
License: MIT

## 1. Purpose and boundary

Service Receipt v1 is a portable, provider-neutral way for a service to bind
an exact JSON result to an issuer identity, a semantic request digest, a time
window, and optional evidence references. A receipt can be verified offline
with Ed25519, SHA-256, base64url, and JSON implementations from a language's
standard library.

The receipt proves only that the holder of the receipt private key signed the
payload bytes. It is not, by itself:

- proof that the embedded public key belongs to the named issuer;
- proof of correct, safe, private, or trusted execution;
- remote attestation, a TEE claim, or an AI reasoning proof;
- proof that a referenced Merkle path, STH, chain anchor, or compute artifact
  has been independently verified;
- authorization to pay, lend, publish a review, or execute a contract action.

Issuer trust, evidence verification, compute-proof verification, freshness,
and application policy are independent decisions and MUST be reported
separately. A verifier MUST NOT collapse them into one trust score or a single
ambiguous "verified" state.

## 2. Encoding

An envelope is JSON with these fields:

```json
{
  "schema": "https://ifandonlyif.io/schemas/service-receipt-v1.json",
  "payload": "BASE64URL_NO_PADDING",
  "payload_sha256": "64_LOWERCASE_HEX",
  "signature": {
    "algorithm": "Ed25519",
    "key_id": "sha256:64_LOWERCASE_HEX",
    "public_key": "BASE64URL_NO_PADDING_32_BYTES",
    "value": "BASE64URL_NO_PADDING_64_BYTES"
  }
}
```

`payload` decodes to the canonical fixed-order JSON below. Every field is
present. Optional values are JSON `null`, not omitted.

```json
{
  "schema": "https://ifandonlyif.io/schemas/service-receipt-v1.json",
  "receipt_id": "sr1_BASE64URL_OF_18_RANDOM_BYTES",
  "issuer": "https://issuer.example",
  "service": "service-name",
  "issued_at": "2026-09-01T03:04:05.000000Z",
  "expires_at": "2026-09-01T03:09:05.000000Z",
  "nonce": null,
  "request_sha256": "64_LOWERCASE_HEX",
  "subject_media_type": "application/json",
  "subject_sha256": "64_LOWERCASE_HEX",
  "subject": "BASE64URL_NO_PADDING_OF_JSON_OBJECT",
  "evidence": null,
  "compute_proof": null
}
```

Canonical payload JSON is the UTF-8 output of the field order above with no
insignificant whitespace. Every non-subject string is restricted to printable
ASCII without backslash, quote, `<`, `>`, or `&`; identifiers use their
narrower grammars below. The subject is separately base64url encoded. This
removes language-specific HTML/Unicode escaping differences. V1 contains no
maps or floating-point fields. A verifier MUST strict-decode the payload,
reject unknown or duplicate fields, re-encode the fixed structure, and require
byte-for-byte equality with the decoded payload.

The envelope itself MAY contain insignificant JSON whitespace and fields in a
different order. Unknown or duplicate envelope fields are rejected.

Limits:

- envelope JSON: 256 KiB;
- decoded payload: 192 KiB;
- decoded subject: 128 KiB;
- JSON nesting: at most 128 object/array containers;
- nonce: 1-128 ASCII letters, digits, `-`, `_`, `.`, or `:`.

## 3. Hashes, identity, and signature

All concatenation below is byte concatenation. Literal strings are UTF-8.

```text
request_sha256 = SHA-256("iff-service-receipt/request/v1\n" || request_projection)
subject_sha256 = SHA-256("iff-service-receipt/subject/v1\n" || subject_bytes)
payload_sha256 = SHA-256(canonical_payload_bytes)
key_id         = "sha256:" || lowercase_hex(SHA-256(raw_public_key))
signing_digest = SHA-256("iff-service-receipt/v1\n" || canonical_payload_bytes)
signature      = Ed25519.Sign(private_key, signing_digest)
```

`subject` contains the exact service-defined receipt-excluded result bytes,
not the outer HTTP response body. The bytes themselves are committed and do
not need a cross-language canonicalization rule. For IFF's
`/api/v3/verify` adapter they are
`encoding/json.Marshal(VerifyResponse)` before `service_receipt` is attached.
They contain normalized fingerprints and evidence, not the caller's plaintext
payment requirements.

The request projection is defined by each service adapter. IFF's
`x402-requirement-verification` adapter uses this fixed-order JSON:

```json
{"url":"NORMALIZED_PUBLIC_HTTPS_URL","received":{"set_fingerprint":"...","option_fingerprints":["..."]}}
```

## 4. Verification algorithm

A base verifier performs these steps in order:

1. Enforce the envelope size and strict JSON rules.
2. Require the exact v1 schema and `Ed25519` algorithm.
3. Decode `payload`, public key, and signature with unpadded base64url and
   enforce their byte lengths.
4. Recompute and compare `payload_sha256`.
5. Recompute `key_id` from the raw public key.
6. Recompute `signing_digest` and verify the Ed25519 signature.
7. Strict-decode the canonical payload, reject duplicate/unknown fields,
   re-encode it, and require exact payload-byte equality.
8. Validate issuer, service, timestamps, nonce, digest formats, subject JSON,
   subject hash, and any descriptor syntax.
9. Evaluate issuer policy, time state, evidence state, compute-proof state,
   and outer-subject matching as separate results.

Cryptographic verification failure invalidates the receipt. Expiry does not
erase a historical signature: it means the receipt is outside its action
window. With clock skew `s`, the eligible interval is
`[issued_at - s, expires_at + s)`. `s` is non-negative; implementations
receiving a negative skew option treat it as zero.

## 5. Issuer trust and key rotation

The public key embedded in a receipt proves only self-consistency. It MUST NOT
make `issuer_trusted` true by itself.

Pinned trust requires both:

- exact equality between the signed `issuer` and the verifier's expected
  issuer origin; and
- an exact full `key_id` match against the verifier's independently supplied
  allowlist.

IFF also publishes `/api/v3/receipts/keys` over its HTTPS origin. A match to
that directory is origin-recognized trust through WebPKI, not an independent
pin. Verifier UIs SHOULD label it `known`, reserving `trusted` for a caller pin.

During rotation the issuer publishes the new current key and retains old
public keys as `previous` for at least the longest receipt lifetime plus all
key-directory cache lifetimes. IFF configures these through
`SERVICE_RECEIPT_PREVIOUS_PUBLIC_KEYS`; no previous private key is required.

The mutable key directory is discovery, not append-only historical key
transparency. Old receipts remain cryptographically verifiable from their
embedded keys, but retroactive historical issuer trust requires a
contemporaneous/manual pin or an archived signed key history.

## 6. Outer response binding

When an envelope is embedded as `service_receipt` in a larger response, the
signed subject is authoritative. A verifier removes the outer
`service_receipt`, compares the remaining JSON value with the decoded signed
subject, and reports `subject_matches_outer` separately.

A valid signature paired with a modified outer verdict is a valid receipt
inside a substituted outer response. The verifier MUST show the signed subject
and MUST NOT describe the modified outer verdict as signed.

## 7. Evidence and compute-proof descriptors

`evidence`, when present, is:

```json
{
  "observation_id": "UUID",
  "report_hash": "64_LOWERCASE_HEX",
  "leaf_hash": "64_LOWERCASE_HEX",
  "log_id": "32_LOWERCASE_HEX",
  "log_index": "CANONICAL_DECIMAL_STRING",
  "tree_size": "CANONICAL_DECIMAL_STRING",
  "sth_root_hash": "64_LOWERCASE_HEX",
  "sth_sha256_hash": "64_LOWERCASE_HEX"
}
```

V1 checks that `leaf_hash = SHA-256(0x00 || bytes(report_hash))` and checks
descriptor syntax. The base verifier still reports `referenced_unverified`:
it does not validate the STH signature, audit path, root, log-key history, or
chain anchor. A service-specific transparency-log adapter performs those
checks.

`compute_proof`, when present, is:

```json
{
  "type": "provider-proof-type",
  "provider": "provider-name",
  "artifact_sha256": "64_LOWERCASE_HEX",
  "artifact_uri": "https://...",
  "verifier": "adapter-name-and-version"
}
```

The base verifier reports `descriptor_signed_unverified`. It does not fetch
the artifact or validate a proof system. A 0G, TEE, ZK, or other adapter may
later validate the descriptor, artifact, public inputs, and provider identity;
until it does, the receipt makes no attestation claim.

An empty `artifact_uri` means the artifact is supplied out of band. A nonempty
value is safe printable ASCII and an HTTPS URL.

For IFF transparency-log evidence, an adapter reconstructs the canonical STH
body with its timestamp in UTC and exactly six fractional digits before
checking the STH SHA-256 digest and Ed25519 signature; generic JSON timestamp
serialization is not necessarily identical to the signed STH body.

## 8. IFF API adapter

`POST /api/v3/verify` remains backward-compatible. A caller opts into v1 with:

```json
"receipt": {"version":"1","nonce":"optional_caller_nonce"}
```

`{}` selects v1 with no nonce. Omission or JSON `null` requests no receipt.
The response adds `service_receipt`; all existing fields are unchanged.
Malformed JSON, wrong option types, duplicate fields, or unknown receipt
options return `400`; a syntactically valid unsupported version or nonce
returns `422`. If issuance is disabled, an
opt-in request fails closed with `503` before endpoint lookup or discovery
work.

Nonce and `receipt_id` do not prevent replay on their own. A consumer that
needs one-time action semantics compares its expected nonce, enforces the
half-open action window, and records consumed receipt IDs in its own state.

The receipt feature adds no database row and does not put receipts in public
cards, manifests, or the transparency log. The existing `/verify` behavior is
unchanged: an unobserved URL may still nominate only its normalized URL for
discovery when discovery is enabled.

IFF uses an API-only `SERVICE_RECEIPT_SIGNING_KEY`. It is independent from
monitor-report, log-STH, webhook, JWT, and anchor keys. Receipt signatures are
provenance/tamper evidence, never monitor signatures or attestations.

## 9. Reference implementation and vectors

- Go package: `go/receipt/` (standard library only)
- Offline command: `(cd go && go run ./cmd/iff-receipt-verify)`
- Browser verifier core: `browser/service-receipt.mjs` (no DOM dependency)
- JSON Schemas: `schemas/service-receipt-v1.json` and
  `schemas/service-receipt-key-directory-v1.json`
- Baseline known-answer vectors: `spec/testdata/service_receipt_v1.json`

The receipt package, this specification, schemas, verifier core, and vectors
are the trust-critical slice published in this MIT-licensed repository.
Production queue topology, private keys, owner/auth state, deployment
configuration, API server implementation, and hosted UI remain outside this
public slice because none is required to independently verify a receipt.
