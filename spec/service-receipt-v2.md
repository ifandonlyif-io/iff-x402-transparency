# IFF Service Receipt v2

Status: implementation specification, 2026-10-10
License: MIT

Service Receipt v2 is [Service Receipt v1](service-receipt-v1.md) with an
ML-DSA-65 signature in place of Ed25519. Every v1 rule that this document does
not restate applies unchanged. That includes the purpose and boundary (§1),
payload fields, request and subject hashing, verification order, trust
evaluation, outer-response binding and descriptors.

A v1 receipt is never read under v2 rules, and a v2 receipt is never read
under v1 rules.

## 1. What changes from v1

1. **Schema.** The envelope `schema` and the payload `schema` are both
   `https://ifandonlyif.io/schemas/service-receipt-v2.json`.
2. **Algorithm.** `signature.algorithm` is exactly `ML-DSA-65`. The algorithm
   is pure ML-DSA-65 with an empty context, as in
   [signature profile v2](x402-signatures-ml-dsa-65.md) §2.
3. **Key and signature encoding.** Both use unpadded base64url, as in v1:
   - `public_key`: 1952 raw bytes, 2603 characters;
   - `value`: 3309 raw bytes, 4412 characters.
4. **Signed message.** For the canonical payload bytes `P`:

   ```text
   payload_sha256 = SHA-256(P)                                (as in v1)
   key_id         = "sha256:" || lowercase_hex(SHA-256(raw_public_key))
   M              = "iff-service-receipt/v2\n" || SHA-256(P)
   value          = ML-DSA-65.Sign(private_key, M, ctx = "")
   ```

   In v1, Ed25519 signs a 32-byte digest of the domain and payload. In v2,
   ML-DSA-65 signs the domain line followed by the payload digest. That is
   the same message construction as signature profile v2 §2.
5. **Unchanged hash domains.** The request and subject digests keep their v1
   domain strings, `iff-service-receipt/request/v1\n` and
   `iff-service-receipt/subject/v1\n`. They are hash inputs, not signature
   domains, and SHA-256 needs no post-quantum change.
6. **Verification.** Step 2 of v1 §4 requires the exact v2 schema and the
   `ML-DSA-65` algorithm. Step 6 verifies ML-DSA-65 over `M`. All other steps
   are unchanged.

## 2. Key directory v2

`GET /api/v3/receipts/keys` returns the schema
`https://ifandonlyif.io/schemas/service-receipt-key-directory-v2.json`. The
directory has the same shape as v1, with two differences:

- `algorithm` is `Ed25519` or `ML-DSA-65`;
- `public_key` decodes to 32 bytes for `Ed25519` and to 1952 bytes for
  `ML-DSA-65`.

A directory entry recognizes a receipt only if all of these hold:

- its `key_id`, `algorithm` and `public_key` all equal the receipt's;
- its `status` is `current` or `previous`.

After the switch, the hosted issuer lists two keys:

- its ML-DSA-65 key as `current`;
- its former Ed25519 key as `previous`.

The `previous` entry is kept for at least the longest v1 receipt lifetime plus
cache lifetimes. Pinned trust (v1 §5) still requires the caller's own exact
`key_id` pin.

## 3. IFF API adapter

`POST /api/v3/verify` accepts these receipt requests:

| Request | Result |
|---|---|
| `"receipt": {"version":"2"}` | A v2 receipt. |
| `"receipt": {}` | A v2 receipt. |
| `"receipt": {"version":"1"}` | `422`. The service no longer issues Ed25519 receipts. |

All other v1 §8 rules are unchanged: the request options, the error codes,
and fail-closed `503` when issuance is disabled. A v1 receipt issued earlier
still verifies offline with a v1 verifier.

The hosted issuer key is the API-only `SERVICE_RECEIPT_MLDSA65_SIGNING_KEY`.
Its value is the 32-byte ML-DSA-65 seed, written as canonical unpadded
base64url (43 characters). The seed is independent from the monitor-report,
log, webhook, JWT, anchor and Apostille keys.

## 4. Reference implementation and vectors

- **Go package:** `go/receipt/`. It verifies both v1 and v2 and uses only the
  standard library (`crypto/mldsa`, Go 1.27 or later).
- **Browser verifier core:** `browser/service-receipt.mjs`. For v2 it uses the
  vendored `@noble/post-quantum` 0.7.1 ML-DSA-65. That library has not been
  independently audited; verification handles only public data.
- **JSON Schemas:**
  - `schemas/service-receipt-v2.json`;
  - `schemas/service-receipt-key-directory-v2.json`.
- **Known-answer vectors:** `spec/testdata/service_receipt_v2.json`. It has the
  same structure as the v1 file and uses a public test seed with deterministic
  signing. Negative cases also cover:
  - a v1 schema with an ML-DSA-65 signature;
  - a v2 schema with an Ed25519 key or signature;
  - a v1 signing digest signed with ML-DSA-65;
  - a key or signature one byte short;
  - a directory entry whose algorithm disagrees with the receipt.
