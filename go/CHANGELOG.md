# Changelog

All notable changes to `github.com/ifandonlyif-io/iff-x402-transparency/go`
are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning
follows [SemVer](https://semver.org/).

Releases are tags `go/vX.Y.Z` on this repository.

## [0.3.0] - 2026-10-10

### Added

- `receipt` package: verifies IFF Service Receipt v1 (Ed25519) and v2
  (ML-DSA-65, signature profile v2). The envelope schema selects the version,
  and the algorithm, key and signature sizes must match it. Standard library
  only.
- `cmd/iff-receipt-verify`: offline receipt verification. Output reports
  `schema` and `algorithm`; `-trusted-key-id` and `-require-trust` pin the issuer key.
- Known-answer vector tests for `spec/testdata/service_receipt_v1.json`,
  `service_receipt_v2.json` and the ML-DSA-65 primitive
  (`internal/mldsavectors`, not part of the public API).

### Changed

- Requires Go 1.27 (`go.mod` is `go 1.27.0`) for `crypto/mldsa`.

## [0.2.0] - 2026-08-30

### Added

- The private monitor now imports this module for its production requirement
  fingerprints, making this implementation the source of truth rather than a
  parallel SDK copy.
- `NormalizeAddressLikeField` and `NormalizeAmount` expose the two normative
  field-normalization operations used by the fingerprint algorithm.
- `Inclusion` (the `inclusion` field of `verify.Result`) now carries
  `ObservationID`, `ObservedAt`, and `LeafHash`, matching the verify API as
  of PR #15 (merged 2026-08-29T11:13Z, commits `d746ded`, `e6abff4`,
  `4f362b0`). All three are pointer-typed and optional for compatibility
  with servers deployed before this API surface existed.

### Notes for release

- Zero external dependencies (standard library only) — confirmed via
  `GOFLAGS=-mod=mod go build ./...` with `GOMODCACHE` pointed at a clean
  temporary directory. No `go.sum` exists or is needed while this holds.
- Released as tag `go/v0.2.0`.

## [0.1.0] - commit `c3eef6a`

Initial version, never tagged or published.

### Added

- `Verify()` / `VerifyAccepts()`: client for `POST /api/v3/verify`.
- `ComputeFingerprint()` / `ComputePayeeFingerprint()`: the C1 requirement
  fingerprint algorithm, tested against the public cross-language conformance
  vectors used by the TypeScript SDK and IFF's production evidence service.
