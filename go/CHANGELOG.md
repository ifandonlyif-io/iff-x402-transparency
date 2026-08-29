# Changelog

All notable changes to `github.com/ifandonlyif-io/iff-x402-transparency/go`
are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning
follows [SemVer](https://semver.org/).

This module has never been tagged or released — `go get` of it fails today
because the containing repository is private (see
`docs/PUBLIC_RELEASE.md`). Versions below are conceptual until a release
path (a git tag on this repository, or a tag in an extracted public repo)
exists; each entry names the commit it corresponds to.

## [0.2.0] - Unreleased

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
- Release from the extracted public repository with tag `go/v0.2.0`.

## [0.1.0] - commit `c3eef6a`

Initial version, never tagged or published.

### Added

- `Verify()` / `VerifyAccepts()`: client for `POST /api/v3/verify`.
- `ComputeFingerprint()` / `ComputePayeeFingerprint()`: the C1 requirement
  fingerprint algorithm, tested against the public cross-language conformance
  vectors used by the TypeScript SDK and IFF's production evidence service.
