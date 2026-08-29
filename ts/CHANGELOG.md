# Changelog

All notable changes to `@ifandonlyif/x402-preflight` are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versioning follows [SemVer](https://semver.org/).

## [0.2.0] - Unreleased

Prepared but not published to npm — see `docs/PUBLIC_RELEASE.md` in the
main repository for the exact release command and the release-readiness
checklist this version went through.

### Added

- `VerifyInclusion` (the `inclusion` block of `POST /api/v3/verify`'s
  response) now carries `observation_id`, `observed_at`, and `leaf_hash`,
  matching the API as of PR #15 (merged 2026-08-29T11:13Z). All three are
  typed optional for compatibility with servers deployed before this API
  surface existed — a caller does not need to branch on API version to
  keep using the fields it already read.

### Fixed

- None since 0.1.0's publish; 0.1.0 on npm predates PR #15 by about five
  hours and is missing the three fields above. Callers reading
  `inclusion.observation_id`, `inclusion.observed_at`, or
  `inclusion.leaf_hash` against the current production API need 0.2.0 or
  later.

## [0.1.0] - 2026-08-29

Initial release, published to npm 2026-08-29T06:31:22Z.

### Added

- `verify()` / `verifyAccepts()`: client for `POST /api/v3/verify`.
- `wrapFetch()`: wraps a `fetch` implementation to preflight-check every
  `402` response before payment proceeds, with configurable `onDiverged`
  (default `"throw"`), `onStale` (default `"strict"` — throws only when
  `matches_last_observed === false`), and `onUnobserved` (default
  `"warn"`, never silent) policies.
- `computeFingerprint()` / `computePayeeFingerprint()`: the C1 requirement
  fingerprint algorithm, computed client-side via WebCrypto
  `crypto.subtle`, tested against the same conformance vectors as IFF's
  production evidence service.
- Bundled MCP server (`iff-x402-preflight-mcp`) exposing a single
  `verify_x402_endpoint` tool over stdio.
