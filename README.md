# iff-x402-transparency

The public, trust-critical verification surface for IFF's x402 requirement
transparency log and Service Receipt v1: protocol specifications, JSON
Schemas, known-answer vectors, offline verifiers, and TypeScript and Go
clients.

The goal is narrow and testable: let an independent reader verify published
log outputs and signed service receipts without relying on undocumented
server logic.

## What's here

- [`spec/x402-requirement-transparency-v1.md`](spec/x402-requirement-transparency-v1.md)
  defines requirement fingerprints, signed tree heads, Merkle inclusion and
  consistency proofs, public fields, and verdict vocabulary.
- [`spec/service-receipt-v1.md`](spec/service-receipt-v1.md) defines the
  canonical Service Receipt v1 envelope, payload, domains, trust model,
  expiry semantics, evidence references, and API adapter behavior.
- [`schemas/`](schemas/) contains JSON Schemas for receipt envelopes and the
  receipt-key directory.
- [`spec/testdata/`](spec/testdata/) contains cross-language known-answer
  vectors for fingerprints, Merkle proofs, and complete receipt verification,
  including negative cases.
- [`spec/verify_example.py`](spec/verify_example.py) is a Python
  standard-library verifier. It pins the production log-key fingerprint,
  recomputes every leaf and the complete Merkle root, verifies an inclusion
  proof, and can retain a checkpoint to verify append-only consistency.
- [`ts/`](ts/) is `@ifandonlyif/x402-preflight`.
- [`go/`](go/) is the canonical Go fingerprint/preflight module imported by
  IFF's private production monitor. It also contains the standard-library-only
  [`receipt`](go/receipt/) package and offline
  [`iff-receipt-verify`](go/cmd/iff-receipt-verify/) command.
- [`browser/service-receipt.mjs`](browser/service-receipt.mjs) is a no-DOM,
  Web Crypto receipt verifier core with Node-based conformance tests.

## Verify independently

Offline conformance check:

```bash
python3 spec/verify_example.py --self-test
python3 -m unittest discover -s spec -p 'test_*.py' -v
```

Verify production and retain a checkpoint for future consistency checks:

```bash
python3 spec/verify_example.py --checkpoint ~/.iff-production-sth.json
```

The verifier pins this production trust anchor in reviewed source:

- log ID: `e33f4a64fe0ef33fca5cbfddce858667`
- SHA-256 of raw Ed25519 public key:
  `e33f4a64fe0ef33fca5cbfddce858667ee56be6347c6cf7ffcda9d1bceaffe5b`

The API's own `/log/keys` response is metadata, not an independent trust
anchor. A key rotation requires a reviewed release that retains old keys for
historical checkpoints and adds the successor through a trusted channel.

### Verify a service receipt

Run the cross-language known-answer tests:

```bash
(cd go && go test ./receipt ./cmd/iff-receipt-verify)
node --test browser/service-receipt.test.mjs
```

Verify a standalone receipt envelope or a complete API response saved as
`response.json`:

```bash
(cd go && go run ./cmd/iff-receipt-verify -file ../response.json)
```

That checks canonical encoding, hashes, the Ed25519 signature, time state,
and—when a full response is supplied—the signed subject binding. It does not
establish who controls the embedded key. For issuer identity, additionally
pass the exact expected issuer and one or more full, independently trusted
`sha256:` key IDs; use `-require-trust` when a trust mismatch must fail the
command.

The receipt key directory is useful origin metadata when fetched from the
exact expected HTTPS issuer. It is not an independently pinned trust anchor.

The version-controlled production pin first published on 2026-09-01 is archived at
[`keys/service-receipt-production-2026-09-01.json`](keys/service-receipt-production-2026-09-01.json):

- issuer: `https://ifandonlyif.io`
- full key ID:
  `sha256:0f872f79cd935ac2d764589c8283d35ae0ca02780faebee8862db85348fc5ceb`

Use the issuer and full key ID together. The dated file is a versioned release
snapshot distributed through this protected repository; the live key
directory remains mutable discovery metadata. Rotation adds a new versioned
snapshot and retains this one so historical receipts keep their original pin.
Its `current` status means current when that dated snapshot was published; an
old snapshot can support historical verification but MUST NOT automatically
authorize newly issued receipts forever. Publish the successor first, overlap
the predecessor for the receipt lifetime plus directory-cache lifetime, then
mark the predecessor historical/inactive in the next versioned snapshot.

## What this proves—and what it doesn't

| Claim | Public evidence | Limitation |
|---|---|---|
| Requirement fingerprints follow v1 | Spec, vectors, and the canonical Go implementation used by production | Published source alone does not identify the binary running on the server |
| An STH came from IFF's pinned log key | Canonical bytes, signature, and pinned key fingerprint | A rotation needs a separately trusted update |
| An observation is included in a snapshot | Recomputed root and RFC 6962 inclusion proof | Inclusion does not prove the observation is factually correct |
| History advanced append-only | A retained STH and consistency proof | One observer cannot exclude every split view; independent witnesses improve this |
| A Service Receipt payload was signed by a particular Ed25519 key | Canonical payload bytes, domain-separated digest, signature, and full key ID | The embedded public key proves only signature self-consistency; identity needs an independently trusted issuer/key policy |
| An API response still matches the receipt's signed subject | Decoded signed subject and its domain-separated hash | Evidence and compute-proof descriptors are references and remain explicitly unverified until checked separately |
| An SDK package came from this source | Public CI and npm OIDC provenance | Provenance identifies source/build, not the production server binary |

The supported statement is: **the monitor's trust-critical outputs and signed
receipt bytes are independently verifiable, and its canonical implementations
are publicly auditable.** This does not turn an observation or receipt into a
claim of payment safety, endpoint honesty, remote attestation, TEE execution,
AI reasoning correctness, or a composite trust score.

This repository deliberately excludes the API server, production deployment
configuration and secrets, owner/auth state, private keys, and hosted UI DOM.
Those components are not needed to reproduce canonical receipt verification.
The receipt vector contains only a conspicuously labelled public test seed;
never trust or deploy that key.

## Development

```bash
(cd go && go test ./...)
(cd go && go vet ./...)
(cd ts && npm ci && npm test && npm run build)
node --test browser/service-receipt.test.mjs
python3 spec/verify_example.py --self-test
python3 -m unittest discover -s spec -p 'test_*.py' -v
python3 -m json.tool schemas/service-receipt-v1.json >/dev/null
python3 -m json.tool schemas/service-receipt-key-directory-v1.json >/dev/null
python3 -m json.tool spec/testdata/service_receipt_v1.json >/dev/null
```

See [SECURITY.md](SECURITY.md) for private vulnerability reporting.

## License

MIT. See [LICENSE](LICENSE).
