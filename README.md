# iff-x402-transparency

The public, trust-critical verification surface for IFF's x402 requirement
transparency log: protocol specification, known-answer vectors, a pinned-key
reference verifier, and TypeScript and Go clients.

The goal is narrow and testable: let an independent reader verify published
log outputs without relying on undocumented server logic. This repository is
not a claim that IFF's production runtime is remotely attested.

## What's here

- [`spec/x402-requirement-transparency-v1.md`](spec/x402-requirement-transparency-v1.md)
  defines requirement fingerprints, signed tree heads, Merkle inclusion and
  consistency proofs, public fields, and verdict vocabulary.
- [`spec/testdata/`](spec/testdata/) contains cross-language known-answer
  vectors for fingerprint and Merkle implementations.
- [`spec/verify_example.py`](spec/verify_example.py) is a Python
  standard-library verifier. It pins the production log-key fingerprint,
  recomputes every leaf and the complete Merkle root, verifies an inclusion
  proof, and can retain a checkpoint to verify append-only consistency.
- [`ts/`](ts/) is `@ifandonlyif/x402-preflight`.
- [`go/`](go/) is the canonical Go fingerprint/preflight module imported by
  IFF's private production monitor.

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

## What this proves—and what it doesn't

| Claim | Public evidence | Limitation |
|---|---|---|
| Requirement fingerprints follow v1 | Spec, vectors, and the canonical Go implementation used by production | Source publication is not runtime attestation |
| An STH came from IFF's pinned log key | Canonical bytes, signature, and pinned key fingerprint | A rotation needs a separately trusted update |
| An observation is included in a snapshot | Recomputed root and RFC 6962 inclusion proof | Inclusion does not prove the observation is factually correct |
| History advanced append-only | A retained STH and consistency proof | One observer cannot exclude every split view; independent witnesses improve this |
| An SDK package came from this source | Public CI and npm OIDC provenance | Provenance identifies source/build, not the production server binary |

The supported statement is: **the monitor's trust-critical outputs are
independently verifiable, and its canonical fingerprint implementation is
publicly auditable.** This repository does not claim TEE execution, remote
attestation, payment safety, endpoint honesty, or a composite trust score.

The first release does not yet expose the GET-only probing and public-card
policy implementation. Those source slices are planned next so auditors can
review manual-probe exclusion, D6 field allowlisting, SSRF policy, tier and
verdict rules, opt-out, and discovery attribution. Even then, public source
will remain auditability—not runtime attestation.

## Development

```bash
(cd go && go test ./...)
(cd ts && npm ci && npm test && npm run build)
python3 spec/verify_example.py --self-test
python3 -m unittest discover -s spec -p 'test_*.py' -v
```

See [SECURITY.md](SECURITY.md) for private vulnerability reporting.

## License

MIT. See [LICENSE](LICENSE).
