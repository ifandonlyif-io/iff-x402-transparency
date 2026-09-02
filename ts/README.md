# @ifandonlyif/x402-preflight

Preflight-verify an x402 v2 payment requirement against [IFF](https://ifandonlyif.io)'s
independent, signed observation of that endpoint before paying. Read the
[SDK guide](https://ifandonlyif.io/sdk) and
[API documentation](https://ifandonlyif.io/docs#preflight) for the public
contract this package wraps.

**Before you install a package whose whole job is checking cryptographic
evidence, check that claim yourself:** the protocol this package speaks —
the requirement fingerprint algorithm, the Merkle transparency log, signed
tree heads, and inclusion/consistency proofs — is openly specified in
[`x402-requirement-transparency-v1.md`](../spec/x402-requirement-transparency-v1.md);
[`verify_example.py`](../spec/verify_example.py) is a standalone,
dependency-free verifier that checks a live log against that spec without
importing this package or anything else from IFF; and this SDK's
`computeFingerprint()` is tested against the same
[conformance vectors](../spec/testdata/fingerprint_vectors.json)
IFF's production server is, so a `consistent` verdict here reflects the
server's own computation, not a separate approximation of it.

The core library uses only global `fetch` and WebCrypto `crypto.subtle`, both
available in supported Node >= 22 releases and modern browsers. The bundled
optional MCP command uses the Model Context Protocol SDK.

## Install

```bash
npm install @ifandonlyif/x402-preflight
```

## Verify a requirement

```ts
import { verify } from "@ifandonlyif/x402-preflight";

const result = await verify("https://api.example.com/v1/quote", paymentRequired);
console.log(result.verdict); // "consistent" | "diverged" | "unobserved" | "stale"
```

## Wrap fetch to preflight-check every 402

```ts
import { wrapFetch } from "@ifandonlyif/x402-preflight";

const preflightFetch = wrapFetch(fetch, { onDiverged: "throw" });
// Hand preflightFetch to your payment wrapper (@x402/fetch,
// Cloudflare Agents' withX402Client, ...) instead of the bare fetch --
// it always returns the original 402 response untouched, so payment can
// still proceed once the preflight check has run.
```

## Fingerprints

```ts
import { computeFingerprint, computePayeeFingerprint } from "@ifandonlyif/x402-preflight";

const fp = await computeFingerprint(options); // { version, setFingerprint, optionFingerprints } | null
const payeeFp = await computePayeeFingerprint(options); // amount-blind: { version, payeeSetFingerprint, payeeFingerprints } | null
```

The fingerprint implementation is tested against the same conformance vectors
as IFF's production evidence service.

## MCP server

```bash
npx --package=@ifandonlyif/x402-preflight iff-x402-preflight-mcp
```

Exposes a single stdio MCP tool, `verify_x402_endpoint {url, payment_required}`
(or `{url, accepts}`), returning the same JSON `verify()` returns. Set `IFF_BASE_URL`
to point at a non-production API.

## What this verifies

The SDK compares a payment requirement with IFF's independent observations. A
`consistent` verdict is evidence of a match, not a payment-safety guarantee.
`diverged`, `stale`, and `unobserved` remain separate states so callers can set
their own policy.

## Verifying independently of this SDK

This package is a convenience client. The underlying protocol — the
requirement fingerprint algorithm, the Merkle transparency log, signed
tree heads, and inclusion/consistency proofs — is fully specified in
[`x402-requirement-transparency-v1.md`](../spec/x402-requirement-transparency-v1.md),
written so a third party can implement a compatible verifier without
reading any of IFF's source, including this SDK's.
`../spec/verify_example.py` is a dependency-light, runnable
reference verifier that checks a live log's signed tree head, Merkle
root, and an inclusion proof using only the algorithms the spec describes
— a good next step if you want to confirm what this SDK reports against
the wire protocol directly.

## Support

Questions and security reports: ben@tokimi.space
