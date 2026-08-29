# Security policy

Please report vulnerabilities privately to `support@ifandonlyif.io`.

Do not open a public issue for a suspected key compromise, proof-verification
bypass, canonicalization mismatch, SSRF issue, leaked credential, or an
unpublished split-view finding. Include the affected version or commit,
reproduction steps, and whether you believe production is affected.

IFF will acknowledge a report, preserve relevant evidence, and coordinate a
disclosure timeline appropriate to the impact. A response is not a promise of
a bounty.

The public security boundary is intentionally precise: signatures are
provenance/tamper evidence, not TEE attestation; an inclusion proof does not
establish factual correctness or payment safety; and source publication does
not remotely attest the binary running in production.
