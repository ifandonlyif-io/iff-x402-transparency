# Contributing

Small, reviewable changes with test vectors are preferred.

Before opening a pull request, run:

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

Changes to canonicalization, hashing, proof verification, or wire fields must
update the relevant specification, JSON Schema, cross-language implementation,
and known-answer vectors in the same pull request. Receipt changes must keep
Go and browser verification behavior aligned, including strict JSON, size and
nesting limits, domain separation, half-open validity windows, and the
distinction between signature validity and issuer trust.

Do not weaken the stated limitations or introduce `safe`/`unsafe`, TEE,
remote-attestation, payment-safety, AI-reasoning-proof, or composite-score
claims. Never add production secrets, private signing keys, server/deployment
configuration, owner/auth state, or hosted UI code to this verification-only
slice. Public test seeds must remain clearly labelled as untrusted test data.

Report security-sensitive findings through [SECURITY.md](SECURITY.md), not a
public issue.
