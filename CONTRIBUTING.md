# Contributing

Small, reviewable changes with test vectors are preferred.

Before opening a pull request, run:

```bash
(cd go && go test ./...)
(cd ts && npm ci && npm test && npm run build)
python3 spec/verify_example.py --self-test
python3 -m unittest discover -s spec -p 'test_*.py' -v
```

Changes to canonicalization, hashing, proof verification, or wire fields must
update the specification and known-answer vectors in the same pull request.
Do not weaken the stated limitations or introduce `safe`/`unsafe`, TEE,
payment-safety, or composite-score claims.

Report security-sensitive findings through [SECURITY.md](SECURITY.md), not a
public issue.
