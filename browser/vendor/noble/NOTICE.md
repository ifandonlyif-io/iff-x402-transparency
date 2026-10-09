# Vendored libraries

`browser/ml-dsa-65.mjs` verifies Service Receipt v2 (ML-DSA-65) signatures with
code from three MIT-licensed packages by Paul Miller. Only the files that
`ml-dsa.js` imports are vendored, unmodified, from the integrity-pinned npm
tarballs used by the IFF reference implementation:

- `@noble/post-quantum` 0.7.1 (`post-quantum/`)
- `@noble/hashes` 2.4.0 (`hashes/`)
- `@noble/curves` 2.4.0 (`curves/`; only the modular and FFT helpers that
  `ml-dsa.js` imports)

Licenses: [post-quantum](LICENSE-noble-post-quantum),
[hashes](LICENSE-noble-hashes), [curves](LICENSE-noble-curves).
`package.json` only marks the files as ES modules for Node. Each file's SHA-256
equals the reference copy, and `service-receipt.test.mjs` checks this table.
These packages are not independently audited for this use, and
`@noble/post-quantum` does not claim constant-time signing; this repository
uses it for verification only, which handles public data. The Go verifier
(`go/receipt`) uses the standard library `crypto/mldsa` instead.

| File | SHA-256 |
|---|---|
| `curves/abstract/fft.js` | `a4b2ff7ca33f4acc85d61f0e83ec3303c3f6b38ecc19b20d0f6462d820e518cf` |
| `curves/abstract/modular.js` | `9ced3aa10598277a735e54f7b61d88e929d565da884ba5385f9006ebb3b6aab2` |
| `curves/utils.js` | `721216668546d48385b5bca2f28b235ac21186cf12084f63e62e8411aa13ab7e` |
| `hashes/_u64.js` | `b09da8c07fe8187c07649494cdb7cd0bcf13df90b506a9473d19e4d5f8c2e102` |
| `hashes/sha3.js` | `9a81e1edb24eae27b335533220167609cfb58008c5690e140ce478acdc669f32` |
| `hashes/utils.js` | `037ad49adb78168b6b699598fd33f85f7877456b1d28b4d032e2a1a16807947c` |
| `post-quantum/_crystals.js` | `0ebd9e698272ad6ff2f05479570f3440c36d96e6ac633c107627fa2ee71ec86a` |
| `post-quantum/ml-dsa.js` | `2765f2c3a29739883dcf1f010d95d3da58cc5ecab659866f7fb91ee48444fc0b` |
| `post-quantum/utils.js` | `081d259b2f9d77537d098e11d13ccad035723f0129651b130e8ecc3031ad9caf` |
| `package.json` | `3ca9d4afd21425087cf31893b8f9f63c81b0b8408db5e343ca76e5f8aa26ab9a` |
