# x402 Requirement Transparency — v1

Status: Draft v1. Owner: IFF (ifandonlyif.io).

This document specifies a self-contained format and protocol for
publishing, and independently verifying, evidence about the payment
requirements a public x402 v2 HTTP endpoint presents over time. It is
written so that a third party can implement a **compatible log** (a
service that ingests observations and publishes the same artifacts) or a
**compatible verifier** (a client that checks those artifacts) without
reading IFF's source code.

## 0. Scope and non-goals

This specification covers:

- A canonical, hashable form for an x402 payment-requirement set
  ("requirement fingerprint", §1).
- A canonical, signed form for one monitor's observation of an endpoint
  ("observation report", §3).
- A Merkle transparency log of observation reports, in the style of
  Certificate Transparency (RFC 6962): leaf/node hashing, sequencing,
  signed tree heads, and inclusion/consistency proofs (§4–§6).
- A minimal key-transparency endpoint (§7) and an on-chain anchoring record
  format for periodically checkpointing the log (§8).
- The public HTTP API surface that exposes all of the above (§9).

It deliberately does **not** specify or imply:

- That a payment made against an observed requirement will succeed, or is
  safe to make.
- That an endpoint's operator, infrastructure, or execution environment has
  been attested to in any way (no TEE / remote-attestation claim).
- A composite "trust score". Every artifact here is a dimensioned,
  independently checkable observation, never a single number.

A monitor's signature over a report, and a log's signature over a tree
head, are **provenance and tamper-evidence**: they let a verifier confirm
*who* published *what*, and that it has not been altered since. They are
not a safety or correctness guarantee about the endpoint being observed.

### 0.1 Operator model

Today, one operator (IFF) runs both the transparency log itself and every
monitor that submits observations to it. That is a deployment fact, not a
structural assumption this specification bakes in: `monitor_id` and
`monitor_public_key` (§3, §7) already exist precisely so a second,
independently operated monitor can submit observations to the same log
without any format change — a verifier that checks a report's signature
against the monitor key it claims, and checks that key's `first_seen`/
`last_seen` window (§7), does not need to know or care how many
organizations operate the monitors it is trusting. §7's `GET
/api/v3/log/keys` is where a verifier discovers the full set of monitor
keys (and log keys) that have ever been active, one operator or many.
Multi-operator monitoring is therefore already representable; a
multi-operator **log** — more than one party independently sequencing and
signing tree heads over the same observation set — is a different, larger
problem and out of scope for this v1 specification.

## 1. Requirement fingerprint v1

An x402 v2 `402 Payment Required` response carries one or more **payment
options**. A payment option's fields relevant to this specification are:

| Field | Meaning |
|---|---|
| `scheme` | x402 payment scheme, e.g. `exact` |
| `network` | CAIP-2 network identifier, e.g. `eip155:8453` |
| `asset` | Asset identifier (a contract address on EVM chains, or a token identifier on others) |
| `pay_to` | Payee address |
| `amount` | Amount as a decimal-string integer (in the asset's base unit) |

`max_timeout_seconds`, if present, is an operational parameter (how long a
payment channel stays open), not a payment requirement, and is **never**
part of any fingerprint in this specification: an endpoint changing it does
not constitute a requirement change.

### 1.1 Field normalization

Before hashing, every field is normalized independently:

| Field | Normalization |
|---|---|
| `scheme` | `trim(x)`, then lowercase |
| `network` | `trim(x)`, then lowercase |
| `asset` | If `trim(x)` matches the regular expression `^0x[0-9a-fA-F]{40}$`, lowercase the **hexadecimal digits only** (the `0x` prefix is already lowercase in the regex, so the whole trimmed string is safe to lowercase directly when it matches). Otherwise, use `trim(x)` unchanged. |
| `pay_to` | Same rule as `asset`. |
| `amount` | `trim(x)`. If the trimmed value consists only of ASCII decimal digits (`0`-`9`), strip leading zeros (so `"000"` → `"0"`, `"0007"` → `"7"`, but a value with a decimal point, sign, or non-digit character is used exactly as trimmed). |

The `asset`/`pay_to` rule is deliberately narrow: it lowercases only values
that already look like an EIP-55 or plain-hex EVM address written with a
lowercase `0x` prefix. Addresses on other networks (for example, Solana's
base58 addresses) are case-sensitive and must **not** be lowercased — a
value that does not match the regex, including one with an uppercase `0X`
prefix, passes through with only whitespace trimmed.

### 1.2 Canonical option JSON

A normalized option is serialized as JSON with **exactly** these five keys,
in this order, with no inserted whitespace, and without HTML-escaping `<`,
`>`, or `&`:

```json
{"scheme":"exact","network":"eip155:8453","asset":"0xab12...","pay_to":"0xef56...","amount":"1000000"}
```

### 1.3 Fingerprint formulas

```
option_fp(option) = hex( SHA-256( "iff-x402-option/v1\n" || canonical_json(option) ) )

OptionFPs(options) = sort( unique( option_fp(o) for o in options ) )   // ascending, case-sensitive hex string sort

set_fp(options) = hex( SHA-256( "iff-x402-set/v1\n" || join(OptionFPs(options), "\n") ) )
```

`hex(...)` is lowercase hexadecimal. `||` is byte-string concatenation
(the domain-separation prefixes above include a literal newline,
`0x0A`, not the two characters `\` and `n`). `sort` is an ascending sort of
the hex strings by their byte values (equivalently, ordinary
case-sensitive ASCII string sort, since hex digests are lowercase hex).

A fingerprint is computed **only** when the observed HTTP status was `402`
and at least one payment option was present; there is no fingerprint for
any other response. Two observations with the same `set_fp` are considered
to present the identical requirement set, regardless of option order or
duplicate options in the original response.

Test vectors: `spec/testdata/fingerprint_vectors.json` in this repository
(a JSON array of named cases covering casing, leading
zeros, duplicate/reordered options, base58 case-sensitivity, and the empty
set). Field version: `fingerprint_version: 1` in that file corresponds to
this section.

### 1.4 Payee fingerprint variant

A second fingerprint, used only to classify *why* two requirement sets
differ (§2.3), is computed the same way but **without the `amount` field**
and with a different domain-separation prefix:

```
canonical_payee_json(option) = {"scheme":...,"network":...,"asset":...,"pay_to":...}   // same 4 fields, same order, same normalization, amount omitted

payee_fp(option) = hex( SHA-256( "iff-x402-payee/v1\n" || canonical_payee_json(option) ) )
```

There is no aggregate "payee set fingerprint": `payee_fp` is computed
per-option and compared per-option (§2.3).

## 2. Verdict vocabulary

A verifier comparing a payment requirement it received against what has
been independently observed produces exactly one of four verdicts. These
words are the complete vocabulary; nothing in this system ever outputs a
"safe" / "unsafe" label or a numeric score.

| Verdict | Meaning |
|---|---|
| `consistent` | Every option received matches an option observed within the freshness window. |
| `diverged` | At least one received option does not match anything observed within the window. |
| `unobserved` | No independent observation exists for this endpoint at all. |
| `stale` | Observations exist, but the most recent one is older than the freshness window. |

### 2.1 Freshness window

```
window_seconds = probe_interval_seconds(endpoint) * 2 + 600
```

`probe_interval_seconds` is the endpoint's own re-probe cadence (shorter
for endpoints under active ownership verification, longer for endpoints
only discovered from public sources). It is exposed, unmodified, on the
endpoint's public evidence card as `freshness.interval_seconds` — plainly:
for every endpoint, in both tiers, `freshness.interval_seconds` on that
card is the exact same value `window_seconds` above was computed from. A
verifier holding only the public card (never the verify API's response)
can therefore recompute `window_seconds` itself as
`freshness.interval_seconds * 2 + 600`, without knowing anything about
tiers or per-tier configuration.

### 2.2 Verdict algorithm

The verdict vocabulary itself never changes: it is exactly the four words
in the table above, always exactly one of them, never a fifth word and
never `safe`/`unsafe`/a score. `stale` is a **freshness** statement about
how old the most recent observation is — it is not, by itself, a
statement about whether the received requirement still matches what was
last seen. A stale endpoint's requirement is still compared against the
last thing observed, and the response says separately whether that
comparison still matches.

Given a set of received options and the full set of `set_fp`-distinct
fingerprintable observations recorded for the endpoint:

1. If there is no endpoint record for the URL at all → `unobserved`, and
   the response's `known` field (present only for this verdict) is
   `false`.
2. Else if the endpoint record exists but has never produced a
   fingerprintable observation → `unobserved`, `known: true`.
3. Else let `latest` be the most recent fingerprintable observation. If
   `latest`'s timestamp is older than `window_seconds` (§2.1) before now,
   the verdict is fixed to `stale`, and the comparison window used in the
   next step is anchored at `latest`'s own timestamp —
   `[latest_time - window_seconds, latest_time]` — **not** at "now": a
   window ending at "now" would always be empty for an observation that
   is, by definition, already older than `window_seconds`, and would say
   nothing about whether the requirement still matches what was last
   seen. Otherwise the verdict is not yet fixed, and the window is `[now -
   window_seconds, now]` as in v0 of this rule.
4. Let `ObservedOptionFPs` be the union of `option_fp` values across every
   fingerprintable observation inside that window. `matches_last_observed`
   is `true` when every `option_fp` of every received option is a member
   of `ObservedOptionFPs`, `false` otherwise. If the verdict was not
   already fixed to `stale` in step 3, it is now decided:
   `consistent` when `matches_last_observed` is `true`, `diverged`
   otherwise.

`matches_last_observed` is present in the response for every verdict
*except* `unobserved` (which has nothing to compare against). It is the
only field that distinguishes a stale observation that still matches the
received requirement from one that no longer does, since the verdict word
itself stays `stale` in both cases.

Whenever `matches_last_observed` is `false` — for **both** a `diverged`
verdict and a mismatching `stale` one — the response identifies exactly
which received options failed to match, **by their `option_fp`, never by
their raw `pay_to`/`asset`/`amount`** (returning the raw values back to
the caller would let a mismatch be used as an oracle for "guess an
address, see if it was ever paid to"), and carries a `divergence_kind`
(§2.3). When `matches_last_observed` is `true`, the unmatched-options list
is empty and `divergence_kind` is absent.

The table below summarizes which response fields a caller can expect for
each verdict (beyond `url`, `verdict`, `received`, `unmatched_received_options`,
`ownership`, and `disclaimer`, which are present for all four):

| Field | `consistent` | `diverged` | `stale` | `unobserved` |
|---|---|---|---|---|
| `tier`, `window_seconds` | present | present | present | present only when `known: true` |
| `observed` | present | present | present | absent |
| `matches_last_observed` | `true` | `false` | `true` or `false` | absent |
| `divergence_kind` | absent | present | present iff `matches_last_observed: false` | absent |
| `known` | absent | absent | absent | present |

### 2.3 Divergence kind

Whenever `matches_last_observed` is `false` (§2.2) — regardless of whether
the verdict is `diverged` or a mismatching `stale` — the response is
further classified by comparing `payee_fp` (§1.4) values, computed in
memory from the same comparison window §2.2 used (this classification is
never persisted):

| `divergence_kind` | Condition |
|---|---|
| `amount_only` | Every received option's `payee_fp` is present in the comparison window's set of payee fingerprints — only `amount` differs from what has been observed. |
| `payee` | At least one received option's `payee_fp` is **not** present in the comparison window — `scheme`, `network`, `asset`, or `pay_to` differs, not just the amount. |

A verifier consuming this system's output is expected to treat these two
cases differently: `amount_only` is consistent with legitimate dynamic
pricing, while `payee` means the endpoint is asking to pay a scheme,
network, asset, or address that has never been independently observed.

## 3. Observation report

One **observation** is one monitor's record of probing one endpoint at one
point in time. Its canonical, hashable form is a JSON object with
**exactly** these keys, in this order, with no inserted whitespace and no
HTML-escaping, and with a key omitted (not emitted as `null`) exactly where
noted below:

```json
{
  "endpoint_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
  "probe_type": "scheduled",
  "monitor_id": "iff-monitor-1",
  "monitor_version": "3.0.0",
  "monitor_public_key": "base64-encoded-32-byte-ed25519-public-key",
  "status_code": 402,
  "reachable": true,
  "protocol_status": "pass",
  "x402_version": 2,
  "latency_ms": 123,
  "payment_options": [
    {"scheme":"exact","network":"eip155:8453","asset":"0x...","amount":"1000000","pay_to":"0x...","max_timeout_seconds":60}
  ],
  "check_codes": ["http_402_observed", "x402_v2_valid"],
  "error_code": "",
  "observed_at": "2026-08-29T12:00:00.123456Z"
}
```

Field notes:

- `probe_type` is one of `initial`, `scheduled`, `discovery`, or `manual`.
  **Only `initial`, `scheduled`, and `discovery` observations are ever
  sequenced into the transparency log (§4); `manual` observations never
  are**, regardless of their content.
- `monitor_public_key`, `status_code`, `x402_version`, and `latency_ms` are
  omitted from the JSON entirely when absent (not present as `null`).
  `error_code` is omitted when empty.
- Each entry of `payment_options` uses the field order
  `scheme, network, asset, amount, pay_to, max_timeout_seconds` — note
  this is **not** the same field order as the fingerprint's canonical
  option JSON (§1.2), which omits `max_timeout_seconds` and orders
  `pay_to` before `amount`. The two serializations exist for different
  purposes (a complete report vs. a minimal hashable set) and must not be
  conflated. `max_timeout_seconds` is **always present** in this report
  form, even when the endpoint's own response never provided one: it is
  emitted as `0` in that case, never omitted, because unlike this report's
  other optional fields it has no "absent means omitted" rule of its own.
- `check_codes` is an array of short, ASCII, machine-readable strings a
  monitor implementation attaches to describe what it observed and why
  (the example above, `http_402_observed` then `x402_v2_valid`, is what
  IFF's own monitor emits for an ordinary successful probe). **These
  strings are implementation-defined**: this specification fixes their
  JSON position and type (an array of strings, possibly empty), not their
  vocabulary. A compatible log or monitor may use an entirely different
  set of check-code strings; they are not part of any cross-implementation
  contract, and a verifier should not branch its logic on a specific
  string here beyond what it has independently agreed with that monitor.
- `observed_at` is UTC, truncated to microsecond precision, formatted with
  **exactly six fractional digits** and a literal `Z` suffix:
  `2006-01-02T15:04:05.000000Z` (Go time-layout notation). This exact
  truncation and format matters: the database column backing it has only
  microsecond resolution, and any different formatting (fewer/more
  fractional digits, a numeric offset instead of `Z`) produces different
  bytes and therefore a different hash.

```
report_hash = hex( SHA-256( canonical_report_json ) )
```

If the report is signed, the signature covers the **raw 32-byte SHA-256
digest**, not the JSON bytes and not the hex string:

```
monitor_signature = base64( Ed25519-Sign(monitor_private_key, SHA-256(canonical_report_json)) )
```

A verifier checks a report by recomputing `canonical_report_json` from the
report's own fields, confirming its SHA-256 digest equals the claimed
`report_hash`, and — when a `monitor_public_key` is present — confirming
`Ed25519-Verify(monitor_public_key, digest, monitor_signature)`.

## 4. Transparency log

The transparency log is a single, global, append-only Merkle tree (RFC
6962 construction) over observation reports, shared across every endpoint
this system has ever observed. It is **not** partitioned per endpoint: an
inclusion proof or a consistency proof is always relative to this one
tree.

### 4.1 What gets sequenced

Every `initial`, `scheduled`, and `discovery` observation is sequenced
exactly once, in the order its underlying record was created, using a
strict `(created_at, id)` tiebreak so that the order is stable even when
two observations share the same creation timestamp. `manual` observations
are never sequenced. Sequencing assigns each entry a **dense, zero-based,
strictly increasing** `log_index`: entry 0 is the first ever sequenced
entry, entry 1 the second, and so on, with no gaps.

### 4.2 Leaf hashing

A log entry's leaf is the raw 32 bytes of its observation's `report_hash`
(§3) — decode the hex string, do not re-hash the hex characters:

```
leaf_hash(entry) = SHA-256( 0x00 || report_hash_bytes )
```

`0x00` is a single leaf-domain-separation byte (RFC 6962 §2.1). This is
the *only* place `0x00` is used as a prefix in this specification.

### 4.3 Node hashing

Every interior node of the tree is:

```
node_hash(left, right) = SHA-256( 0x01 || left || right )
```

where `left` and `right` are each a 32-byte child hash (a leaf hash or
another node hash), and `0x01` is the interior-node domain-separation
byte. This, and only this, is how two hashes are ever combined anywhere in
this specification — inclusion proofs, consistency proofs, and root
computation all use exactly this formula.

The root hash of a tree with zero leaves is `SHA-256("")` (the SHA-256
digest of the empty byte string) — a special case with **no** domain
separation byte, per RFC 6962.

### 4.4 Tree shape

Let `D[0:n]` denote the ordered list of the tree's first `n` leaf hashes
(§4.2). The tree's root at size `n` is the Merkle Tree Hash `MTH(D[0:n])`,
defined recursively exactly as RFC 6962 §2.1 defines it:

```
MTH(D[0:0])  = SHA-256("")                            -- empty tree (§4.3)
MTH(D[0:1])  = D[0]                                    -- one leaf: its own leaf_hash
MTH(D[0:n])  = node_hash( MTH(D[0:k]), MTH(D[k:n]) )    for n > 1
```

where `k` is the largest power of two strictly less than `n` (so `D[0:k]`
is always a perfect binary subtree of `k` leaves, and `D[k:n]` is the same
construction recursively applied to the remaining `n - k` leaves, which
need not itself be a power of two). `node_hash` is §4.3's formula. This
recursive definition is normative and complete: it, together with
§4.2–§4.3 and the verification algorithms in §6, is sufficient to
independently compute or verify every artifact this log publishes,
without consulting RFC 6962 itself.

*(Informative — not a different tree shape, just an efficient way to
compute the same root.)* An implementation does not need to recompute
`MTH` recursively from scratch on every append. The [compact-range
representation the `transparency-dev/merkle` Go module
implements](https://github.com/transparency-dev/merkle) maintains only the
`O(log n)` "frontier" nodes needed to extend the tree by one leaf and to
answer inclusion/consistency queries, without touching most of the tree's
interior nodes on every write. Every node such an implementation persists
long-term corresponds to some `MTH(D[i:j])` for a range `[i:j]` that is
already a complete power-of-two subtree in the definition above — nothing
about the recursive definition changes to accommodate this optimization.

## 5. Signed tree head (STH)

A signed tree head is a checkpoint: a commitment to the entire tree's
state at a given size, signed by the log operator's key.

### 5.1 Canonical bytes

```json
{"log_id":"7eb8000c99b6e474b553fa38757d76fa","tree_size":8,"timestamp":"2026-08-29T00:00:00.000000Z","root_hash":"c6f684ce14d150072e8237a2d0183d75c6681088c406914e684fb0ba8b6eb8fb"}
```

The JSON object has **exactly** these four keys, in this order, with no
inserted whitespace:

| Key | Type | Value |
|---|---|---|
| `log_id` | string | See §5.3. |
| `tree_size` | number | The number of leaves this STH commits to (a JSON integer, not a string). |
| `timestamp` | string | UTC, microsecond-truncated, formatted exactly as §3 specifies for `observed_at` (`2006-01-02T15:04:05.000000Z`). |
| `root_hash` | string | Lowercase hex of the 32-byte root hash (§4.3) at `tree_size`. |

### 5.2 Signature

```
sth_sha256 = SHA-256(canonical_bytes)
sth_keccak256 = Keccak-256(canonical_bytes)
signature = base64( Ed25519-Sign(log_private_key, sth_sha256) )
```

As with the observation report (§3), the signature covers the raw 32-byte
SHA-256 digest, not the canonical bytes directly and not the hex string.
`sth_keccak256` is not signed; it exists solely so the STH's content can be
referenced by hash from an EVM on-chain record (§8), where Keccak-256 is
the native hash function.

### 5.3 Log identity

```
log_id = hex( SHA-256(ed25519_public_key)[0:16] )
```

`ed25519_public_key` is the raw 32-byte Ed25519 public key. `log_id` is
therefore 32 lowercase hex characters (16 bytes). A log may rotate its
signing key; each key has its own `log_id`, and §7 describes how a
verifier discovers which keys have ever been valid and when.

The derivation above is an identifier, **not a trust anchor**. A verifier
MUST obtain an expected `log_id` and full public-key fingerprint through a
channel independent of the log response it is checking, such as a reviewed
release of the verifier, a retained earlier checkpoint, or another operator's
witness. Accepting both `public_key` and `log_id` from the same untrusted STH
only proves that the two attacker-controlled values agree with each other.
`GET /api/v3/log/keys` is useful for key history but, when served by the same
operator, is not by itself an independent trust source.

### 5.4 Publication cadence

A new STH is published only when the tree has grown since the previous
one — there is never more than one STH for a given `tree_size`, and a
`tree_size` that was never reached never has an STH. A verifier must not
assume STHs are published at a fixed wall-clock interval; it should always
fetch the current one (§9.1) rather than compute an expected `tree_size`.

## 6. Proof formats and verification

Both proof types are arrays of 32-byte hashes, transported as lowercase
hex strings, ordered as RFC 6962 specifies (bottom of the tree toward the
root). Sections 6.1–6.2 give complete, self-contained verification
pseudocode; an implementer does not need to consult RFC 6962 itself to
implement a verifier, only to implement a log that constructs these
proofs.

Throughout, `HASH_NODE(l, r)` is §4.3's `node_hash`, and integer division
`/` truncates toward zero (as in most languages' integer division; all
operands here are non-negative).

### 6.1 Inclusion proof

An inclusion proof demonstrates that the leaf at `log_index` is present in
the tree at `tree_size`, given the tree's root hash at that size.

```
function verify_inclusion(leaf_hash, log_index, tree_size, audit_path, root_hash) -> bool:
    if not (0 <= log_index < tree_size):
        return false

    node_index = log_index
    last_index = tree_size - 1
    hash = leaf_hash
    path_pos = 0

    while last_index > 0:
        if node_index is odd:
            if path_pos >= length(audit_path): return false
            hash = HASH_NODE(audit_path[path_pos], hash)   # sibling is to the left
            path_pos = path_pos + 1
        else if node_index < last_index:
            if path_pos >= length(audit_path): return false
            hash = HASH_NODE(hash, audit_path[path_pos])   # sibling is to the right
            path_pos = path_pos + 1
        # else: node_index == last_index and node_index is even --
        #       this node has no sibling yet at this level; it is
        #       promoted to the next level unchanged, and no audit_path
        #       entry is consumed for this step.
        node_index = node_index / 2
        last_index = last_index / 2

    return path_pos == length(audit_path) and hash == root_hash
```

A tree with exactly one leaf (`tree_size == 1`) has an empty `audit_path`:
the loop body never executes (`last_index` starts at 0), and `hash` must
already equal `root_hash` (the single leaf's own hash).

### 6.2 Consistency proof

A consistency proof demonstrates that the tree at `second` leaves is an
append-only extension of the tree at `first` leaves — i.e. that the first
`first` leaves, in order, are identical between the two — given both
roots.

```
function verify_consistency(first, second, proof, first_root, second_root) -> bool:
    if not (0 <= first <= second):
        return false
    if first == second:
        return length(proof) == 0 and first_root == second_root
    if first == 0:
        return length(proof) == 0

    shift = count_trailing_zero_bits(first)          # e.g. first=6 (0b110) -> shift=1
    if first == (1 << shift):                         # first is itself a power of two
        seed = first_root
        remaining = proof
    else:
        if length(proof) < 1: return false
        seed = proof[0]
        remaining = proof[1:]

    inner = bit_length((first - 1) XOR (second - 1)) - shift
    if inner < 0:
        return false
    mask = (first - 1) >> shift

    # Exact proof-length check. Every valid consistency proof has
    # precisely this many elements: `inner` fold-or-skip positions, one
    # border element per set bit of (second-1) above them, plus the
    # leading seed element already split off above when `first` is not
    # itself a power of two. A proof of any other length -- too short to
    # even slice below, or padded with extra elements -- is rejected here,
    # before any hashing happens.
    expected = inner + popcount((second - 1) >> (inner + shift))
    if first != (1 << shift):
        expected = expected + 1
    if length(proof) != expected:
        return false

    border = remaining[inner:]

    # --- Reconstruct first_root: fold in only the positions that are
    #     part of `first`'s own tree structure (bit i of mask == 1). ---
    hash1 = seed
    for i in 0 .. inner-1:
        if bit(mask, i) == 1:
            hash1 = HASH_NODE(remaining[i], hash1)      # sibling on the left
        # else: position i belongs only to the extension beyond `first`; skip it for hash1
    for h in border:
        hash1 = HASH_NODE(h, hash1)
    if hash1 != first_root:
        return false

    # --- Reconstruct second_root: fold in every position. ---
    hash2 = seed
    for i in 0 .. inner-1:
        if bit(mask, i) == 0:
            hash2 = HASH_NODE(hash2, remaining[i])      # sibling on the right
        else:
            hash2 = HASH_NODE(remaining[i], hash2)      # sibling on the left
    for h in border:
        hash2 = HASH_NODE(h, hash2)
    return hash2 == second_root
```

`count_trailing_zero_bits`, `bit_length`, and `popcount` are the standard
bit-twiddling operations (e.g. Go's `math/bits.TrailingZeros64`,
`bits.Len64`, and `bits.OnesCount64`); `XOR` is bitwise exclusive-or;
`bit(x, i)` reads bit `i` of `x` (0 = least significant). `first - 1` when
`first == 0` is not reached, because that case returns earlier.

Both algorithms above are validated in the IFF repository by an
independent test implementation (`internal/log`'s test suite) checked
against every tree size from 1 to 300 leaves and a wide spread of
first/second pairs — not merely round-tripped against the same code that
constructs the proofs.

A live verifier needs a retained or independently witnessed earlier STH to
make §6.2 meaningful. Fetching two STHs and their proof from the same log in
one unauthenticated session checks the Merkle arithmetic, but does not detect
a view the log shows only to that verifier. The reference verifier therefore
supports a durable checkpoint file: it advances the checkpoint only after
the current STH, full tree, inclusion proof, and consistency proof have all
verified.

## 7. Key transparency

`GET /api/v3/log/keys` (§9.6) returns every contiguous log-key activation
epoch (so a key reactivated after another key appears again as a new epoch),
and every monitor public key that has ever appeared in a sequenced observation:

```json
{
  "log_keys": [
    {"log_id": "7eb8000c99b6e474b553fa38757d76fa", "public_key": "base64...", "valid_from": "2026-08-29T00:00:00Z", "valid_to": null}
  ],
  "monitor_keys": [
    {"monitor_id": "iff-monitor-1", "public_key": "base64...", "first_seen": "2026-08-29T00:00:00Z", "last_seen": "2026-08-29T12:00:00Z"}
  ]
}
```

`valid_to: null` (the field may also be omitted) means the key is still
active — it signed the most recently issued STH. A verifier checking an
STH should confirm the key it verified against was valid (its `valid_from`
is at or before the STH's `timestamp`, and its `valid_to` is either absent
or after that timestamp) rather than assuming a single, unchanging key
forever.

This endpoint is key-transparency metadata, not an out-of-band trust anchor.
Consumers still pin expected log-key fingerprints as required by §5.3.

Both epoch lists are derived, not separately stored, so a compatible log
must be able to reconstruct them from what it already persists:

- A `log_keys` entry's `valid_from` is the `timestamp` of the first STH in
  that contiguous `(log_id, public_key)` activation. Its `valid_to`, when
  present, is the `valid_from` of the next key epoch — i.e. the moment a
  different key's first STH appears — not necessarily the timestamp of the
  last STH this key itself signed. If an earlier key is reactivated after a
  different key, it appears again as a new entry rather than extending its
  old interval. `valid_to` is absent (`null`) for exactly the epoch that signed
  the STH currently returned by `GET /api/v3/log/sth` (§9.1).
- A `monitor_keys` entry's `first_seen`/`last_seen` are the minimum and
  maximum `observed_at` (§3) across every observation report bearing that
  `(monitor_id, monitor_public_key)` pair with a sequencable `probe_type`
  (`initial`, `scheduled`, or `discovery` — the same eligibility §4.1
  uses; `manual` reports never count, whether or not the underlying
  observation has actually been sequenced into the log yet). A monitor
  that has only ever submitted `manual` observations does not appear in
  `monitor_keys` at all.

## 8. Anchoring record

Periodically, the log operator publishes its most recent STH's identity
on-chain, as evidence-oriented reputation feedback under [ERC-8004]'s
reputation registry (the same mechanism this system uses for per-endpoint
daily evidence manifests, distinguished by tag):

| On-chain field | Value |
|---|---|
| `agentID` | The log operator's own ERC-8004 agent ID — never an observed endpoint's owner's agent. |
| `value` / `valueDecimals` | `1` / `0` — a binary "this evidence exists" signal, never a score. |
| `tag1` | `x402-monitoring` |
| `tag2` | `log-tree-head` |
| `endpoint` | The log's own base URL, e.g. `https://ifandonlyif.io/api/v3/log`. |
| `feedbackURI` | The specific STH's URL, e.g. `https://ifandonlyif.io/api/v3/log/sth/8`. |
| `feedbackHash` | The anchored STH's `sth_keccak256` (§5.2), as raw 32 bytes. |

A verifier that trusts a given ERC-8004 agent ID as "the real IFF log" can
use this record to confirm that a specific `tree_size`'s STH — fetched
independently over HTTPS from `feedbackURI` — was the one the operator
committed to on-chain at that time, without having to trust the HTTPS
transport alone. This is a checkpoint mechanism (the same role Certificate
Transparency's gossip/monitoring ecosystem plays), not a claim that
anything referenced from the log is safe to transact with.

## 9. API reference

All endpoints below are public, unauthenticated, `GET`, and cacheable
(each response carries a `Cache-Control: public, max-age=N` header — the
values noted are current defaults, not part of the wire format). Error
responses are `{"error": true, "message": "..."}` with a `4xx`/`5xx`
status; this system's public log/evidence surface never includes an
`error_code` field (that field exists only in owner-authenticated,
non-public responses elsewhere in the product).

### 9.1 `GET /api/v3/log/sth`

The most recently published STH (§5), as a JSON object with keys `log_id,
tree_size, timestamp, root_hash, sha256_hash, keccak256_hash, signature,
public_key`. `404` if no STH has ever been published.

### 9.2 `GET /api/v3/log/sth/:tree_size`

The STH published for exactly this `tree_size`. Same shape as §9.1. `404`
if no STH exists at that exact size (§5.4).

### 9.3 `GET /api/v3/log/entries?start=&end=`

Log entries in the half-open range `[start, end)`, ordered by `log_index`.
`end - start` is capped at 1000 (a request for more receives a truncated
`end`, not an error). Response:

```json
{"start": 0, "end": 2, "entries": [ { "...": "one entry, shape below" } ]}
```

Each entry:

```json
{
  "log_index": 0,
  "leaf_hash": "64-hex-chars",
  "observation_id": "uuid",
  "endpoint_id": "uuid",
  "endpoint_url": "https://api.example.com/v1/quote",
  "report_hash": "64-hex-chars",
  "observed_at": "2026-08-29T12:00:00Z",
  "probe_type": "scheduled",
  "monitor_id": "iff-monitor-1",
  "status_code": 402,
  "reachable": true,
  "protocol_status": "pass",
  "set_fingerprint": "64-hex-chars-or-null"
}
```

This is the complete, fixed field set — nothing else is ever present, and
`probe_type` is never `manual` (§3, §4.1). `set_fingerprint` is present as
JSON `null`, never omitted, when the observation had no payment options to
fingerprint (§1.3). `observed_at` here (and every other timestamp field
this API surface returns) is RFC 3339 in UTC, at **whatever fractional-
second precision the value happens to serialize at** — it may have no
fractional digits, six of them, or anything in between; a verifier must
parse it as general RFC 3339, not assume a fixed width. Only §3's
canonical report form fixes the exact six-digit format, and only because
that exact byte sequence feeds a hash (`report_hash`) — a concern that
does not apply to a plain API response field.

### 9.4 `GET /api/v3/log/proof/inclusion?observation_id=<uuid>|leaf_hash=<hex>&tree_size=<n>`

An inclusion proof (§6.1) for one entry, identified by exactly one of
`observation_id` or `leaf_hash`. `tree_size` is optional and defaults to
the current log size; if given, it must be at least `log_index + 1` and at
most the current log size.

```json
{"log_index": 5, "tree_size": 8, "audit_path": ["64-hex-chars", "..."]}
```

`404` if the identified entry does not exist (or has not been sequenced
yet).

### 9.5 `GET /api/v3/log/proof/consistency?first=<n>&second=<n>`

A consistency proof (§6.2) between two tree sizes, `0 <= first <= second
<= <current log size>`.

```json
{"proof": ["64-hex-chars", "..."]}
```

### 9.6 `GET /api/v3/log/keys`

See §7.

## 10. Test vectors

Two checked-in vector files accompany this specification:

- `spec/testdata/fingerprint_vectors.json` — requirement
  fingerprint (§1) known-answer vectors: option sets, expected
  `set_fingerprint` and `option_fingerprints`, and relational assertions
  (e.g. a case-variant must equal its baseline, a base58 case change must
  not).
- `spec/testdata/log_vectors.json` — a worked example for the
  transparency log (§4–§6): eight leaves with their `report_hash`/
  `leaf_hash` values, the resulting `tree_size=8` root, one inclusion
  proof (`log_index=5`), one consistency proof (`first=6, second=8`,
  including the `first`-sized root so a verifier does not need to
  recompute it), and one STH signed over the full tree. The STH's signing
  key is a published, non-secret Ed25519 seed
  (`test_private_key_seed_base64` in the file) used only for this vector
  — a real log's signing key is never published.

Both files are generated and re-verified by the IFF repository's own test
suite (`internal/log`'s `TestSpecVectorsGenerateAndVerify` for the second
file), so they stay byte-for-byte in sync with the reference
implementation; a compatible implementation should be able to reproduce
every value in `log_vectors.json` from its `leaves` alone, and should
independently verify (not merely re-derive) its `inclusion_proof`,
`consistency_proof`, and `signed_tree_head` using §6's algorithms.

### 10.1 Runnable conformance example

`spec/verify_example.py`, alongside this document, is a dependency-light
(Python standard library only, including a from-scratch Ed25519 verifier)
reference verifier that implements exactly §4–§6's algorithms against a
*running* log rather than the static vectors above: it fetches
`GET /api/v3/log/sth`, `GET /api/v3/log/entries`, and
`GET /api/v3/log/proof/inclusion` from a configurable base URL (default
`https://ifandonlyif.io`), then checks the STH's canonical bytes and
Ed25519 signature (§5), recomputes the Merkle tree root from every fetched
entry (§4.4) against the STH's `root_hash`, and verifies one inclusion
proof (§6.1). `python3 spec/verify_example.py --self-test` runs the
same logic offline against `log_vectors.json` instead, with no network
access. It imports nothing from IFF's monitor implementation; a reader
does not need this repository's source to trust what it checks, only this
specification.

One detail worth calling out for any other implementation: `GET
/api/v3/log/sth`'s `timestamp` field is not guaranteed to already be
formatted in the exact six-fractional-digit form canonical bytes require
(§5.1) — like every other timestamp this API surface returns (§9.3), it
may serialize with fewer fractional digits when trailing digits are zero.
A verifier must reformat the parsed timestamp value into that exact form
before computing canonical bytes, never assume the API's raw string
already is that form. `verify_example.py`'s `normalize_timestamp` is a
worked example of doing this correctly; it was found necessary by running
this exact check against production.

## Appendix A: worked example

From `spec/testdata/log_vectors.json` (§10): leaf 0's `report_hash` is
`SHA-256("iff-log-vector-leaf-0")`. Its `leaf_hash` is
`SHA-256(0x00 || report_hash_bytes)`. The tree's root at `tree_size=8` is
the value in `root_hash`. The inclusion proof for `log_index=5` is a
3-element `audit_path`; running §6.1's algorithm with `leaf_hash =
leaves[5].leaf_hash`, `log_index = 5`, `tree_size = 8`, and that
`audit_path` against `root_hash` must return `true`. The consistency proof
between `first=6` and `second=8` is a 3-element `proof`; running §6.2's
algorithm with `first_root = first_root_hash` and `second_root = root_hash`
must also return `true`. The `signed_tree_head` object's `sth_body` is the
exact canonical bytes (§5.1) for `tree_size=8`; `SHA-256(sth_body)` must
equal `sha256_hash`, and `Ed25519-Verify(public_key, sha256_hash,
signature)` must succeed.

[ERC-8004]: https://eips.ethereum.org/EIPS/eip-8004
