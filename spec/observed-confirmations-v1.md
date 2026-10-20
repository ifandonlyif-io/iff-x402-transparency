# Observed-tier Confirmations — v1

Status: Draft v1. Owner: IFF (ifandonlyif.io).

This document specifies how a monitor records the **observed tier** of x402
endpoints (endpoints it found through discovery rather than through owner
registration) as change events plus daily confirmation statistics, and how a
third party independently checks those statistics. It extends
[x402 Requirement Transparency — v1](https://github.com/ifandonlyif-io/iff-x402-transparency/blob/main/spec/x402-requirement-transparency-v1.md)
("the transparency spec"): requirement fingerprints, observation reports, the
RFC 6962 log, signed tree heads (STHs), proofs, and anchoring records are
defined there and are unchanged here.

The key words MUST, MUST NOT, SHOULD, and MAY are to be interpreted as in
RFC 2119.

## 0. Scope and non-goals

This specification covers:

- The classification of one observed-tier probe result (§1).
- A canonical, recomputable observed **state key** (§2).
- **Episodes**: runs of identical observed state (§3).
- The canonical **daily confirmation document** for one UTC accounting day
  (§4) and its **document leaf** in the transparency log (§5).
- The **commitment levels** `sealed`, `logged`, `anchored` (§6) and the public
  read API (§7).
- The observed evidence-card profile (§8) and the shared freshness rule and
  observed comparison window of `POST /api/v3/verify` (§9).

It deliberately does **not** specify or imply:

- That every scheduled probe actually ran, that no probe was missed, or that
  an endpoint's state never changed between two probes. A daily document is
  the monitor's own confirmation statistics.
- That a payment made against an observed requirement will succeed or is safe
  to make. There is no composite trust score.
- Any attestation of the monitor's execution environment. Monitor and log
  signatures are provenance and tamper-evidence, not attestation.

An anchor bounds when a document existed (no later than the anchoring block);
it does not date the individual probes counted in it.

The verified tier (`initial`/`scheduled` probes of owner-registered endpoints)
is out of scope except for the shared freshness rule (§9.1): every
verified-tier probe remains a stored, signed, logged observation.

## 1. Probe outcome classification

Every observed-tier probe result is classified into exactly one outcome, in
this order:

| Outcome | Condition |
|---|---|
| `no_information` | no HTTP response (`reachable = false`: DNS, TLS, timeout, URL policy), or HTTP status 403 or 429 |
| `valid_requirements` | HTTP 402 with at least one payment option whose requirement fingerprint (transparency spec §1) computes |
| `invalid_requirements` | any other HTTP 402 (options missing or unparseable) |
| `non_402` | any other HTTP response |

`valid_requirements`, `invalid_requirements`, and `non_402` are
**definitive**: they say something about the endpoint. `no_information` does
not; in particular a 403 or 429 is a throttling signal, never evidence that
requirements changed.

## 2. State key (`iff-observed-state-key/v1`)

The state key of one probe is the lowercase hex SHA-256 of the canonical JSON
(§4.2 rules) of this object, with members in exactly this (alphabetical) order:

| Member | Value |
|---|---|
| `check_codes` | the report's check codes, sorted by byte order; never `null` (`[]` when empty) |
| `error_code` | the report's error code, or `null` when empty |
| `monitor_key_id` | `"sha256:" + hex(SHA-256(raw monitor public key))` |
| `protocol_status` | `pass`, `warn`, `fail`, or `unknown` |
| `reachable` | boolean |
| `set_fingerprint` | the set fingerprint (transparency spec §1.3) of a 402 with at least one option whose fingerprint computed, else `null` |
| `status_code` | the HTTP status, or `null` when there was no response |
| `x402_version` | integer, or `null` |

Latency, observation time, and monitor version are not inputs, so two probes
that saw the same thing have the same key. `monitor_key_id` is an input on
purpose: after a monitor key rotation every endpoint stores one new full
observation. A state key MUST be recomputable from the stored signed
observation and its fingerprint row with this algorithm.

## 3. Episodes

An **episode** is one maximal run of probes of one endpoint with the same
state key. Its `episode_id` is the id of the stored observation that opened
it; A→B→A is three episodes, and the two A episodes do not share
confirmation times.

- A probe whose state key differs from the endpoint's open episode (or with no
  open episode) is a **transition**: its signed observation is stored and
  sequenced into the log exactly as before, the open episode closes at the
  probe's time, and a new episode opens.
- A probe with the same state key is a **confirmation**: no observation is
  stored or logged. The open episode's `probes` count increases, its
  `last_probe_at` advances, and for `valid_requirements` its `last_valid_at`
  advances.
- A probe resubmitting the open episode's last-counted signed report, or a
  signed report already stored as an observation (same report hash), is a
  **replay** and changes nothing. With change-only storage, an older
  confirmation whose report was not stored is outside this deduplication
  guarantee: discovery tasks do not retry, and every run signs a fresh report.
- A probe observed earlier than the open episode's `last_probe_at` (a late
  result) with the same state key is counted in the open episode; one with a
  different key is stored as an observation but counted in no episode, and
  the day's document reports it in `uncounted_late_results`.

Every confirmation and transition is also counted in the **UTC accounting
day** in which it was accepted: the database's UTC date at write time, which
need not equal the probe's own UTC date. Implementations MAY store every
probe in full (a shadow mode); the episode and day counts MUST be the same in
both modes.

## 4. Daily confirmation document (`iff-observed-confirmations/v1`)

### 4.1 Sealing

After a UTC accounting day ends, the monitor seals it exactly once into one
document. A day with no counted probe still gets a document with empty
`entries`. Days are sealed in order, so a missed run delays publication but
never skips a day. A sealed document is immutable and MUST NOT be replaced.
Endpoints that have opted out at sealing time are not listed; they are only
counted in `omitted_opted_out_endpoints`.

### 4.2 Canonical encoding

The document body is UTF-8 JSON with:

- members in exactly the order listed in §4.3 (no sorting), no insignificant
  whitespace, and no trailing newline;
- no HTML escaping: `<`, `>`, and `&` appear as themselves; other escaping
  follows Go `encoding/json` (`"`, `\`, and control characters escaped;
  U+2028 and U+2029 written as `\u2028` and `\u2029`);
- integers for every count;
- explicit `null` for an absent optional value (members are never omitted);
- every timestamp in UTC with exactly six fractional digits:
  `YYYY-MM-DDTHH:MM:SS.ffffffZ`;
- `entries` sorted by `url` byte order, and each entry's `episodes` sorted by
  `opened_at`, then `episode_id`.

`document_hash = hex(SHA-256(body))` over the exact bytes. A verifier MUST hash
the bytes it received; it MUST NOT re-encode a parsed document.

### 4.3 Members

Top level, in order:

| Member | Type | Meaning |
|---|---|---|
| `schema` | string | `iff-observed-confirmations/v1` |
| `day` | string | the accounting day, `YYYY-MM-DD` |
| `monitor_id` | string | the sealing monitor |
| `state_key_algorithm` | string | `iff-observed-state-key/v1` |
| `fingerprint_version` | integer | requirement fingerprint version of `set_fingerprint` values |
| `sealed_at` | timestamp | sealing time |
| `endpoint_count` | integer | number of `entries` |
| `omitted_opted_out_endpoints` | integer | endpoints counted that day but opted out at sealing |
| `uncounted_late_results` | integer | different-key late results accepted that day (§3) |
| `totals` | object | `{probes, valid_confirmations, transitions}` summed over `entries`; `transitions` counts episodes with `opened_in_day = true` |
| `entries` | array | one per listed endpoint, never `null` |

Each entry, in order: `url`; `probes`; `reachable`, `protocol_pass`,
`protocol_warn`, `protocol_fail`, `protocol_unknown`, and
`valid_confirmations` (each the sum of the day's `probes` of the episodes with
that reachability, protocol status, or outcome `valid_requirements`);
`first_probe_at`; `last_probe_at`; `episodes`.

Each episode, in order: `episode_id`, `state_key`, `set_fingerprint` (`null`
unless the outcome is `valid_requirements`), `outcome`, `opened_at` (may be
before the day), `opened_in_day`, and the day-scoped `probes`,
`first_probe_at`, `last_probe_at`, and `last_valid_at` (the day's
`last_probe_at` for `valid_requirements`, else `null`). `first_probe_at` may be
before the day's start, because the accounting day is the day a result was
accepted.

Only fields of the public allowlist appear: no latency, no raw requirement
options, no owner data.

## 5. Document leaf

A sealed document enters the transparency log as one leaf of kind
`confirmation_document`:

```text
leaf_data = UTF8("iff-observed-confirmations/v1\n") || document_hash_bytes   (30 + 32 = 62 bytes)
leaf_hash = SHA-256(0x00 || leaf_data)
```

`document_hash_bytes` are the 32 raw bytes of `document_hash`. An observation
leaf's data is the 32-byte report hash (transparency spec §4.2), so the two
leaf kinds can never collide; they share one tree, one STH, and one proof
format, and observation leaf hashes are unchanged. Document leaves are
sequenced with observation leaves in one `(created_at, id)` order.

`GET /api/v3/log/entries` returns, for every entry, `log_index`, `leaf_hash`,
`leaf_type` (`observation` or `confirmation_document`), and `set_fingerprint`
(`null` for a document leaf). Observation entries keep their transparency-spec
fields. A document entry carries `document: {day, document_hash, sealed_at}`
instead of observation fields. A verifier that does not implement this
section SHOULD report a document leaf as unsupported (`unavailable`), never as
invalid.

## 6. Commitment levels

A document's commitment level is derived from existing records only:

| Level | Condition | What it adds |
|---|---|---|
| `sealed` | the document exists | an immutable body and its hash, published by the monitor only |
| `logged` | its leaf has a `log_index`, and some STH has `tree_size > log_index` | an inclusion proof under a log-signed tree head |
| `anchored` | some `confirmed` anchor (transparency spec §8) has `tree_size > log_index` | an on-chain upper bound on when the document existed |

A document can have a `log_index` while still `sealed` (sequenced, but not yet
covered by an STH). For `anchored`, the confirmed anchor with the smallest
covering `tree_size` is reported. Levels only advance; they are a summary
reported by the API, not a verification result.

## 7. Public API

All routes are public, unauthenticated, and answer `HEAD` like `GET`. `:day`
MUST be `YYYY-MM-DD` naming a valid calendar date, else `400`; an unsealed
day is `404`. Errors use `{"error": true, "message": "..."}`.

### 7.1 `GET /api/v3/evidence/observed-confirmations/:day` and `/latest`

`/latest` selects the latest sealed day. Response, in this member order:

```json
{
  "day": "2026-10-20",
  "schema": "iff-observed-confirmations/v1",
  "document_hash": "<64 hex>",
  "sealed_at": "2026-10-21T00:10:03.123450Z",
  "endpoint_count": 1,
  "probe_count": 4,
  "transition_count": 1,
  "leaf": {"leaf_hash": "<64 hex>", "leaf_data_prefix": "iff-observed-confirmations/v1\n", "log_index": 4},
  "commitment": "anchored",
  "anchor": {"chain": "base", "tree_size": 5, "transaction_hash": "0x…", "confirmed_at": "2026-10-22T00:15:42Z"},
  "body_url": "/api/v3/evidence/observed-confirmations/2026-10-20/body",
  "body": {"schema": "iff-observed-confirmations/v1", "…": "…"},
  "disclaimer": "Daily confirmation statistics as observed by the IFF monitor. Not proof that every probe ran, and not a safety, delivery, or payment guarantee."
}
```

`leaf.log_index` and `anchor` are omitted until they exist. `sealed_at` equals
the body's `sealed_at`. `body` embeds the stored body bytes unchanged
(including unescaped `<`, `>`, `&`). Because `commitment`, `leaf.log_index`,
and `anchor` advance after sealing, these responses are cacheable only
briefly (`Cache-Control: public, max-age=300`).

### 7.2 `GET /api/v3/evidence/observed-confirmations/:day/body`

The exact stored body bytes, `Content-Type: application/json; charset=utf-8`,
`ETag: "<document_hash>"`, `Cache-Control: public, max-age=31536000, immutable`.

### 7.3 Verifying a document

1. Fetch `/:day/body` and compute `SHA-256` over the exact bytes; it MUST equal
   `document_hash`, and the body's `schema` and `day` MUST be
   `iff-observed-confirmations/v1` and the requested day.
2. Compute `leaf_hash` per §5 from that hash; it MUST equal `leaf.leaf_hash`.
3. If `leaf.log_index` is present, fetch an STH (transparency spec §9.1) with
   `tree_size > log_index`, verify its signature (§5.2 there), fetch
   `/api/v3/log/proof/inclusion?leaf_hash=<leaf_hash>&tree_size=<tree_size>`,
   and verify the audit path against the STH's `root_hash` (§6.1 there).
4. For `anchored`, check the anchoring record of `anchor.tree_size` on chain
   (§8 there) and a consistency proof from that tree size to the STH used in
   step 3.

Steps 1-3 are what IFF's MCP tool `get_observed_confirmation` reports as
`document_hash_check`, `leaf_hash_check`, `inclusion_proof`, and
`sth_signature`, each `valid`, `invalid`, or `unavailable`; it reports the
commitment level and anchor as server-reported.

## 8. Observed evidence-card profile

An observed-tier card (`tier: observed`, with its fixed disclaimer) differs
from a verified-tier card only as follows.

- **`protocol` and `evidence`** come from the endpoint's last stored signed
  observation and keep its real observation time; an old report is never
  presented as a current success.
- **`availability`** has two windows over UTC accounting days, summed from the
  daily counters: `today` (the current UTC accounting day) and `7d` (today
  plus the six previous accounting days). Each window keeps `window`,
  `samples`, `reachable_rate`, and `protocol_pass_rate` (percentages 0–100,
  two decimals) and adds `basis: "daily_counters"`, `window_start` (the first
  day's `00:00:00Z`), and `window_end` (the exclusive boundary at the next UTC
  day's `00:00:00Z`). Both windows have the same `window_end`, fixed for the
  current accounting day rather than the response time. The current day is
  unfinished, so its counts continue to accumulate within those fixed
  boundaries. Latency percentiles are omitted.
- **`freshness`** keeps `status`, `observed_at` (the last stored
  observation's time), and `interval_seconds`, and adds `reason` (§9.1, only
  when stale), `last_confirmed_at` (T), `last_attempt_at`, and
  `last_attempt_outcome` (the open episode's `last_probe_at` and outcome).
- **`requirements.history`** is derived from `valid_requirements` episodes:
  consecutive episodes with the same `set_fingerprint` merge into one run with
  `first_seen` = earliest `opened_at`, `last_seen` = latest `last_valid_at`,
  and `observations` = the sum of `probes`.

## 9. Freshness and verify

### 9.1 Freshness (both tiers)

```text
W = 2 × probe_interval_seconds + 600
T = time of the last probe with valid requirements (observed: max last_valid_at)
U = time of the last definitive probe (observed: max last_probe_at over
    episodes with a definitive outcome; verified: the last reachable
    observation whose status is not 403 or 429)
```

In order: no T → stale, `reason = never_confirmed`; U later than T → stale,
`reason = current_requirements_unavailable`; T earlier than `now − W` → stale,
`reason = confirmation_expired`; otherwise fresh (T exactly at `now − W`, or U
equal to T, is fresh). `no_information` results never advance U, so a 429
alone never makes an endpoint stale; it only stops renewing T.

### 9.2 `POST /api/v3/verify`

Every response carries `comparison_policy`: `observation-window/v1` for the
verified tier (unchanged per-observation window) and
`observed-confirmation-window/v1` for the observed tier. Responses also carry
`freshness_reason` (when stale), `last_confirmed_at`, `last_attempt_at`, and
`last_attempt_outcome`. The verdict vocabulary is unchanged: `consistent`,
`diverged`, `unobserved`, `stale`.

For the observed tier, with T and freshness as in §9.1:

```text
R = fresh ? max(now, T) : T
L = R − W
eligible = valid_requirements episodes with L <= last_valid_at <= R
         ∪ valid_requirements late results with L <= observed_at <= R
option_union = option fingerprints of the eligible episodes' opening observations (and late results)
payee_union  = amount-blind payee fingerprints of the same observations
```

If the probing worker's clock is ahead of the API's clock, a fresh T can be
later than now. Using `max(now, T)` keeps that confirmation inside its own
window without changing its signed timestamp or widening the window beyond W.

An episode whose `last_valid_at` lies in `[L, R]` had at least one confirmation
in the window, which makes this union equal to a per-probe union without
storing per-probe rows. An endpoint with no T is `unobserved` with
`known = true`; an unknown URL is `unobserved` with `known = false`. When fresh,
each received option is `consistent` or `diverged` against `option_union`, and
the divergence kind uses `payee_union`; when stale, the same comparison runs
with R = T and the verdict stays `stale`. If T exists but no eligible episode
can be read, or an eligible episode lacks its opening observation or
fingerprint, the response is HTTP 503 with
`{"error": true, "code": "comparison_unavailable", ...}` and no verdict:
an incomplete union is never turned into a precise verdict. Only "now" and
"the last valid confirmation T" are supported as the window's right edge.

### 9.3 Existing discovery history during migration

Readers retain pre-episode discovery evidence through a read-only legacy
prefix. With no episode, the prefix contains the endpoint's stored discovery
observations. Once episodes exist, the prefix ends before the database
`created_at` of the first episode's opening observation. This admission-time
boundary prevents shadow confirmations from being counted a second time;
D8 and comparison windows still use the original signed `observed_at`, never
`created_at` as a confirmation time. No observation is rewritten and no
synthetic episode or signed confirmation is backfilled.
The episode-aware writer must be fully deployed and old writer jobs drained
before these readers are enabled. Raw-only writes admitted after that boundary
are not a supported old-writer rollback mode; this prefix is migration
compatibility for retained history, not support for mixed writer generations.

The prefix and episode sources jointly determine T, U, the last attempt,
requirement history, and the eligible comparison union. Thus an opted-out
endpoint with frozen historical requirements remains `stale` after expiry,
not `unobserved`, and a first new non-402 episode does not erase its earlier
T. Legacy rows contribute one original probe each; episode rows contribute
their recorded confirmation counts. Summary and inclusion proof refer to the
same original observation, whether it is a legacy row or an episode opening.

A missing opening, ambiguous admission boundary, or fingerprintable legacy
observation without its required fingerprint makes comparison unavailable.
In particular, an unrepresented raw observation with the exact same
`created_at` as the first opening is not ordered by UUID to guess which came
first. Incomplete evidence is not reported as `never_confirmed`.

The comparison resource bound applies to the combined legacy, episode, and
late-result set. If that complete set exceeds the bound, the API returns
`comparison_unavailable` (HTTP 503), with no verdict, instead of comparing a
silently truncated prefix. The current implementation admits up to 500
eligible observations/episodes/results.

## 10. Test vectors

In [`docs/spec/testdata/`](testdata/):

- `observed_state_key_vectors.json`: state-key test vectors (§2).
- `observed_confirmations_v1/<case>/`: `input.json` (counter rows), `body.json`
  (exact canonical body, no trailing newline), and `document_hash.txt` for
  `empty_day`, `single_endpoint_two_episodes` (escaping and ordering), and
  `opted_out_omitted` (§4).
- `observed_document_leaf_vectors.json`: `document_hash`, 62-byte `leaf_data`
  (hex), and `leaf_hash` (§5), computed independently with Python `hashlib`,
  including the leaves of the three document vectors.

The service's tests read these copies: the document and state-key copies
must equal the implementation's own vectors, and every leaf vector must equal
both of the service's leaf implementations.
