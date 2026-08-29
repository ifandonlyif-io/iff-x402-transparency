#!/usr/bin/env python3
"""Reference verifier for x402-requirement-transparency-v1.md.

Fetches a log's current signed tree head (STH), every sequenced entry it
commits to, and one inclusion proof, then independently verifies:

  1. The STH's canonical bytes reproduce its own sha256_hash (spec Sec. 5.1).
  2. The STH's log_id is hex(SHA-256(public_key)[:16]) (spec Sec. 5.3).
  3. The STH's Ed25519 signature over that sha256_hash is valid (Sec. 5.2).
  4. Every entry's leaf_hash is SHA-256(0x00 || report_hash) (Sec. 4.2).
  5. The Merkle Tree Hash (Sec. 4.4) recomputed from all leaves equals the
     STH's root_hash.
  6. One inclusion proof verifies against that root_hash (Sec. 6.1).
  7. When --checkpoint is supplied, the current tree is an append-only
     extension of the previously trusted tree (Sec. 6.2).

This script is intentionally self-contained: it imports nothing from the
IFF codebase, and its only third-party dependency is the Python standard
library (including a from-scratch Ed25519 verifier, since verifying an
Ed25519 signature is not itself in the standard library). A third party
should be able to read this file next to the spec and convince themselves
both that it implements exactly what the spec says, and that it works
against the real, running log.

Usage:

    python3 verify_example.py                          # verify production
    python3 verify_example.py --checkpoint ~/.iff-production-sth.json
    python3 verify_example.py --base-url http://localhost:8080 \
      --allow-untrusted-key                            # local development only
    python3 verify_example.py --base-url https://log.example \
      --trusted-log-key LOG_ID=PUBLIC_KEY_SHA256
    python3 verify_example.py --self-test              # offline, uses
                                                         # testdata/log_vectors.json,
                                                         # no network access

Note on HTTP: Cloudflare (which fronts ifandonlyif.io) rejects Python
urllib's default User-Agent header with an HTTP 403. This script always
sends an explicit, descriptive User-Agent to avoid that -- see USER_AGENT
below. If you port this logic to another HTTP client, keep that in mind.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import sys
import tempfile
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

DEFAULT_BASE_URL = "https://ifandonlyif.io"

# Cloudflare blocks requests whose User-Agent looks like a bare scripting
# library's default (e.g. "Python-urllib/3.x") with a 403. Any descriptive,
# non-empty User-Agent avoids that; this one also self-identifies for
# anyone reading IFF's access logs.
USER_AGENT = "iff-spec-verify-example/1 (+https://github.com/ifandonlyif-io/iff-x402-transparency)"

REQUEST_TIMEOUT_SECONDS = 15

# A 1000-entry page is currently well below this limit. The cap is applied
# before JSON decoding so a verifier cannot be made to buffer an unbounded
# response from either a compromised log or a mistyped --base-url.
MAX_JSON_RESPONSE_BYTES = 8 * 1024 * 1024

# The API caps a single /log/entries page at 1000 rows (spec Sec. 9.3).
ENTRIES_PAGE_SIZE = 1000

# Trust anchors are intentionally carried in the independently distributed
# verifier, not learned from the same API response whose signature is being
# checked. The value is SHA-256(raw Ed25519 public key), lowercase hex. A key
# rotation requires a reviewed verifier release that retains old keys for
# historical checkpoints and adds the new key through a trusted channel.
PRODUCTION_TRUSTED_LOG_KEYS = {
    "e33f4a64fe0ef33fca5cbfddce858667": (
        "e33f4a64fe0ef33fca5cbfddce858667"
        "ee56be6347c6cf7ffcda9d1bceaffe5b"
    ),
}


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------


def http_get_json(url: str) -> dict:
    request = Request(
        url,
        headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
    )
    try:
        with urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
            body = response.read(MAX_JSON_RESPONSE_BYTES + 1)
    except HTTPError as exc:
        detail = exc.read()[:300]
        raise RuntimeError(f"GET {url} -> HTTP {exc.code}: {detail!r}") from exc
    except URLError as exc:
        raise RuntimeError(f"GET {url} -> {exc}") from exc
    if len(body) > MAX_JSON_RESPONSE_BYTES:
        raise RuntimeError(
            f"GET {url} -> response exceeds {MAX_JSON_RESPONSE_BYTES} bytes"
        )
    try:
        decoded = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"GET {url} -> invalid JSON response") from exc
    if not isinstance(decoded, dict):
        raise RuntimeError(f"GET {url} -> expected a JSON object")
    return decoded


# ---------------------------------------------------------------------------
# RFC 6962 Merkle hashing (spec Sec. 4)
# ---------------------------------------------------------------------------


def leaf_hash_from_report_hash(report_hash_hex: str) -> bytes:
    """spec Sec. 4.2: leaf_hash(entry) = SHA-256(0x00 || report_hash)."""
    report_hash = bytes.fromhex(report_hash_hex)
    return hashlib.sha256(b"\x00" + report_hash).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    """spec Sec. 4.3: node_hash(left, right) = SHA-256(0x01 || left || right)."""
    return hashlib.sha256(b"\x01" + left + right).digest()


def merkle_tree_hash(leaves: list[bytes]) -> bytes:
    """spec Sec. 4.4: MTH, the recursive Merkle Tree Hash over an ordered
    list of leaf hashes. Empty tree is SHA-256("") with no domain byte."""
    n = len(leaves)
    if n == 0:
        return hashlib.sha256(b"").digest()
    if n == 1:
        return leaves[0]
    k = 1
    while k * 2 < n:
        k *= 2
    return node_hash(merkle_tree_hash(leaves[:k]), merkle_tree_hash(leaves[k:]))


def verify_inclusion(
    leaf: bytes,
    log_index: int,
    tree_size: int,
    audit_path: list[bytes],
    root_hash: bytes,
) -> bool:
    """spec Sec. 6.1, transcribed directly from the pseudocode."""
    if not (0 <= log_index < tree_size):
        return False

    node_index = log_index
    last_index = tree_size - 1
    current = leaf
    path_pos = 0

    while last_index > 0:
        if node_index % 2 == 1:
            if path_pos >= len(audit_path):
                return False
            current = node_hash(audit_path[path_pos], current)
            path_pos += 1
        elif node_index < last_index:
            if path_pos >= len(audit_path):
                return False
            current = node_hash(current, audit_path[path_pos])
            path_pos += 1
        # else: node_index == last_index and even -- promoted unchanged,
        # no audit_path entry consumed.
        node_index //= 2
        last_index //= 2

    return path_pos == len(audit_path) and current == root_hash


def _trailing_zero_bits(value: int) -> int:
    """Returns the number of low zero bits in a positive integer."""
    return (value & -value).bit_length() - 1


def verify_consistency(
    first: int,
    second: int,
    proof: list[bytes],
    first_root: bytes,
    second_root: bytes,
) -> bool:
    """spec Sec. 6.2, transcribed directly from the pseudocode."""
    if not (0 <= first <= second):
        return False
    if first == second:
        return len(proof) == 0 and first_root == second_root
    if first == 0:
        return len(proof) == 0

    shift = _trailing_zero_bits(first)
    first_is_power_of_two = first == (1 << shift)
    if first_is_power_of_two:
        seed = first_root
        remaining = proof
    else:
        if not proof:
            return False
        seed = proof[0]
        remaining = proof[1:]

    inner = ((first - 1) ^ (second - 1)).bit_length() - shift
    if inner < 0:
        return False
    mask = (first - 1) >> shift

    expected = inner + ((second - 1) >> (inner + shift)).bit_count()
    if not first_is_power_of_two:
        expected += 1
    if len(proof) != expected:
        return False

    border = remaining[inner:]

    hash1 = seed
    for i in range(inner):
        if (mask >> i) & 1:
            hash1 = node_hash(remaining[i], hash1)
    for sibling in border:
        hash1 = node_hash(sibling, hash1)
    if hash1 != first_root:
        return False

    hash2 = seed
    for i in range(inner):
        if (mask >> i) & 1:
            hash2 = node_hash(remaining[i], hash2)
        else:
            hash2 = node_hash(hash2, remaining[i])
    for sibling in border:
        hash2 = node_hash(sibling, hash2)
    return hash2 == second_root


# ---------------------------------------------------------------------------
# Ed25519 verification (RFC 8032), implemented from scratch: the standard
# library has no Ed25519 primitive, and this script deliberately carries no
# third-party dependency (spec Sec. 5.2's signatures, and the log_vectors.json
# self-test's signed_tree_head, both need it).
# ---------------------------------------------------------------------------

_P = 2**255 - 19
_D = (-121665 * pow(121666, _P - 2, _P)) % _P
_SQRT_MINUS_ONE = pow(2, (_P - 1) // 4, _P)
_L = 2**252 + 27742317777372353535851937790883648493  # base-point order


def _inv(x: int) -> int:
    return pow(x, _P - 2, _P)


def _recover_x(y: int, sign: int) -> int:
    """Given a curve point's y-coordinate and the low bit of x, recover x.
    Raises ValueError if y does not correspond to a point on the curve."""
    x2 = (y * y - 1) * _inv(_D * y * y + 1) % _P
    if x2 == 0:
        if sign:
            raise ValueError("invalid point encoding")
        return 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = (x * _SQRT_MINUS_ONE) % _P
    if (x * x - x2) % _P != 0:
        raise ValueError("y is not the coordinate of a curve point")
    if (x & 1) != sign:
        x = _P - x
    return x


def _point_add(p: tuple[int, int], q: tuple[int, int]) -> tuple[int, int]:
    x1, y1 = p
    x2, y2 = q
    denom_common = _D * x1 * x2 * y1 * y2
    x3 = (x1 * y2 + x2 * y1) * _inv(1 + denom_common) % _P
    y3 = (y1 * y2 + x1 * x2) * _inv(1 - denom_common) % _P
    return (x3, y3)


def _scalar_mult(p: tuple[int, int], e: int) -> tuple[int, int]:
    if e == 0:
        return (0, 1)
    q = _scalar_mult(p, e // 2)
    q = _point_add(q, q)
    if e & 1:
        q = _point_add(q, p)
    return q


def _is_on_curve(p: tuple[int, int]) -> bool:
    x, y = p
    return (-x * x + y * y - 1 - _D * x * x * y * y) % _P == 0


def _decode_point(data: bytes) -> tuple[int, int]:
    if len(data) != 32:
        raise ValueError("point must be 32 bytes")
    sign = data[31] >> 7
    y = int.from_bytes(data, "little") & ((1 << 255) - 1)
    x = _recover_x(y, sign)
    point = (x, y)
    if not _is_on_curve(point):
        raise ValueError("decoded point is not on the curve")
    return point


_BASE_Y = (4 * _inv(5)) % _P
_BASE = (_recover_x(_BASE_Y, 0), _BASE_Y)


def ed25519_verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """RFC 8032 Sec. 5.1.7. Returns False for any malformed or invalid
    input rather than raising -- callers treat "did not verify" uniformly."""
    if len(public_key) != 32 or len(signature) != 64:
        return False
    try:
        a = _decode_point(public_key)
        r = _decode_point(signature[:32])
    except ValueError:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= _L:
        return False
    digest = hashlib.sha512(signature[:32] + public_key + message).digest()
    k = int.from_bytes(digest, "little") % _L
    lhs = _scalar_mult(_BASE, s)
    rhs = _point_add(r, _scalar_mult(a, k))
    return lhs == rhs


# ---------------------------------------------------------------------------
# STH verification (spec Sec. 5)
# ---------------------------------------------------------------------------


def normalize_timestamp(raw: str) -> str:
    """Reformats an RFC 3339 UTC timestamp into the exact microsecond-
    truncated, six-fractional-digit form spec Sec. 3 and Sec. 5.1 require
    inside canonical bytes ("2006-01-02T15:04:05.000000Z").

    This is not optional bookkeeping: the API's own JSON encoding of a
    stored Go time.Time trims trailing zero fractional digits (observed in
    production: a timestamp signed as "...51.569340Z" round-trips through
    the API's JSON as "...51.56934Z" -- one digit short). Sec. 9.3 already
    warns that every timestamp field this API returns may serialize at
    "whatever fractional-second precision the value happens to serialize
    at" and must be parsed as general RFC 3339, not assumed fixed-width;
    the same is true of GET /api/v3/log/sth's own timestamp field, even
    though it feeds a hash. A verifier must therefore always rebuild this
    canonical form from the parsed value, never trust the API's raw string
    to already be in it.
    """
    iso = raw[:-1] + "+00:00" if raw.endswith("Z") else raw
    parsed = datetime.fromisoformat(iso).astimezone(timezone.utc)
    return parsed.strftime("%Y-%m-%dT%H:%M:%S") + f".{parsed.microsecond:06d}Z"


def canonical_sth_bytes(sth: dict) -> bytes:
    """spec Sec. 5.1: exactly these four keys, in this order, no inserted
    whitespace."""
    canonical = {
        "log_id": sth["log_id"],
        "tree_size": sth["tree_size"],
        "timestamp": normalize_timestamp(sth["timestamp"]),
        "root_hash": sth["root_hash"],
    }
    return json.dumps(canonical, separators=(",", ":")).encode("utf-8")


def _decode_base64(value: object, field_name: str, expected_length: int) -> bytes:
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a base64 string")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise ValueError(f"{field_name} is not canonical base64") from exc
    if len(decoded) != expected_length:
        raise ValueError(f"{field_name} must decode to {expected_length} bytes")
    return decoded


def _decode_hash(value: object, field_name: str) -> bytes:
    if not isinstance(value, str) or len(value) != 64 or value.lower() != value:
        raise ValueError(f"{field_name} must be 64 lowercase hex characters")
    try:
        return bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError(f"{field_name} must be 64 lowercase hex characters") from exc


def verify_sth(
    sth: dict,
    trusted_log_keys: dict[str, str],
    allow_untrusted_key: bool = False,
) -> bytes:
    """Runs spec Sec. 5.1-5.3's checks. Returns the canonical bytes on
    success; raises ValueError describing the first failed check."""
    canonical_bytes = canonical_sth_bytes(sth)

    computed_sha256 = hashlib.sha256(canonical_bytes).hexdigest()
    if computed_sha256 != sth["sha256_hash"]:
        raise ValueError(
            f"sha256_hash mismatch: computed {computed_sha256}, "
            f"STH claims {sth['sha256_hash']}"
        )

    public_key = _decode_base64(sth["public_key"], "public_key", 32)
    public_key_sha256 = hashlib.sha256(public_key).hexdigest()
    expected_log_id = public_key_sha256[:32]
    if expected_log_id != sth["log_id"]:
        raise ValueError(
            f"log_id mismatch: hex(sha256(public_key)[:16]) = "
            f"{expected_log_id}, STH claims {sth['log_id']}"
        )

    trusted_fingerprint = trusted_log_keys.get(sth["log_id"])
    if trusted_fingerprint is None and not allow_untrusted_key:
        raise ValueError(
            f"log_id {sth['log_id']} has no trust anchor; pass "
            "--trusted-log-key LOG_ID=PUBLIC_KEY_SHA256, or use "
            "--allow-untrusted-key only for local development"
        )
    if trusted_fingerprint is not None and public_key_sha256 != trusted_fingerprint:
        raise ValueError(
            f"public key fingerprint mismatch for log_id {sth['log_id']}: "
            f"computed {public_key_sha256}, trusted {trusted_fingerprint}"
        )

    signature = _decode_base64(sth["signature"], "signature", 64)
    digest = hashlib.sha256(canonical_bytes).digest()
    if not ed25519_verify(public_key, digest, signature):
        raise ValueError("Ed25519 signature over the STH's sha256_hash is invalid")

    return canonical_bytes


# ---------------------------------------------------------------------------
# Main flow: fetch from a running log and verify everything above.
# ---------------------------------------------------------------------------


def fetch_all_entries(base_url: str, tree_size: int) -> dict[int, dict]:
    """Fetches every entry in [0, tree_size), paginating at the API's
    1000-row cap (spec Sec. 9.3), and returns them keyed by log_index."""
    entries_by_index: dict[int, dict] = {}
    start = 0
    while start < tree_size:
        end = min(start + ENTRIES_PAGE_SIZE, tree_size)
        page = http_get_json(f"{base_url}/api/v3/log/entries?start={start}&end={end}")
        for entry in page["entries"]:
            entries_by_index[entry["log_index"]] = entry
        start = end
    return entries_by_index


def parse_trusted_log_keys(values: list[str]) -> dict[str, str]:
    trusted = dict(PRODUCTION_TRUSTED_LOG_KEYS)
    for value in values:
        try:
            log_id, fingerprint = value.split("=", 1)
        except ValueError as exc:
            raise ValueError(
                "--trusted-log-key must be LOG_ID=PUBLIC_KEY_SHA256"
            ) from exc
        if len(log_id) != 32 or log_id.lower() != log_id:
            raise ValueError("trusted LOG_ID must be 32 lowercase hex characters")
        if len(fingerprint) != 64 or fingerprint.lower() != fingerprint:
            raise ValueError(
                "trusted PUBLIC_KEY_SHA256 must be 64 lowercase hex characters"
            )
        try:
            bytes.fromhex(log_id)
            bytes.fromhex(fingerprint)
        except ValueError as exc:
            raise ValueError("trusted key values must be lowercase hexadecimal") from exc
        if fingerprint[:32] != log_id:
            raise ValueError(
                "trusted LOG_ID must equal the first 16 bytes of PUBLIC_KEY_SHA256"
            )
        existing = trusted.get(log_id)
        if existing is not None and existing != fingerprint:
            raise ValueError(f"conflicting trusted fingerprints for log_id {log_id}")
        trusted[log_id] = fingerprint
    return trusted


def load_checkpoint(path: str, base_url: str) -> dict | None:
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as handle:
            checkpoint = json.load(handle)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read checkpoint {path}: {exc}") from exc
    if not isinstance(checkpoint, dict) or not isinstance(checkpoint.get("sth"), dict):
        raise ValueError(f"checkpoint {path} has an invalid shape")
    if checkpoint.get("base_url") != base_url:
        raise ValueError(
            f"checkpoint {path} belongs to {checkpoint.get('base_url')!r}, "
            f"not {base_url!r}"
        )
    return checkpoint["sth"]


def save_checkpoint(path: str, base_url: str, sth: dict) -> None:
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    payload = {"base_url": base_url, "sth": sth}
    fd, temporary_path = tempfile.mkstemp(prefix=".iff-sth-", dir=directory, text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, separators=(",", ":"), sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)
    except BaseException:
        try:
            os.unlink(temporary_path)
        except FileNotFoundError:
            pass
        raise


def verify_checkpoint_consistency(
    base_url: str,
    previous_sth: dict,
    current_sth: dict,
    trusted_log_keys: dict[str, str],
    allow_untrusted_key: bool,
) -> None:
    verify_sth(previous_sth, trusted_log_keys, allow_untrusted_key)
    first = previous_sth["tree_size"]
    second = current_sth["tree_size"]
    if not isinstance(first, int) or not isinstance(second, int) or first < 0:
        raise ValueError("checkpoint tree_size values must be non-negative integers")
    if first > second:
        raise ValueError(
            f"log shrank from checkpoint tree_size {first} to current tree_size {second}"
        )

    proof: list[bytes] = []
    if first < second and first > 0:
        proof_url = (
            f"{base_url}/api/v3/log/proof/consistency"
            f"?first={first}&second={second}"
        )
        print(f"GET {proof_url}")
        response = http_get_json(proof_url)
        if not isinstance(response.get("proof"), list):
            raise ValueError("consistency response proof must be an array")
        proof = [_decode_hash(item, "consistency proof hash") for item in response["proof"]]

    if not verify_consistency(
        first,
        second,
        proof,
        _decode_hash(previous_sth["root_hash"], "checkpoint root_hash"),
        _decode_hash(current_sth["root_hash"], "current root_hash"),
    ):
        raise ValueError(
            f"consistency proof failed from tree_size {first} to {second}"
        )
    print(f"  [OK] append-only consistency verifies from tree_size={first} to {second}")


def run_against_api(
    base_url: str,
    trusted_log_keys: dict[str, str],
    allow_untrusted_key: bool,
    checkpoint_path: str | None,
) -> None:
    base_url = base_url.rstrip("/")

    print(f"GET {base_url}/api/v3/log/sth")
    sth = http_get_json(f"{base_url}/api/v3/log/sth")
    verify_sth(sth, trusted_log_keys, allow_untrusted_key)
    tree_size = sth["tree_size"]
    if not isinstance(tree_size, int) or isinstance(tree_size, bool) or tree_size < 0:
        raise ValueError("tree_size must be a non-negative integer")
    root_hash = _decode_hash(sth["root_hash"], "root_hash")
    print(f"  [OK] canonical bytes reproduce sha256_hash {sth['sha256_hash']}")
    print(f"  [OK] log_id = hex(sha256(public_key)[:16]) = {sth['log_id']}")
    print(f"  [OK] Ed25519 signature valid under a pinned public-key fingerprint")
    print(f"  tree_size = {tree_size}")

    previous_sth = None
    if checkpoint_path is not None:
        previous_sth = load_checkpoint(checkpoint_path, base_url)
        if previous_sth is None:
            print(f"  [NOTE] {checkpoint_path} does not exist; this run establishes it")
        else:
            verify_checkpoint_consistency(
                base_url,
                previous_sth,
                sth,
                trusted_log_keys,
                allow_untrusted_key,
            )

    if tree_size == 0:
        print("Log is empty (tree_size = 0); nothing further to verify.")
        if checkpoint_path is not None:
            save_checkpoint(checkpoint_path, base_url, sth)
        return

    print(f"GET {base_url}/api/v3/log/entries (tree_size={tree_size}, paginated)")
    entries_by_index = fetch_all_entries(base_url, tree_size)
    if len(entries_by_index) != tree_size:
        raise ValueError(
            f"expected {tree_size} entries, fetched {len(entries_by_index)}"
        )

    leaves: list[bytes] = []
    for index in range(tree_size):
        entry = entries_by_index[index]
        leaf = leaf_hash_from_report_hash(entry["report_hash"])
        if leaf.hex() != entry["leaf_hash"]:
            raise ValueError(
                f"leaf_hash mismatch at log_index {index}: "
                f"recomputed {leaf.hex()}, entry claims {entry['leaf_hash']}"
            )
        leaves.append(leaf)
    print(f"  [OK] recomputed leaf_hash for all {tree_size} entries from report_hash")

    computed_root = merkle_tree_hash(leaves)
    if computed_root != root_hash:
        raise ValueError(
            f"Merkle root mismatch: recomputed {computed_root.hex()}, "
            f"STH claims {sth['root_hash']}"
        )
    print(f"  [OK] recomputed Merkle tree root matches STH root_hash {sth['root_hash']}")

    target_index = tree_size - 1
    target_entry = entries_by_index[target_index]
    proof_url = (
        f"{base_url}/api/v3/log/proof/inclusion"
        f"?observation_id={target_entry['observation_id']}&tree_size={tree_size}"
    )
    print(f"GET {proof_url}")
    proof = http_get_json(proof_url)
    audit_path = [bytes.fromhex(h) for h in proof["audit_path"]]
    ok = verify_inclusion(
        leaves[target_index], proof["log_index"], proof["tree_size"], audit_path, root_hash
    )
    if not ok:
        raise ValueError(f"inclusion proof failed to verify for log_index={target_index}")
    print(
        f"  [OK] inclusion proof verifies for log_index={target_index} "
        f"(observation_id={target_entry['observation_id']}) against tree_size={tree_size}"
    )

    print()
    print("All checks passed.")
    if checkpoint_path is not None:
        save_checkpoint(checkpoint_path, base_url, sth)
        print(f"Checkpoint updated atomically: {checkpoint_path}")
    else:
        print(
            "Append-only history was not checked: pass --checkpoint PATH and "
            "retain that file between runs."
        )


# ---------------------------------------------------------------------------
# Offline self-test against spec/testdata/log_vectors.json -- exercises
# the same functions above with no network access, useful for confirming
# this script's own logic (independent of whether production is reachable)
# before trusting its verdict about a live log.
# ---------------------------------------------------------------------------


def run_self_test() -> None:
    vectors_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "testdata", "log_vectors.json")
    print(f"Loading {vectors_path}")
    with open(vectors_path, "r", encoding="utf-8") as handle:
        vectors = json.load(handle)

    leaves = []
    for leaf_entry in vectors["leaves"]:
        leaf = leaf_hash_from_report_hash(leaf_entry["report_hash"])
        if leaf.hex() != leaf_entry["leaf_hash"]:
            raise ValueError(f"leaf {leaf_entry['index']}: leaf_hash mismatch")
        leaves.append(leaf)
    print(f"  [OK] recomputed leaf_hash for all {len(leaves)} vector leaves")

    root_hash = bytes.fromhex(vectors["root_hash"])
    computed_root = merkle_tree_hash(leaves)
    if computed_root != root_hash:
        raise ValueError("vector Merkle root mismatch")
    print(f"  [OK] recomputed Merkle tree root matches vector root_hash {vectors['root_hash']}")

    inclusion = vectors["inclusion_proof"]
    audit_path = [bytes.fromhex(h) for h in inclusion["audit_path"]]
    ok = verify_inclusion(
        leaves[inclusion["log_index"]], inclusion["log_index"], inclusion["tree_size"], audit_path, root_hash
    )
    if not ok:
        raise ValueError("vector inclusion_proof failed to verify")
    print(f"  [OK] vector inclusion_proof verifies for log_index={inclusion['log_index']}")

    consistency = vectors["consistency_proof"]
    consistency_path = [bytes.fromhex(h) for h in consistency["proof"]]
    ok = verify_consistency(
        consistency["first"],
        consistency["second"],
        consistency_path,
        bytes.fromhex(consistency["first_root_hash"]),
        root_hash,
    )
    if not ok:
        raise ValueError("vector consistency_proof failed to verify")
    print(
        "  [OK] vector consistency_proof verifies append-only extension "
        f"from tree_size={consistency['first']} to {consistency['second']}"
    )

    sth = vectors["signed_tree_head"]
    vector_key = _decode_base64(sth["public_key"], "public_key", 32)
    vector_fingerprint = hashlib.sha256(vector_key).hexdigest()
    canonical_bytes = verify_sth(sth, {sth["log_id"]: vector_fingerprint})
    if canonical_bytes != sth["sth_body"].encode("utf-8"):
        raise ValueError("vector sth_body does not match recomputed canonical bytes")
    print("  [OK] vector signed_tree_head verifies (canonical bytes, log_id, Ed25519 signature)")

    print()
    print("Self-test passed: this script's Merkle, leaf-hash, and Ed25519")
    print("logic reproduces every value in log_vectors.json.")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--base-url",
        default=DEFAULT_BASE_URL,
        help=f"log API base URL (default: {DEFAULT_BASE_URL})",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="verify spec/testdata/log_vectors.json offline instead of calling --base-url",
    )
    parser.add_argument(
        "--trusted-log-key",
        action="append",
        default=[],
        metavar="LOG_ID=PUBLIC_KEY_SHA256",
        help=(
            "add a trusted log signing-key fingerprint; may be repeated. "
            "The production key is pinned in this verifier by default"
        ),
    )
    parser.add_argument(
        "--allow-untrusted-key",
        action="store_true",
        help="accept a self-asserted STH key (local development only)",
    )
    parser.add_argument(
        "--checkpoint",
        metavar="PATH",
        help=(
            "persist a verified STH and, on later runs, verify append-only "
            "consistency before atomically advancing it"
        ),
    )
    args = parser.parse_args()

    try:
        if args.self_test:
            run_self_test()
        else:
            trusted_log_keys = parse_trusted_log_keys(args.trusted_log_key)
            run_against_api(
                args.base_url,
                trusted_log_keys,
                args.allow_untrusted_key,
                args.checkpoint,
            )
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"FAILED: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
