"""Independent standard-library checks of the observed-profile vectors."""

from __future__ import annotations

import base64
from contextlib import redirect_stdout
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path
import unittest
from unittest import mock

import verify_example as verifier


TESTDATA = Path(__file__).parent / "testdata"


def canonical(value: object) -> bytes:
    # Python's ordinary UTF-8 encoder leaves these separators literal; Go's
    # encoding/json escapes them even with HTML escaping disabled.
    return (json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
            .replace("\u2028", "\\u2028").replace("\u2029", "\\u2029").encode("utf-8"))


def utc(value: str) -> str:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc).isoformat(
        timespec="microseconds").replace("+00:00", "Z")


def document_from_input(source: dict) -> dict:
    """Rebuild the document from unsorted daily rows, independently of Go."""
    by_url: dict[str, list[dict]] = {}
    for row in source["rows"] or []:
        by_url.setdefault(row["url"], []).append(row)
    entries = []
    omitted = 0
    for url, rows in sorted(by_url.items(), key=lambda item: item[0].encode("utf-8")):
        if rows[0]["opted_out"]:
            omitted += 1
            continue
        episodes = []
        for row in rows:
            episodes.append({
                "episode_id": row["episode_id"], "state_key": row["state_key"],
                "set_fingerprint": row["set_fingerprint"], "outcome": row["outcome"],
                "opened_at": utc(row["opened_at"]), "opened_in_day": row["opened_in_day"],
                "probes": row["probes"], "first_probe_at": utc(row["first_probe_at"]),
                "last_probe_at": utc(row["last_probe_at"]),
                "last_valid_at": utc(row["last_probe_at"]) if row["outcome"] == "valid_requirements" else None,
            })
        episodes.sort(key=lambda row: (row["opened_at"], row["episode_id"]))
        entries.append({
            "url": url, "probes": sum(row["probes"] for row in rows),
            "reachable": sum(row["probes"] for row in rows if row["reachable"]),
            "protocol_pass": sum(row["probes"] for row in rows if row["protocol_status"] == "pass"),
            "protocol_warn": sum(row["probes"] for row in rows if row["protocol_status"] == "warn"),
            "protocol_fail": sum(row["probes"] for row in rows if row["protocol_status"] == "fail"),
            "protocol_unknown": sum(row["probes"] for row in rows if row["protocol_status"] == "unknown"),
            "valid_confirmations": sum(row["probes"] for row in rows if row["outcome"] == "valid_requirements"),
            "first_probe_at": min(utc(row["first_probe_at"]) for row in rows),
            "last_probe_at": max(utc(row["last_probe_at"]) for row in rows), "episodes": episodes,
        })
    return {
        "schema": "iff-observed-confirmations/v1", "day": source["day"],
        "monitor_id": source["monitor_id"], "state_key_algorithm": "iff-observed-state-key/v1",
        "fingerprint_version": 1, "sealed_at": utc(source["sealed_at"]),
        "endpoint_count": len(entries), "omitted_opted_out_endpoints": omitted,
        "uncounted_late_results": source["uncounted_late_results"],
        "totals": {
            "probes": sum(row["probes"] for row in entries),
            "valid_confirmations": sum(row["valid_confirmations"] for row in entries),
            "transitions": sum(episode["opened_in_day"] for row in entries for episode in row["episodes"]),
        },
        "entries": entries,
    }


class ObservedVectorTest(unittest.TestCase):
    def test_state_key_vectors(self) -> None:
        vectors = json.loads((TESTDATA / "observed_state_key_vectors.json").read_bytes())
        key_id = "sha256:" + hashlib.sha256(base64.b64decode(vectors["monitor_public_key"], validate=True)).hexdigest()
        self.assertEqual(vectors["monitor_key_id"], key_id)
        for vector in vectors["vectors"]:
            with self.subTest(vector=vector["name"]):
                value = vector["input"]
                payload = {
                    "check_codes": sorted(value["check_codes"] or [], key=lambda text: text.encode("utf-8")),
                    "error_code": value["error_code"] or None, "monitor_key_id": key_id,
                    "protocol_status": value["protocol_status"], "reachable": value["reachable"],
                    "set_fingerprint": value["set_fingerprint"] or None,
                    "status_code": value["status_code"] or None, "x402_version": value["x402_version"],
                }
                encoded = canonical(payload)
                self.assertEqual(vector["canonical"].encode("utf-8"), encoded)
                self.assertEqual(vector["state_key"], hashlib.sha256(encoded).hexdigest())

    def test_documents_and_raw_body_hashes(self) -> None:
        for case in sorted((TESTDATA / "observed_confirmations_v1").iterdir()):
            with self.subTest(case=case.name):
                source = json.loads((case / "input.json").read_bytes())
                body = (case / "body.json").read_bytes()
                self.assertEqual(body, canonical(document_from_input(source)))
                self.assertFalse(body.endswith(b"\n"))
                self.assertEqual((case / "document_hash.txt").read_text().strip(), hashlib.sha256(body).hexdigest())
                # A verifier must hash bytes, not a whitespace-normalized parse.
                self.assertNotEqual(hashlib.sha256(body).digest(), hashlib.sha256(body + b"\n").digest())
                schema = json.loads((TESTDATA.parent.parent / "schemas/observed-confirmations-v1.json").read_bytes())
                self.assertEqual(set(schema["required"]), set(json.loads(body)))
                self.assertEqual(list(schema["properties"]), list(json.loads(body)))

    def test_document_leaf_vectors_and_document_binding(self) -> None:
        vectors = json.loads((TESTDATA / "observed_document_leaf_vectors.json").read_bytes())
        self.assertEqual("iff-observed-confirmations/v1\n", vectors["leaf_data_prefix"])
        for vector in vectors["vectors"]:
            with self.subTest(vector=vector["name"]):
                leaf_data = vectors["leaf_data_prefix"].encode() + bytes.fromhex(vector["document_hash"])
                self.assertEqual(vectors["leaf_data_length"], len(leaf_data))
                self.assertEqual(vector["leaf_data"], leaf_data.hex())
                self.assertEqual(vector["leaf_hash"], verifier.leaf_hash_from_document_hash(vector["document_hash"]).hex())
                self.assertNotEqual(vector["leaf_hash"], verifier.leaf_hash_from_report_hash(vector["document_hash"]).hex())
                if vector["name"].startswith("observed_confirmations_v1/"):
                    case = vector["name"].removesuffix(" document")
                    self.assertEqual(vector["document_hash"], hashlib.sha256((TESTDATA / case / "body.json").read_bytes()).hexdigest())

    def test_document_hash_rejects_noncanonical_or_wrong_length_hex(self) -> None:
        for value in ["", "00", "00" * 31, "00" * 33, "GG" * 32, "AB" * 32, "00" * 31 + "  ", None]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                verifier.leaf_hash_from_document_hash(value)

    def test_legacy_observation_entry_and_unknown_leaf(self) -> None:
        digest = "12" * 32
        self.assertEqual(verifier.leaf_hash_from_report_hash(digest), verifier.leaf_hash_from_entry({"report_hash": digest}))
        for entry in [{"leaf_type": "future"}, {"leaf_type": "confirmation_document"},
                      {"leaf_type": "confirmation_document", "document": {"document_hash": "00"}}]:
            with self.subTest(entry=entry), self.assertRaises(ValueError):
                verifier.leaf_hash_from_entry(entry)

    def test_mixed_tree_and_last_document_live_reader(self) -> None:
        vector = json.loads((TESTDATA / "observed_document_leaf_vectors.json").read_bytes())["vectors"][2]
        observation = {"leaf_type": "observation", "report_hash": "12" * 32, "observation_id": "test-observation"}
        document = {"leaf_type": "confirmation_document", "document": {"day": "2026-10-18", "document_hash": vector["document_hash"]}}
        with (TESTDATA / "log_vectors.json").open() as handle:
            signed = json.load(handle)["signed_tree_head"]
        for last_document in [False, True]:
            with self.subTest(last_document=last_document):
                entries = [observation.copy(), document.copy()]
                if not last_document:
                    entries.reverse()
                leaves = []
                for index, entry in enumerate(entries):
                    entry["log_index"] = index
                    leaf = verifier.leaf_hash_from_entry(entry)
                    entry["leaf_hash"] = leaf.hex()
                    leaves.append(leaf)
                sth = {**signed, "tree_size": 2, "root_hash": hashlib.sha256(b"\x01" + leaves[0] + leaves[1]).hexdigest()}
                urls = []

                def respond(url: str) -> dict:
                    urls.append(url)
                    if url.endswith("/sth"):
                        return sth
                    if "/entries?" in url:
                        return {"start": 0, "end": 2, "entries": entries}
                    self.assertIn("?leaf_hash=" + entries[1]["leaf_hash"] + "&tree_size=2", url)
                    return {"log_index": 1, "tree_size": 2, "audit_path": [leaves[0].hex()]}

                # Signature checks have dedicated signed-vector tests. This
                # regression exercises the live reader against both leaf kinds.
                with mock.patch.object(verifier, "http_get_json", side_effect=respond), \
                     mock.patch.object(verifier, "verify_sth"), redirect_stdout(io.StringIO()):
                    verifier.run_against_api("https://example.invalid", {}, False, None)
                self.assertEqual(3, len(urls))


if __name__ == "__main__":
    unittest.main()
