"""Negative and conformance tests for the dependency-free verifier."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import sys
import unittest

SPEC_DIR = os.path.dirname(os.path.abspath(__file__))
if SPEC_DIR not in sys.path:
    sys.path.insert(0, SPEC_DIR)

import verify_example as verifier


def build_consistency_proof(leaves: list[bytes], first: int) -> list[bytes]:
    """Small recursive RFC 6962 proof builder, independent of the verifier."""
    if first == 0:
        return []

    def subproof(m: int, subtree: list[bytes], complete: bool) -> list[bytes]:
        n = len(subtree)
        if m == n:
            return [] if complete else [verifier.merkle_tree_hash(subtree)]
        split = 1 << ((n - 1).bit_length() - 1)
        if m <= split:
            return subproof(m, subtree[:split], complete) + [
                verifier.merkle_tree_hash(subtree[split:])
            ]
        return subproof(m - split, subtree[split:], False) + [
            verifier.merkle_tree_hash(subtree[:split])
        ]

    return subproof(first, leaves, True)


class VerifyExampleTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        vectors_path = os.path.join(SPEC_DIR, "testdata", "log_vectors.json")
        with open(vectors_path, "r", encoding="utf-8") as handle:
            cls.vectors = json.load(handle)

    def test_consistency_vector_and_exact_length(self) -> None:
        vector = self.vectors["consistency_proof"]
        proof = [bytes.fromhex(item) for item in vector["proof"]]
        first_root = bytes.fromhex(vector["first_root_hash"])
        second_root = bytes.fromhex(self.vectors["root_hash"])

        self.assertTrue(
            verifier.verify_consistency(
                vector["first"], vector["second"], proof, first_root, second_root
            )
        )
        self.assertFalse(
            verifier.verify_consistency(
                vector["first"],
                vector["second"],
                proof + [bytes(32)],
                first_root,
                second_root,
            )
        )

    def test_consistency_rejects_tampered_proof(self) -> None:
        vector = self.vectors["consistency_proof"]
        proof = [bytes.fromhex(item) for item in vector["proof"]]
        proof[0] = bytes([proof[0][0] ^ 1]) + proof[0][1:]

        self.assertFalse(
            verifier.verify_consistency(
                vector["first"],
                vector["second"],
                proof,
                bytes.fromhex(vector["first_root_hash"]),
                bytes.fromhex(self.vectors["root_hash"]),
            )
        )

    def test_consistency_across_tree_shapes(self) -> None:
        leaves = [hashlib.sha256(f"leaf-{i}".encode()).digest() for i in range(64)]
        for second in range(1, len(leaves) + 1):
            second_root = verifier.merkle_tree_hash(leaves[:second])
            for first in range(second + 1):
                first_root = verifier.merkle_tree_hash(leaves[:first])
                proof = build_consistency_proof(leaves[:second], first)
                with self.subTest(first=first, second=second):
                    self.assertTrue(
                        verifier.verify_consistency(
                            first, second, proof, first_root, second_root
                        )
                    )

    def test_equal_size_requires_equal_roots_and_empty_proof(self) -> None:
        root = bytes.fromhex(self.vectors["root_hash"])
        self.assertTrue(verifier.verify_consistency(8, 8, [], root, root))
        self.assertFalse(verifier.verify_consistency(8, 8, [bytes(32)], root, root))
        self.assertFalse(verifier.verify_consistency(8, 8, [], root, bytes(32)))

    def test_sth_requires_external_trust_anchor(self) -> None:
        sth = self.vectors["signed_tree_head"]
        with self.assertRaisesRegex(ValueError, "has no trust anchor"):
            verifier.verify_sth(sth, {})

    def test_sth_accepts_matching_pinned_fingerprint(self) -> None:
        sth = self.vectors["signed_tree_head"]
        public_key = verifier._decode_base64(sth["public_key"], "public_key", 32)
        fingerprint = hashlib.sha256(public_key).hexdigest()
        verifier.verify_sth(sth, {sth["log_id"]: fingerprint})

    def test_sth_rejects_wrong_pinned_fingerprint(self) -> None:
        sth = self.vectors["signed_tree_head"]
        wrong_fingerprint = sth["log_id"] + ("00" * 16)
        with self.assertRaisesRegex(ValueError, "public key fingerprint mismatch"):
            verifier.verify_sth(sth, {sth["log_id"]: wrong_fingerprint})

    def test_sth_rejects_self_consistent_attacker_key_identity(self) -> None:
        sth = copy.deepcopy(self.vectors["signed_tree_head"])
        attacker_key = bytes(range(32))
        attacker_fingerprint = hashlib.sha256(attacker_key).hexdigest()
        sth["public_key"] = verifier.base64.b64encode(attacker_key).decode("ascii")
        sth["log_id"] = attacker_fingerprint[:32]
        sth["sha256_hash"] = hashlib.sha256(verifier.canonical_sth_bytes(sth)).hexdigest()

        # It fails at the trust boundary before signature validity matters.
        with self.assertRaisesRegex(ValueError, "has no trust anchor"):
            verifier.verify_sth(sth, {})

    def test_trusted_key_parser_rejects_log_id_mismatch(self) -> None:
        with self.assertRaisesRegex(ValueError, "must equal the first 16 bytes"):
            verifier.parse_trusted_log_keys([("00" * 16) + "=" + ("11" * 32)])


class ProfileV2Test(unittest.TestCase):
    """Signature profile v2 (ML-DSA-65) through the same verifier entry points."""

    @classmethod
    def setUpClass(cls) -> None:
        path = os.path.join(SPEC_DIR, "testdata", "ml_dsa_65_vectors.json")
        with open(path, "r", encoding="utf-8") as handle:
            cls.doc = json.load(handle)["profile_v2_examples"]
        with open(os.path.join(SPEC_DIR, "testdata", "log_vectors.json"), encoding="utf-8") as handle:
            cls.v1 = json.load(handle)["signed_tree_head"]

    def v2_sth(self) -> dict:
        e = copy.deepcopy(self.doc["signed_tree_head"])
        return {
            "log_id": e["log_id"], "tree_size": e["tree_size"], "timestamp": e["timestamp"],
            "root_hash": e["root_hash"], "sha256_hash": e["sha256_hash"],
            "public_key": e["public_key_base64"], "signature": e["signature_base64"],
            "signature_algorithm": e["signature_algorithm"],
        }

    def pin(self, sth: dict) -> dict:
        key = verifier.base64.b64decode(sth["public_key"])
        fp = hashlib.sha256(key).hexdigest()
        return {fp[:32]: fp}

    def reject(self, sth: dict, pattern: str, trusted: dict | None = None) -> None:
        with self.assertRaisesRegex(ValueError, pattern):
            verifier.verify_sth(sth, self.pin(self.v2_sth()) if trusted is None else trusted)

    def test_v2_sth_verifies(self) -> None:
        sth = self.v2_sth()
        canonical = verifier.verify_sth(sth, self.pin(sth))
        self.assertEqual(canonical.decode(), self.doc["signed_tree_head"]["canonical_bytes"])
        del sth["signature_algorithm"]  # the informational field is optional
        verifier.verify_sth(sth, self.pin(sth))

    def test_v2_sth_needs_trust_anchor_and_exact_fingerprint(self) -> None:
        sth = self.v2_sth()
        self.reject(sth, "has no trust anchor", {})
        self.reject(sth, "fingerprint mismatch", {sth["log_id"]: sth["log_id"] + "00" * 16})
        verifier.verify_sth(sth, {}, allow_untrusted_key=True)

    def test_pinned_keys_support_several_entries(self) -> None:
        sth = self.v2_sth()
        pins = {**self.pin(sth), **self.pin(self.v1)}
        verifier.verify_sth(sth, pins)
        for entry in verifier.PRODUCTION_TRUSTED_LOG_KEYS.items():
            pins[entry[0]] = entry[1]
        verifier.verify_sth(sth, pins)
        v1 = copy.deepcopy(self.v1)
        verifier.verify_sth(v1, pins | self.pin(v1))

    def test_key_one_byte_short_is_rejected_with_no_fallback(self) -> None:
        sth = self.v2_sth()
        key = verifier.base64.b64decode(sth["public_key"])[:-1]
        sth["public_key"] = verifier.base64.b64encode(key).decode()
        self.reject(sth, "expected 32 .Ed25519. or 1952", {})

    def test_signature_one_byte_short_is_rejected(self) -> None:
        sth = self.v2_sth()
        sig = verifier.base64.b64decode(sth["signature"])[:-1]
        sth["signature"] = verifier.base64.b64encode(sig).decode()
        self.reject(sth, "signature must decode to 3309 bytes")

    def test_flipped_signature_byte_is_rejected(self) -> None:
        sth = self.v2_sth()
        sig = bytearray(verifier.base64.b64decode(sth["signature"]))
        sig[100] ^= 1
        sth["signature"] = verifier.base64.b64encode(bytes(sig)).decode()
        self.reject(sth, "ML-DSA-65 signature .* invalid")

    def test_ed25519_signature_with_ml_dsa_key_is_rejected(self) -> None:
        sth = self.v2_sth()
        sth["signature"] = self.v1["signature"]  # a genuine 64-byte Ed25519 signature
        self.reject(sth, "signature must decode to 3309 bytes")

    def test_ml_dsa_signature_with_ed25519_key_is_rejected(self) -> None:
        sth = copy.deepcopy(self.v1)
        sth["signature"] = self.doc["signed_tree_head"]["signature_base64"]
        with self.assertRaisesRegex(ValueError, "signature must decode to 64 bytes"):
            verifier.verify_sth(sth, self.pin(sth))

    def test_v1_style_message_signed_with_ml_dsa_is_rejected(self) -> None:
        sth = self.v2_sth()
        sth["signature"] = self.doc["negative_signatures_for_signed_tree_head"]["v1_style_digest_only_message"]
        self.reject(sth, "ML-DSA-65 signature .* invalid")

    def test_wrong_domain_signature_is_rejected(self) -> None:
        sth = self.v2_sth()
        sth["signature"] = self.doc["negative_signatures_for_signed_tree_head"]["wrong_domain_line"]
        self.reject(sth, "ML-DSA-65 signature .* invalid")

    def test_log_id_mismatch_is_rejected_for_both_profiles(self) -> None:
        sth = self.v2_sth()
        sth["log_id"] = "00" * 16
        # sha256_hash covers log_id, so refresh it to reach the log_id check
        sth["sha256_hash"] = hashlib.sha256(verifier.canonical_sth_bytes(sth)).hexdigest()
        self.reject(sth, "log_id mismatch", {})
        v1 = copy.deepcopy(self.v1)
        v1["log_id"] = "00" * 16
        v1["sha256_hash"] = hashlib.sha256(verifier.canonical_sth_bytes(v1)).hexdigest()
        with self.assertRaisesRegex(ValueError, "log_id mismatch"):
            verifier.verify_sth(v1, {}, allow_untrusted_key=True)

    def test_algorithm_name_mismatch_is_rejected(self) -> None:
        sth = self.v2_sth()
        sth["signature_algorithm"] = "Ed25519"
        self.reject(sth, "disagrees with the ML-DSA-65 public key")
        v1 = copy.deepcopy(self.v1)
        v1["signature_algorithm"] = "ML-DSA-65"
        with self.assertRaisesRegex(ValueError, "disagrees with the Ed25519 public key"):
            verifier.verify_sth(v1, self.pin(v1))
        v1["signature_algorithm"] = "Ed25519"
        verifier.verify_sth(v1, self.pin(v1))

    def test_modified_canonical_field_is_rejected(self) -> None:
        sth = self.v2_sth()
        sth["tree_size"] = 9
        self.reject(sth, "sha256_hash mismatch")

    def test_monitor_report_v2_and_negatives(self) -> None:
        r = self.doc["monitor_report"]
        args = (r["canonical_report_json"], r["report_hash"], r["public_key_base64"], r["signature_base64"])
        self.assertEqual(verifier.verify_monitor_report_signature(*args), "ML-DSA-65")
        self.assertEqual(verifier.verify_monitor_report_signature(*args, "ML-DSA-65"), "ML-DSA-65")
        with self.assertRaisesRegex(ValueError, "disagrees"):
            verifier.verify_monitor_report_signature(*args, "Ed25519")
        with self.assertRaisesRegex(ValueError, "report_hash mismatch"):
            verifier.verify_monitor_report_signature(args[0].replace("123", "124"), *args[1:])
        sig = verifier.base64.b64decode(args[3])
        with self.assertRaisesRegex(ValueError, "3309"):
            verifier.verify_monitor_report_signature(*args[:3], verifier.base64.b64encode(sig[:-1]).decode())
        sth_sig = self.doc["signed_tree_head"]["signature_base64"]  # another artifact's signature
        with self.assertRaisesRegex(ValueError, "ML-DSA-65 signature .* invalid"):
            verifier.verify_monitor_report_signature(*args[:3], sth_sig)

    def test_vector_file_code_path_with_own_negative_cases(self) -> None:
        doc = copy.deepcopy(self.doc)
        doc["negative_cases"] = [
            {"name": "domain", "target": "signed_tree_head", "domain": "iff-x402-monitor-report/v2\n",
             "expected_error": "domain"},
            {"name": "message", "target": "signed_tree_head", "signed_message_hex": "00",
             "expected_error": "message"},
            {"name": "log_id", "target": "signed_tree_head", "log_id": "11" * 16, "expected_error": "log_id"},
            {"name": "algorithm", "target": "signed_tree_head", "signature_algorithm": "Ed25519",
             "expected_error": "algorithm"},
            {"name": "digest-only", "target": "signed_tree_head",
             "signature_base64": doc["negative_signatures_for_signed_tree_head"]["v1_style_digest_only_message"],
             "expected_error": "signature"},
            {"name": "report algorithm", "target": "monitor_report",
             "monitor_signature_algorithm": "Ed25519", "expected_error": "algorithm"},
            {"name": "report field", "target": "monitor_report",
             "canonical_report_json": doc["monitor_report"]["canonical_report_json"].replace("402", "403"),
             "expected_error": "hash"},
        ]
        self.assertEqual(verifier.verify_signature_vectors_v2(doc), (2, 7))
        doc["negative_cases"].append({"name": "not actually bad", "target": "monitor_report"})
        with self.assertRaisesRegex(ValueError, "was accepted"):
            verifier.verify_signature_vectors_v2(doc)

    def test_v1_behaviour_is_unchanged(self) -> None:
        sth = copy.deepcopy(self.v1)
        key = verifier.base64.b64decode(sth["public_key"])
        self.assertEqual(len(key), 32)
        verifier.verify_sth(sth, self.pin(sth))
        sig = bytearray(verifier.base64.b64decode(sth["signature"]))
        sig[0] ^= 1
        sth["signature"] = verifier.base64.b64encode(bytes(sig)).decode()
        with self.assertRaisesRegex(ValueError, "Ed25519 signature .* invalid"):
            verifier.verify_sth(sth, self.pin(sth))
        with self.assertRaisesRegex(ValueError, "has no trust anchor"):
            verifier.verify_sth(copy.deepcopy(self.v1), {})
        self.assertEqual(verifier.signature_algorithm_for_key(key), "Ed25519")


class ProductionPinsTest(unittest.TestCase):
    """keys/x402-transparency-production-2026-10-10.json is internally
    consistent and agrees with the pins carried in verify_example.py."""

    @classmethod
    def setUpClass(cls) -> None:
        path = os.path.join(SPEC_DIR, "..", "keys", "x402-transparency-production-2026-10-10.json")
        with open(path, encoding="utf-8") as handle:
            cls.pins = json.load(handle)

    def test_log_keys(self) -> None:
        self.assertEqual([k["algorithm"] for k in self.pins["log_keys"]], ["Ed25519", "ML-DSA-65"])
        for entry in self.pins["log_keys"]:
            raw = verifier.base64.b64decode(entry["public_key"], validate=True)
            self.assertEqual(verifier.signature_algorithm_for_key(raw), entry["algorithm"])
            digest = hashlib.sha256(raw).hexdigest()
            self.assertEqual(entry["public_key_sha256"], digest)
            self.assertEqual(entry["log_id"], digest[:32])
            self.assertEqual(verifier.PRODUCTION_TRUSTED_LOG_KEYS[entry["log_id"]], digest)
        self.assertEqual(set(self.pins["log_keys"][i]["log_id"] for i in (0, 1)),
                         set(verifier.PRODUCTION_TRUSTED_LOG_KEYS))

    def test_monitor_keys(self) -> None:
        self.assertEqual([k["algorithm"] for k in self.pins["monitor_keys"]], ["Ed25519", "ML-DSA-65"])
        for entry in self.pins["monitor_keys"]:
            self.assertEqual(entry["monitor_id"], "iff-production-monitor")
            raw = verifier.base64.b64decode(entry["public_key"], validate=True)
            self.assertEqual(verifier.signature_algorithm_for_key(raw), entry["algorithm"])
            self.assertEqual(entry["key_id"], "sha256:" + hashlib.sha256(raw).hexdigest())

    def test_note_present(self) -> None:
        self.assertIn("out-of-band", self.pins["note"])


if __name__ == "__main__":
    unittest.main()
