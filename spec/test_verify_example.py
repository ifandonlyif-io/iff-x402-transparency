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


if __name__ == "__main__":
    unittest.main()
