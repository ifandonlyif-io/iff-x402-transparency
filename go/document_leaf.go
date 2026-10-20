package preflight

import "crypto/sha256"

// DocumentLeafDomain is the domain prefix for an
// iff-observed-confirmations/v1 confirmation-document leaf.
const DocumentLeafDomain = "iff-observed-confirmations/v1\n"

// DocumentLeafHash returns SHA-256(0x00 || DocumentLeafDomain || documentHash).
// documentHash is the 32 raw SHA-256 bytes of the sealed document body, not
// the UTF-8 bytes of its hexadecimal representation. This only computes the
// leaf binding; it does not verify a document, inclusion proof, STH, or anchor.
func DocumentLeafHash(documentHash [sha256.Size]byte) [sha256.Size]byte {
	var input [1 + len(DocumentLeafDomain) + sha256.Size]byte
	copy(input[1:], DocumentLeafDomain)
	copy(input[1+len(DocumentLeafDomain):], documentHash[:])
	return sha256.Sum256(input[:])
}
