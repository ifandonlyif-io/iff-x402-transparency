/** Domain prefix for an iff-observed-confirmations/v1 document leaf. */
export const DOCUMENT_LEAF_DOMAIN = "iff-observed-confirmations/v1\n";

/**
 * Computes SHA-256(0x00 || DOCUMENT_LEAF_DOMAIN || documentHash).
 * documentHash must be the 32 raw SHA-256 bytes of the sealed document body,
 * not the UTF-8 bytes of its hexadecimal representation. This only computes
 * the leaf binding; it does not verify a document, inclusion proof, STH, or anchor.
 */
export async function documentLeafHash(documentHash: Uint8Array): Promise<Uint8Array> {
  if (documentHash.length !== 32) {
    throw new RangeError("document hash must contain exactly 32 bytes");
  }
  const prefix = new TextEncoder().encode(DOCUMENT_LEAF_DOMAIN);
  const input = new Uint8Array(1 + prefix.length + documentHash.length);
  input.set(prefix, 1);
  input.set(documentHash, 1 + prefix.length);
  return new Uint8Array(await globalThis.crypto.subtle.digest("SHA-256", input));
}
