// ML-DSA-65 (FIPS 204) verification over the vendored @noble/post-quantum.
// Pure ML-DSA with an explicit empty context: the message actually signed is
// 0x00 || 0x00 || M (FIPS 204 Algorithm 2). HashML-DSA, an external mu and a
// non-empty context are never used, so such signatures do not verify.
// Verification only; this module never signs.
import { ml_dsa65 } from "./vendor/noble/post-quantum/ml-dsa.js";

export const MLDSA65 = Object.freeze({
    publicKeySize: ml_dsa65.lengths.publicKey,
    signatureSize: ml_dsa65.lengths.signature,
});
const EMPTY_CONTEXT = new Uint8Array(0);
const isBytes = (value) => value instanceof Uint8Array;

// FIPS 204 ML-DSA.Verify with the empty context. Sizes are checked exactly
// first; a library error is a rejection, never an exception for the caller.
export function verifyMLDSA(publicKey, message, signature) {
    if (!isBytes(publicKey) || !isBytes(message) || !isBytes(signature) ||
        publicKey.length !== MLDSA65.publicKeySize || signature.length !== MLDSA65.signatureSize) return false;
    try {
        return ml_dsa65.verify(signature, message, publicKey, { context: EMPTY_CONTEXT }) === true;
    } catch {
        return false;
    }
}
