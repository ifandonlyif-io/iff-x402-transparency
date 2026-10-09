#!/usr/bin/env python3
"""Verification-only ML-DSA-65 (FIPS 204), standard library only.

This is a from-scratch, readable verifier for the post-quantum signature
profile in x402-signatures-ml-dsa-65.md. It implements ML-DSA.Verify
(FIPS 204 Algorithm 3, pure mode) and ML-DSA.Verify_internal (Algorithm 8)
for the ML-DSA-65 parameter set. It cannot sign and it is not constant time:
verification handles only public data.

    verify(public_key, message, signature, context=b"") -> bool

Every malformed or invalid input returns False. The function does not raise
on attacker-controlled data.

Cross-checked against Go's crypto/mldsa through
testdata/ml_dsa_65_vectors.json (see test_ml_dsa_65.py).
"""

from __future__ import annotations

import hashlib

# --- ML-DSA-65 parameters (FIPS 204 Table 1) --------------------------------
Q = 8380417  # modulus
D = 13  # dropped bits of t
TAU = 49  # number of +-1 in c
LAMBDA = 192  # collision strength; c~ is LAMBDA/4 = 48 bytes
GAMMA1 = 1 << 19
GAMMA2 = (Q - 1) // 32  # 261888
K, L = 6, 5
ETA = 4
BETA = TAU * ETA  # 196
OMEGA = 55
ZETA = 1753  # 512th root of unity mod Q
N = 256

C_TILDE_BYTES = LAMBDA // 4  # 48
PK_BYTES = 32 + K * 32 * 10  # rho || t1 (10 bits each) = 1952
Z_BYTES = L * 32 * 20  # z, 20 bits each = 3200
SIG_BYTES = C_TILDE_BYTES + Z_BYTES + OMEGA + K  # 3309
INV_N = pow(N, -1, Q)  # 256^-1 mod q = 8347681


def _bitrev8(x: int) -> int:
    return int(f"{x:08b}"[::-1], 2)


# FIPS 204 Appendix B: zetas[k] = ZETA^BitRev8(k) mod q, computed, not typed.
ZETAS = [pow(ZETA, _bitrev8(k), Q) for k in range(N)]


# --- NTT (Algorithms 41 and 42) ---------------------------------------------
def ntt(a: list[int]) -> list[int]:
    """Algorithm 41. Input coefficients in [0, q); output in [0, q)."""
    w = list(a)
    m = 0
    length = 128
    while length >= 1:
        for start in range(0, N, 2 * length):
            m += 1
            z = ZETAS[m]
            for j in range(start, start + length):
                t = z * w[j + length] % Q
                w[j + length] = (w[j] - t) % Q
                w[j] = (w[j] + t) % Q
        length >>= 1
    return w


def inv_ntt(a: list[int]) -> list[int]:
    """Algorithm 42."""
    w = list(a)
    m = N
    length = 1
    while length < N:
        for start in range(0, N, 2 * length):
            m -= 1
            z = -ZETAS[m]
            for j in range(start, start + length):
                t = w[j]
                w[j] = (t + w[j + length]) % Q
                w[j + length] = (z * (t - w[j + length])) % Q
        length <<= 1
    return [x * INV_N % Q for x in w]


# --- Bit packing (Algorithms 16-19, 21) ------------------------------------
def _unpack_bits(data: bytes, bits: int, count: int) -> list[int]:
    """Little-endian fixed-width fields, as SimpleBitUnpack / BitUnpack use."""
    value = int.from_bytes(data, "little")
    mask = (1 << bits) - 1
    return [(value >> (bits * i)) & mask for i in range(count)]


def pk_decode(pk: bytes) -> tuple[bytes, list[list[int]]]:
    """Algorithm 23: pk = rho || SimpleBitPack(t1_i, 2^10 - 1)."""
    rho = pk[:32]
    t1 = [_unpack_bits(pk[32 + 320 * i : 32 + 320 * (i + 1)], 10, N) for i in range(K)]
    return rho, t1


def hint_bit_unpack(y: bytes) -> list[list[int]] | None:
    """Algorithm 21, with every malformed-hint rejection.

    y has OMEGA + K bytes: up to OMEGA hint indices (ascending within each
    polynomial) followed by K cumulative counts. Returns K lists of 0/1, or
    None for a malformed encoding.
    """
    h = [[0] * N for _ in range(K)]
    index = 0
    for i in range(K):
        end = y[OMEGA + i]
        if end < index or end > OMEGA:
            return None  # counts must be non-decreasing and at most omega
        first = index
        while index < end:
            if index > first and y[index - 1] >= y[index]:
                return None  # indices inside one polynomial must strictly increase
            h[i][y[index]] = 1
            index += 1
    for i in range(index, OMEGA):
        if y[i] != 0:
            return None  # unused index slots must be zero
    return h


def sig_decode(sig: bytes):
    """Algorithm 27. Returns (c_tilde, z, h) or None if the hint is malformed.

    z coefficients are BitUnpack(.., gamma1 - 1, gamma1): z = gamma1 - field,
    giving integers in [-gamma1 + 1, gamma1].
    """
    c_tilde = sig[:C_TILDE_BYTES]
    z = []
    for i in range(L):
        start = C_TILDE_BYTES + 640 * i
        z.append([GAMMA1 - v for v in _unpack_bits(sig[start : start + 640], 20, N)])
    h = hint_bit_unpack(sig[C_TILDE_BYTES + Z_BYTES :])
    if h is None:
        return None
    return c_tilde, z, h


# --- Sampling (Algorithms 29, 30, 32) ---------------------------------------
def sample_in_ball(rho: bytes) -> list[int]:
    """Algorithm 29 over SHAKE256: a polynomial with TAU coefficients of +-1."""
    stream = hashlib.shake_256(rho).digest(8 + 4096)  # ample; extended if needed
    signs = int.from_bytes(stream[:8], "little")  # bit i = h[i]
    pos = 8
    c = [0] * N
    for i in range(N - TAU, N):
        while True:
            if pos >= len(stream):
                stream = hashlib.shake_256(rho).digest(len(stream) * 2)
            j = stream[pos]
            pos += 1
            if j <= i:
                break
        c[i] = c[j]
        c[j] = 1 - 2 * ((signs >> (i + TAU - N)) & 1)  # (-1)^h[i + tau - 256]
    return c


def rej_ntt_poly(seed34: bytes) -> list[int]:
    """Algorithms 30 and 14: SHAKE128 rejection sampling of one NTT-domain poly."""
    length = 1024
    stream = hashlib.shake_128(seed34).digest(length)
    out: list[int] = []
    pos = 0
    while len(out) < N:
        if pos + 3 > len(stream):
            length *= 2
            stream = hashlib.shake_128(seed34).digest(length)
        z = stream[pos] | (stream[pos + 1] << 8) | ((stream[pos + 2] & 0x7F) << 16)
        pos += 3
        if z < Q:  # CoeffFromThreeBytes
            out.append(z)
    return out


def expand_a(rho: bytes) -> list[list[list[int]]]:
    """Algorithm 32: A[r][s] = RejNTTPoly(rho || s || r), s = column, r = row."""
    return [
        [rej_ntt_poly(rho + bytes([s, r])) for s in range(L)] for r in range(K)
    ]


# --- Rounding (Algorithms 36, 40) and w1Encode (Algorithm 28) ---------------
def decompose(r: int) -> tuple[int, int]:
    """Algorithm 36: r = r1 * 2 * gamma2 + r0 with r0 in (-gamma2, gamma2]."""
    r %= Q
    r0 = r % (2 * GAMMA2)
    if r0 > GAMMA2:
        r0 -= 2 * GAMMA2
    if r - r0 == Q - 1:
        return 0, r0 - 1
    return (r - r0) // (2 * GAMMA2), r0


def use_hint(h: int, r: int) -> int:
    """Algorithm 40 (HighBits of r, nudged by the hint bit). m = 16."""
    m = (Q - 1) // (2 * GAMMA2)
    r1, r0 = decompose(r)
    if h == 1:
        return (r1 + 1) % m if r0 > 0 else (r1 - 1) % m
    return r1


def w1_encode(w1: list[list[int]]) -> bytes:
    """Algorithm 28: SimpleBitPack(w1_i, 15), 4 bits per coefficient."""
    out = bytearray()
    for poly in w1:
        for j in range(0, N, 2):
            out.append(poly[j] | (poly[j + 1] << 4))
    return bytes(out)


def _h(data: bytes, nbytes: int) -> bytes:
    """H(x, n) = SHAKE256(x, 8n bits)."""
    return hashlib.shake_256(data).digest(nbytes)


# --- Verification (Algorithms 3 and 8) --------------------------------------
def _verify_internal(pk: bytes, m_prime: bytes, sig: bytes) -> bool:
    """Algorithm 8, ML-DSA.Verify_internal(pk, M', sigma)."""
    rho, t1 = pk_decode(pk)
    decoded = sig_decode(sig)
    if decoded is None:
        return False
    c_tilde, z, h = decoded

    # ||z||inf < gamma1 - beta (checked first; it is cheap and decisive).
    bound = GAMMA1 - BETA
    if any(abs(coef) >= bound for poly in z for coef in poly):
        return False

    a_hat = expand_a(rho)
    tr = _h(pk, 64)
    mu = _h(tr + m_prime, 64)
    c_hat = ntt([x % Q for x in sample_in_ball(c_tilde)])

    z_hat = [ntt([x % Q for x in poly]) for poly in z]
    # t1 * 2^d (Power2Round inverse scaling), then NTT.
    t1_hat = [ntt([(x << D) % Q for x in poly]) for poly in t1]

    w1 = []
    for i in range(K):
        acc = [0] * N
        for j in range(L):
            row = a_hat[i][j]
            zj = z_hat[j]
            acc = [(s + a * b) % Q for s, a, b in zip(acc, row, zj)]
        ct = t1_hat[i]
        acc = [(s - c * t) % Q for s, c, t in zip(acc, c_hat, ct)]
        w_approx = inv_ntt(acc)
        hi = h[i]
        w1.append([use_hint(hi[n], w_approx[n]) for n in range(N)])

    c_prime = _h(mu + w1_encode(w1), C_TILDE_BYTES)
    return c_prime == c_tilde


def verify(
    public_key: bytes, message: bytes, signature: bytes, context: bytes = b""
) -> bool:
    """Algorithm 3, ML-DSA.Verify (pure mode), ML-DSA-65.

    Requires a 1952-byte public key, a 3309-byte signature and a context of
    at most 255 bytes. Returns False for anything malformed or invalid.
    """
    try:
        if not all(
            isinstance(x, (bytes, bytearray)) for x in (public_key, message, signature, context)
        ):
            return False
        public_key, message = bytes(public_key), bytes(message)
        signature, context = bytes(signature), bytes(context)
        if len(public_key) != PK_BYTES or len(signature) != SIG_BYTES:
            return False
        if len(context) > 255:
            return False
        m_prime = b"\x00" + bytes([len(context)]) + context + message
        return _verify_internal(public_key, m_prime, signature)
    except Exception:  # never raise on attacker-controlled data
        return False
