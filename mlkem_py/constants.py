"""
ML-KEM constants for q=3329, n=256.

Zeta table matches FIPS 203 Algorithm 9 (NTT) / Algorithm 10 (INTT).
Primitive 256th root of unity: zeta = 17  (ord(17) mod 3329 = 256).
"""

Q = 3329
N = 256
ZETA = 17  # primitive 256th root of unity mod Q


def _bitrev7(x: int) -> int:
    """Reverse the low 7 bits of x."""
    result = 0
    for _ in range(7):
        result = (result << 1) | (x & 1)
        x >>= 1
    return result


# FIPS 203 Table 2: zetas[i] = ZETA^(BitRev7(i)) mod Q for i=0..127
# zetas[0] = 1 is unused by the NTT algorithm itself
zetas = [pow(ZETA, _bitrev7(i), Q) for i in range(128)]

# Gamma constants for pair-wise NTT-domain multiplication.
# For pair i (i=0..127), the degree-1 factor is (X^2 - gamma[i])
# where gamma[i] = ZETA^(2*BitRev7(i)+1) mod Q.
gammas = [pow(ZETA, 2 * _bitrev7(i) + 1, Q) for i in range(128)]

# Precomputed inverse of 128 mod Q, needed for INTT scaling.
# The NTT has 7 layers (not 8) — it stops at degree-1 pairs,
# so the effective transform size is 128, not 256.
# 128^{-1} mod 3329 = 3303
N_INV = pow(128, -1, Q)
assert (128 * N_INV) % Q == 1


if __name__ == "__main__":
    print(f"Q = {Q}")
    print(f"zetas = {zetas}")
    print(f"gammas = {gammas}")
    print(f"N_INV = {N_INV}")
    # Sanity: zeta^256 == 1 (mod Q)
    assert pow(ZETA, 256, Q) == 1
    # zeta^128 != 1 (primitive)
    assert pow(ZETA, 128, Q) != 1
    print("All sanity checks passed.")
