"""
Reference NTT/INTT for ML-KEM (FIPS 203 Algorithms 9-10).

Iterative Cooley-Tukey DIT NTT over Z_3329[X]/(X^256 + 1).
7 butterfly layers on 256 elements.
"""
from mlkem_py.constants import Q, N, zetas, N_INV


def ntt(f: list[int]) -> list[int]:
    """
    Forward NTT (FIPS 203 Algorithm 9).

    Input: polynomial f with 256 coefficients in [0, Q-1].
    Output: NTT(f) with 256 coefficients in [0, Q-1].
    """
    assert len(f) == N
    f_hat = list(f)  # copy
    k = 1
    length = 128
    while length >= 2:
        for start in range(0, 256, 2 * length):
            zeta = zetas[k]
            k += 1
            for j in range(start, start + length):
                t = (zeta * f_hat[j + length]) % Q
                f_hat[j + length] = (f_hat[j] - t) % Q
                f_hat[j] = (f_hat[j] + t) % Q
        length //= 2
    return f_hat


def intt(f_hat: list[int]) -> list[int]:
    """
    Inverse NTT (FIPS 203 Algorithm 10).

    Input: NTT-domain polynomial with 256 coefficients in [0, Q-1].
    Output: time-domain polynomial with 256 coefficients in [0, Q-1].
    """
    assert len(f_hat) == N
    f = list(f_hat)  # copy
    k = 127
    length = 2
    while length <= 128:
        for start in range(0, 256, 2 * length):
            zeta = zetas[k]
            k -= 1
            for j in range(start, start + length):
                t = f[j]
                f[j] = (t + f[j + length]) % Q
                f[j + length] = (zeta * (f[j + length] - t)) % Q
        length *= 2
    for i in range(N):
        f[i] = (f[i] * N_INV) % Q
    return f


def mul_ntt_pairs(f_hat: list[int], g_hat: list[int]) -> list[int]:
    """
    Pointwise multiplication in NTT domain (FIPS 203 Algorithm 11).

    Operates on 128 pairs of degree-1 polynomials:
    For pair i: (f0, f1) * (g0, g1) mod (X^2 - gamma_i)
      = (f0*g0 + f1*g1*gamma_i, f0*g1 + f1*g0)
    """
    from mlkem_py.constants import gammas

    assert len(f_hat) == N and len(g_hat) == N
    h_hat = [0] * N
    for i in range(128):
        f0, f1 = f_hat[2 * i], f_hat[2 * i + 1]
        g0, g1 = g_hat[2 * i], g_hat[2 * i + 1]
        gamma = gammas[i]
        h_hat[2 * i] = (f0 * g0 + f1 * g1 * gamma) % Q
        h_hat[2 * i + 1] = (f0 * g1 + f1 * g0) % Q
    return h_hat


if __name__ == "__main__":
    import random
    random.seed(42)

    # Roundtrip test: INTT(NTT(f)) == f
    f = [random.randint(0, Q - 1) for _ in range(N)]
    f_hat = ntt(f)
    f_back = intt(f_hat)
    assert f_back == f, "NTT roundtrip failed!"

    # Convolution test: NTT(f*g) == mul_ntt_pairs(NTT(f), NTT(g))
    g = [random.randint(0, Q - 1) for _ in range(N)]
    fg_ntt = mul_ntt_pairs(ntt(f), ntt(g))
    fg = intt(fg_ntt)

    # Verify via schoolbook multiplication mod (X^256+1)
    fg_school = [0] * N
    for i in range(N):
        for j in range(N):
            if i + j < N:
                fg_school[i + j] = (fg_school[i + j] + f[i] * g[j]) % Q
            else:
                # X^256 = -1, so wrap with negation
                fg_school[i + j - N] = (fg_school[i + j - N] - f[i] * g[j]) % Q
    assert fg == fg_school, "Convolution test failed!"

    print("All reference NTT tests passed.")
