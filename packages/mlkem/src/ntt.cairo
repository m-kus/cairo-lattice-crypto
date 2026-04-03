//! NTT operations for ML-KEM (q=3329, n=256).

use crate::ntt_felt252::{ntt_256, ntt_verify_256};
use crate::mul_ntt_felt252::mul_ntt_pairs_256;
use crate::inner_product_felt252::inner_product_k3_256;
use crate::zq::Zq;

/// Forward NTT via unrolled circuit.
pub fn ntt_fast(f: Span<Zq>) -> Array<Zq> {
    assert(f.len() == 256, 'ntt_fast requires n=256');
    ntt_256(f)
}

/// Pair-wise NTT-domain multiply via unrolled circuit.
pub fn mul_ntt_pairs(f: Span<Zq>, g: Span<Zq>) -> Array<Zq> {
    assert(f.len() == 256 && g.len() == 256, 'expected 256 elements');
    mul_ntt_pairs_256(f, g)
}

/// Fused inner product of k=3 pair-wise NTT multiplies.
pub fn inner_product_k3(
    a0: Span<Zq>, a1: Span<Zq>, a2: Span<Zq>,
    b0: Span<Zq>, b1: Span<Zq>, b2: Span<Zq>,
) -> Array<Zq> {
    inner_product_k3_256(a0, a1, a2, b0, b1, b2)
}

/// Verify INTT hint: assert NTT(hint) == expected, return hint.
/// Uses ntt_verify_256 which skips output array construction.
pub fn intt_with_hint(f_ntt: Span<Zq>, result_hint: Span<Zq>) -> Span<Zq> {
    assert(f_ntt.len() == result_hint.len(), 'length mismatch');
    ntt_verify_256(result_hint, f_ntt);
    result_hint
}
