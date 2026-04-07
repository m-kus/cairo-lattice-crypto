//! Poseidon-based hash functions for ML-KEM (replacing SHA3/SHAKE).
//!
//! Provides G, H, J, XOF, and PRF functions using Poseidon instead of Keccak.
//! XOF squeezes Zq coefficients via base-Q extraction (same pattern as Falcon).
//!
//! This is NOT FIPS 203 compliant — it preserves the algebraic structure of
//! ML-KEM while replacing all hash functions for STARK efficiency.

use core::poseidon::{hades_permutation, poseidon_hash_span};
use corelib_imports::bounded_int::{BoundedInt, DivRemHelper, bounded_int_div_rem, downcast};
use crate::zq::{NZ_Q, QConst, Zq};

// =============================================================================
// LOW extraction chain (from u128, 128 bits -> 6 Zq)
// Each DivRem by Q=3329 removes ~11.7 bits. 6 safe coefficients (>=58 bits input).
// =============================================================================

type ExtractLQ1 = BoundedInt<0, 102217592947112785660370864353189609>;
type ExtractLQ2 = BoundedInt<0, 30705194637162146488546369586419>;
type ExtractLQ3 = BoundedInt<0, 9223549004854955388569050641>;
type ExtractLQ4 = BoundedInt<0, 2770666567994879960519390>;
type ExtractLQ5 = BoundedInt<0, 832281936916455380150>;
type ExtractLQ6 = BoundedInt<0, 250009593546547125>; // ~58 bits, discarded

impl DivRemU128ByQ of DivRemHelper<u128, QConst> {
    type DivT = ExtractLQ1;
    type RemT = Zq;
}
impl DivRemLQ1ByQ of DivRemHelper<ExtractLQ1, QConst> {
    type DivT = ExtractLQ2;
    type RemT = Zq;
}
impl DivRemLQ2ByQ of DivRemHelper<ExtractLQ2, QConst> {
    type DivT = ExtractLQ3;
    type RemT = Zq;
}
impl DivRemLQ3ByQ of DivRemHelper<ExtractLQ3, QConst> {
    type DivT = ExtractLQ4;
    type RemT = Zq;
}
impl DivRemLQ4ByQ of DivRemHelper<ExtractLQ4, QConst> {
    type DivT = ExtractLQ5;
    type RemT = Zq;
}
impl DivRemLQ5ByQ of DivRemHelper<ExtractLQ5, QConst> {
    type DivT = ExtractLQ6;
    type RemT = Zq;
}

// =============================================================================
// HIGH extraction chain (from FeltHigh, 124 bits -> 6 Zq)
// =============================================================================

type FeltHigh = BoundedInt<0, 10633823966279327296825105735305134080>;
type ExtractHQ1 = BoundedInt<0, 3194299779597274646087445399611034>;
type ExtractHQ2 = BoundedInt<0, 959537332411317106064116971946>;
type ExtractHQ3 = BoundedInt<0, 288235906401717364392945921>;
type ExtractHQ4 = BoundedInt<0, 86583330249840001319599>;
type ExtractHQ5 = BoundedInt<0, 26008810528639231396>;
type ExtractHQ6 = BoundedInt<0, 7812799798329597>; // ~53 bits, discarded

impl DivRemFeltHighByQ of DivRemHelper<FeltHigh, QConst> {
    type DivT = ExtractHQ1;
    type RemT = Zq;
}
impl DivRemHQ1ByQ of DivRemHelper<ExtractHQ1, QConst> {
    type DivT = ExtractHQ2;
    type RemT = Zq;
}
impl DivRemHQ2ByQ of DivRemHelper<ExtractHQ2, QConst> {
    type DivT = ExtractHQ3;
    type RemT = Zq;
}
impl DivRemHQ3ByQ of DivRemHelper<ExtractHQ3, QConst> {
    type DivT = ExtractHQ4;
    type RemT = Zq;
}
impl DivRemHQ4ByQ of DivRemHelper<ExtractHQ4, QConst> {
    type DivT = ExtractHQ5;
    type RemT = Zq;
}
impl DivRemHQ5ByQ of DivRemHelper<ExtractHQ5, QConst> {
    type DivT = ExtractHQ6;
    type RemT = Zq;
}

// =============================================================================
// Extraction helpers
// =============================================================================

/// Extract 6 Zq coefficients from low u128 via successive DivRem by Q.
fn extract_6_from_low(value: u128, ref coeffs: Array<Zq>) {
    let (q1, r0) = bounded_int_div_rem(value, NZ_Q);
    coeffs.append(r0);
    let (q2, r1) = bounded_int_div_rem(q1, NZ_Q);
    coeffs.append(r1);
    let (q3, r2) = bounded_int_div_rem(q2, NZ_Q);
    coeffs.append(r2);
    let (q4, r3) = bounded_int_div_rem(q3, NZ_Q);
    coeffs.append(r3);
    let (q5, r4) = bounded_int_div_rem(q4, NZ_Q);
    coeffs.append(r4);
    let (_q6, r5) = bounded_int_div_rem(q5, NZ_Q);
    coeffs.append(r5);
}

/// Extract 4 Zq coefficients from low u128 (for partial rounds).
fn extract_4_from_low(value: u128, ref coeffs: Array<Zq>) {
    let (q1, r0) = bounded_int_div_rem(value, NZ_Q);
    coeffs.append(r0);
    let (q2, r1) = bounded_int_div_rem(q1, NZ_Q);
    coeffs.append(r1);
    let (q3, r2) = bounded_int_div_rem(q2, NZ_Q);
    coeffs.append(r2);
    let (_q4, r3) = bounded_int_div_rem(q3, NZ_Q);
    coeffs.append(r3);
}

/// Extract 6 Zq coefficients from high part of a felt252.
fn extract_6_from_high(value: FeltHigh, ref coeffs: Array<Zq>) {
    let (q1, r0) = bounded_int_div_rem(value, NZ_Q);
    coeffs.append(r0);
    let (q2, r1) = bounded_int_div_rem(q1, NZ_Q);
    coeffs.append(r1);
    let (q3, r2) = bounded_int_div_rem(q2, NZ_Q);
    coeffs.append(r2);
    let (q4, r3) = bounded_int_div_rem(q3, NZ_Q);
    coeffs.append(r3);
    let (q5, r4) = bounded_int_div_rem(q4, NZ_Q);
    coeffs.append(r4);
    let (_q6, r5) = bounded_int_div_rem(q5, NZ_Q);
    coeffs.append(r5);
}

/// Extract 12 Zq from a felt252: 6 from low u128 + 6 from high FeltHigh.
fn extract_12_from_felt252(value: felt252, ref coeffs: Array<Zq>) {
    let val_u256: u256 = value.into();
    extract_6_from_low(val_u256.low, ref coeffs);
    let high_bounded: FeltHigh = downcast(val_u256.high).expect('high exceeds FeltHigh');
    extract_6_from_high(high_bounded, ref coeffs);
}

/// Extract 4 Zq from a felt252 (low half only, for partial rounds).
fn extract_4_from_felt252(value: felt252, ref coeffs: Array<Zq>) {
    let val_u256: u256 = value.into();
    extract_4_from_low(val_u256.low, ref coeffs);
}

// =============================================================================
// Poseidon squeeze: produce N Zq coefficients from a seed
// =============================================================================

/// Squeeze 256 Zq coefficients from a seed using Poseidon permutations.
///
/// 10 full rounds (24 coefficients each from s0+s1) = 240
/// + 1 partial round (12 from s0, 4 from s1) = 16
/// Total = 256
fn squeeze_256(seed: felt252) -> Array<Zq> {
    let (mut s0, mut s1, mut s2): (felt252, felt252, felt252) = (seed, 0, 0);
    let mut coeffs: Array<Zq> = array![];

    // 10 full rounds: 24 coefficients each
    let mut round: u32 = 0;
    while round != 10 {
        let (ns0, ns1, ns2) = hades_permutation(s0, s1, s2);
        s0 = ns0;
        s1 = ns1;
        s2 = ns2;
        extract_12_from_felt252(s0, ref coeffs);
        extract_12_from_felt252(s1, ref coeffs);
        round += 1;
    };

    // Final partial round: 12 from s0 + 4 from s1 = 16
    let (ns0, ns1, _) = hades_permutation(s0, s1, s2);
    extract_12_from_felt252(ns0, ref coeffs);
    extract_4_from_felt252(ns1, ref coeffs);

    coeffs
}

// =============================================================================
// ML-KEM hash function replacements
// =============================================================================

/// G(input) -> (felt252, felt252)
/// Replaces SHA3-512. Produces two independent felt252 outputs.
/// Used to derive (rho, sigma) in KeyGen and (K_bar, r) in Encaps/Decaps.
pub fn hash_g(input: Span<felt252>) -> (felt252, felt252) {
    // Domain-separated: hash with prefix 0 and prefix 1
    let mut input0: Array<felt252> = array![0];
    for val in input {
        input0.append(*val);
    };
    let mut input1: Array<felt252> = array![1];
    for val in input {
        input1.append(*val);
    };
    (poseidon_hash_span(input0.span()), poseidon_hash_span(input1.span()))
}

/// H(input) -> felt252
/// Replaces SHA3-256. Single hash output.
/// Used to hash the encapsulation key.
pub fn hash_h(input: Span<felt252>) -> felt252 {
    poseidon_hash_span(input)
}

/// J(input) -> felt252
/// Replaces SHAKE-256 (truncated). Single hash output.
/// Used for implicit rejection in decapsulation.
pub fn hash_j(input: Span<felt252>) -> felt252 {
    // Domain-separate from H by using prefix 2
    let mut prefixed: Array<felt252> = array![2];
    for val in input {
        prefixed.append(*val);
    };
    poseidon_hash_span(prefixed.span())
}

/// XOF(rho, i, j) -> Array<Zq> (256 coefficients)
/// Replaces SHAKE-128. Expands seed into a polynomial (one entry of matrix A).
pub fn xof(rho: felt252, i: felt252, j: felt252) -> Array<Zq> {
    let seed = poseidon_hash_span(array![rho, i, j].span());
    squeeze_256(seed)
}

/// PRF(sigma, n) -> Array<Zq> (256 coefficients)
/// Replaces SHAKE-256. Expands seed into a polynomial for noise sampling.
/// In our Poseidon variant, PRF produces Zq coefficients directly.
/// The caller is responsible for converting to CBD-distributed values if needed.
pub fn prf(sigma: felt252, n: felt252) -> Array<Zq> {
    // Domain-separate from XOF
    let seed = poseidon_hash_span(array![3, sigma, n].span());
    squeeze_256(seed)
}

/// Sample a small-noise polynomial from a seed.
/// Each coefficient is in [-2, 2] mod Q, from a pseudorandom Zq value.
///
/// Reuses the Poseidon base-Q squeeze (DivRem chains on felt252) to produce
/// 256 Zq values, then maps each to [-2,2] via `val % 5 - 2`.
/// No u128 packing — all arithmetic stays in felt252/BoundedInt.
///
/// Distribution: flat on {-2,-1,0,1,2} (not binomial CBD).
/// Variance 2x of CBD(2) — still well within ML-KEM-768 decryption margin.
pub fn sample_cbd2(sigma: felt252, n: felt252) -> Array<Zq> {
    let seed = poseidon_hash_span(array![3, sigma, n].span());
    let raw = squeeze_256(seed);
    let mut result: Array<Zq> = array![];
    let mut i: u32 = 0;
    while i < 256 {
        let v: felt252 = corelib_imports::bounded_int::upcast(*raw.at(i));
        let v_u16: u16 = v.try_into().unwrap();
        let r = v_u16 % 5; // [0, 4]
        let val: felt252 = if r >= 2 {
            (r - 2).into()
        } else {
            (3329 - (2 - r)).into()
        };
        result.append(corelib_imports::bounded_int::downcast(val).unwrap());
        i += 1;
    };
    result
}

/// Expand matrix A from seed rho.
/// Returns k*k polynomials (each 256 Zq) in row-major NTT domain.
/// For ML-KEM-768, k=3, so 9 polynomials.
pub fn expand_a(rho: felt252, k: u32) -> Array<Array<Zq>> {
    let mut matrix: Array<Array<Zq>> = array![];
    let mut i: u32 = 0;
    while i < k {
        let mut j: u32 = 0;
        while j < k {
            matrix.append(xof(rho, i.into(), j.into()));
            j += 1;
        };
        i += 1;
    };
    matrix
}
