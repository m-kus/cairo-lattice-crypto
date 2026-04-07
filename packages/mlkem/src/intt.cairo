//! Naive iterative INTT for ML-KEM (FIPS 203 Algorithm 10).
//!
//! This is a direct implementation — NOT hint-based. Used for:
//! - Off-chain encapsulation (generating ciphertexts)
//! - Test vector generation
//! - E2E testing
//!
//! On-chain verification should use `ntt::intt_with_hint` instead.

use crate::zq::{Zq, add_mod, sub_mod, mul_mod};
use corelib_imports::bounded_int::downcast;

/// Zeta table (same as NTT but accessed in reverse order for INTT).
fn get_zetas() -> [felt252; 128] {
    [
        1, 1729, 2580, 3289, 2642, 630, 1897, 848, 1062, 1919, 193, 797,
        2786, 3260, 569, 1746, 296, 2447, 1339, 1476, 3046, 56, 2240, 1333,
        1426, 2094, 535, 2882, 2393, 2879, 1974, 821, 289, 331, 3253, 1756,
        1197, 2304, 2277, 2055, 650, 1977, 2513, 632, 2865, 33, 1320, 1915,
        2319, 1435, 807, 452, 1438, 2868, 1534, 2402, 2647, 2617, 1481, 648,
        2474, 3110, 1227, 910, 17, 2761, 583, 2649, 1637, 723, 2288, 1100,
        1409, 2662, 3281, 233, 756, 2156, 3015, 3050, 1703, 1651, 2789, 1789,
        1847, 952, 1461, 2687, 939, 2308, 2437, 2388, 733, 2337, 268, 641,
        1584, 2298, 2037, 3220, 375, 2549, 2090, 1645, 1063, 319, 2773, 757,
        2099, 561, 2466, 2594, 2804, 1092, 403, 1026, 1143, 2150, 2775, 886,
        1722, 1212, 1874, 1029, 2110, 2935, 885, 2154,
    ]
}

/// 128^{-1} mod 3329 = 3303
const N_INV: felt252 = 3303;

/// Compute INTT of a 256-element polynomial.
/// Direct iterative implementation matching FIPS 203 Algorithm 10.
pub fn intt(f_hat: Span<Zq>) -> Array<Zq> {
    assert(f_hat.len() == 256, 'intt requires n=256');
    let zetas = get_zetas();
    let n_inv: Zq = downcast(N_INV).unwrap();

    // Copy input to mutable array
    let mut f: Array<felt252> = array![];
    let mut i: u32 = 0;
    while i < 256 {
        f.append(corelib_imports::bounded_int::upcast(*f_hat.at(i)));
        i += 1;
    };

    // INTT butterfly layers (Algorithm 10)
    let mut k: u32 = 127;
    let mut length: u32 = 2;
    while length <= 128 {
        let mut start: u32 = 0;
        while start < 256 {
            let zeta: Zq = downcast(*zetas.span().at(k)).unwrap();
            k -= 1;
            let mut j: u32 = start;
            while j < start + length {
                let fj: Zq = downcast(*f.at(j)).unwrap();
                let fjl: Zq = downcast(*f.at(j + length)).unwrap();
                // t = f[j]
                // f[j] = t + f[j+len]
                let new_fj = add_mod(fj, fjl);
                // f[j+len] = zeta * (f[j+len] - t)
                let diff = sub_mod(fjl, fj);
                let new_fjl = mul_mod(zeta, diff);
                f = array_set(f, j, corelib_imports::bounded_int::upcast(new_fj));
                f = array_set(f, j + length, corelib_imports::bounded_int::upcast(new_fjl));
                j += 1;
            };
            start += 2 * length;
        };
        length *= 2;
    };

    // Multiply by N_INV = 128^{-1} mod Q
    let mut result: Array<Zq> = array![];
    let mut i: u32 = 0;
    while i < 256 {
        let val: Zq = downcast(*f.at(i)).unwrap();
        result.append(mul_mod(val, n_inv));
        i += 1;
    };
    result
}

/// Set element at index in array (rebuilds array — O(n) but simple).
fn array_set(arr: Array<felt252>, idx: u32, val: felt252) -> Array<felt252> {
    let span = arr.span();
    let mut result: Array<felt252> = array![];
    let mut i: u32 = 0;
    while i < span.len() {
        if i == idx {
            result.append(val);
        } else {
            result.append(*span.at(i));
        }
        i += 1;
    };
    result
}
