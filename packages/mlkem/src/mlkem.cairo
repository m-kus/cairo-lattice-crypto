//! ML-KEM-768 encapsulation and decapsulation (optimized).
//!
//! Optimizations applied:
//!   1. Matrix A passed as input (pre-expanded)
//!   2. ek_hash pre-computed (no serialization)
//!   3. r_hat + noise passed as hints (no NTTs/CBD in encaps)
//!   4. Circuit-generated mul/inner_product in felt252 mode
//!   5. downcast-based output reduction (no u128 packing)

use crate::compress::{compress_1, compress_10, compress_4, decompress_1};
use crate::hash::hash_g;
use crate::ntt::{ntt_fast, inner_product_k3, intt_with_hint};
use crate::types::{K, DecapsHint, EncapsHint, MlkemCiphertext, MlkemEncapsulationKey};
use crate::zq::{Zq, add_mod, sub_mod};

fn poly_add(a: Span<Zq>, b: Span<Zq>) -> Array<Zq> {
    let mut r: Array<Zq> = array![];
    let mut i: u32 = 0;
    while i < a.len() { r.append(add_mod(*a.at(i), *b.at(i))); i += 1; };
    r
}

fn poly_sub(a: Span<Zq>, b: Span<Zq>) -> Array<Zq> {
    let mut r: Array<Zq> = array![];
    let mut i: u32 = 0;
    while i < a.len() { r.append(sub_mod(*a.at(i), *b.at(i))); i += 1; };
    r
}

fn derive_kr(ek_hash: felt252, m: Span<u8>) -> (felt252, felt252) {
    let mut g_input: Array<felt252> = array![ek_hash];
    let mut i: u32 = 0;
    while i < m.len() { g_input.append((*m.at(i)).into()); i += 1; };
    hash_g(g_input.span())
}

// =============================================================================
// Encapsulate — 4 NTTs (hint checks) + 4 inner_product circuits + G hash
// =============================================================================

pub fn encapsulate(
    ek: @MlkemEncapsulationKey,
    a_matrix: @Array<Array<Zq>>,
    m: Span<u8>,
    hint: EncapsHint,
) -> (felt252, MlkemCiphertext) {
    assert(m.len() == 256, 'message must be 256 bits');

    let (k_bar, _r_seed) = derive_kr(*ek.ek_hash, m);

    // u[i] = INTT(A^T_col_i * r_hat) + e1[i]
    let mut u: Array<Array<Zq>> = array![];
    let mut i: u32 = 0;
    while i < K {
        let col_ntt = inner_product_k3(
            a_matrix.at(i).span(), a_matrix.at(K + i).span(), a_matrix.at(2 * K + i).span(),
            hint.r_hat.at(0).span(), hint.r_hat.at(1).span(), hint.r_hat.at(2).span(),
        );
        let col_time = intt_with_hint(col_ntt.span(), hint.u_intt.at(i).span());
        u.append(poly_add(col_time, hint.e1.at(i).span()));
        i += 1;
    };

    // v = INTT(t_hat^T * r_hat) + e2 + Decompress_1(m)
    let tr_ntt = inner_product_k3(
        ek.t_hat.at(0).span(), ek.t_hat.at(1).span(), ek.t_hat.at(2).span(),
        hint.r_hat.at(0).span(), hint.r_hat.at(1).span(), hint.r_hat.at(2).span(),
    );
    let tr_time = intt_with_hint(tr_ntt.span(), hint.v_intt.span());
    let v_plus_e2 = poly_add(tr_time, hint.e2.span());
    let mut v: Array<Zq> = array![];
    let mut i: u32 = 0;
    while i < 256 {
        v.append(add_mod(*v_plus_e2.at(i), decompress_1(*m.at(i))));
        i += 1;
    };

    (k_bar, MlkemCiphertext { u, v })
}

// =============================================================================
// Decapsulate — 3 NTTs (ct.u) + 5 NTTs (hint checks) + 6 inner_product + G hash
// =============================================================================

pub fn decapsulate(
    ek: @MlkemEncapsulationKey,
    a_matrix: @Array<Array<Zq>>,
    ct: @MlkemCiphertext,
    hint: DecapsHint,
) -> felt252 {
    // ── Step 1: Decrypt ──
    let mut u_ntt: Array<Array<Zq>> = array![];
    let mut i: u32 = 0;
    while i < K { u_ntt.append(ntt_fast(ct.u.at(i).span())); i += 1; };

    let product_ntt = inner_product_k3(
        hint.s_hat.at(0).span(), hint.s_hat.at(1).span(), hint.s_hat.at(2).span(),
        u_ntt.at(0).span(), u_ntt.at(1).span(), u_ntt.at(2).span(),
    );
    let product = intt_with_hint(product_ntt.span(), hint.decrypt_intt.span());
    let w = poly_sub(ct.v.span(), product);

    // ── Step 2: Recover message ──
    let mut m_prime: Array<u8> = array![];
    let mut i: u32 = 0;
    while i < 256 { m_prime.append(compress_1(*w.at(i))); i += 1; };

    // ── Step 3: Derive (K_bar, r_seed) ──
    let (k_bar, _r_seed) = derive_kr(*ek.ek_hash, m_prime.span());

    // ── Step 4: Re-encryption check ──
    let mut i: u32 = 0;
    while i < K {
        let col_ntt = inner_product_k3(
            a_matrix.at(i).span(), a_matrix.at(K + i).span(), a_matrix.at(2 * K + i).span(),
            hint.reencrypt_r_hat.at(0).span(),
            hint.reencrypt_r_hat.at(1).span(),
            hint.reencrypt_r_hat.at(2).span(),
        );
        let col_time = intt_with_hint(col_ntt.span(), hint.reencrypt_u_intt.at(i).span());
        let u_prime_i = poly_add(col_time, hint.reencrypt_e1.at(i).span());
        let mut j: u32 = 0;
        while j < 256 {
            assert(
                compress_10(*u_prime_i.at(j)) == compress_10(*ct.u.at(i).at(j)),
                'u reencrypt mismatch',
            );
            j += 1;
        };
        i += 1;
    };

    // Check v
    let tr_ntt = inner_product_k3(
        ek.t_hat.at(0).span(), ek.t_hat.at(1).span(), ek.t_hat.at(2).span(),
        hint.reencrypt_r_hat.at(0).span(),
        hint.reencrypt_r_hat.at(1).span(),
        hint.reencrypt_r_hat.at(2).span(),
    );
    let tr_time = intt_with_hint(tr_ntt.span(), hint.reencrypt_v_intt.span());
    let v_no_msg = poly_add(tr_time, hint.reencrypt_e2.span());
    let mut m_poly: Array<Zq> = array![];
    let mut i: u32 = 0;
    while i < 256 { m_poly.append(decompress_1(*m_prime.at(i))); i += 1; };
    let v_prime = poly_add(v_no_msg.span(), m_poly.span());
    let mut i: u32 = 0;
    while i < 256 {
        assert(compress_4(*v_prime.at(i)) == compress_4(*ct.v.at(i)), 'v reencrypt mismatch');
        i += 1;
    };

    k_bar
}
