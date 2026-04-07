//! ML-KEM-768 key generation and off-chain hint preparation.

use crate::hash::{hash_g, hash_h, expand_a, sample_cbd2};
use crate::intt::intt;
use crate::ntt::{ntt_fast, inner_product_k3};
use crate::types::{K, DecapsHint, EncapsHint, MlkemCiphertext, MlkemEncapsulationKey};
use crate::zq::{Zq, add_mod};
use corelib_imports::bounded_int::upcast;

fn poly_add(a: Span<Zq>, b: Span<Zq>) -> Array<Zq> {
    let mut r: Array<Zq> = array![];
    let mut i: u32 = 0;
    while i < a.len() { r.append(add_mod(*a.at(i), *b.at(i))); i += 1; };
    r
}

fn at_r_col_ntt(a: @Array<Array<Zq>>, r_ntt: @Array<Array<Zq>>, i: u32) -> Array<Zq> {
    inner_product_k3(
        a.at(i).span(), a.at(K + i).span(), a.at(2 * K + i).span(),
        r_ntt.at(0).span(), r_ntt.at(1).span(), r_ntt.at(2).span(),
    )
}

fn serialize_ek(rho: felt252, t_hat: @Array<Array<Zq>>) -> Array<felt252> {
    let mut out: Array<felt252> = array![rho];
    let mut i: u32 = 0;
    while i < K {
        let poly = t_hat.at(i);
        let mut j: u32 = 0;
        while j < 256 { out.append(upcast(*poly.at(j))); j += 1; };
        i += 1;
    };
    out
}

pub fn keygen(seed: felt252) -> (MlkemEncapsulationKey, Array<Array<Zq>>, Array<Array<Zq>>) {
    let (rho, sigma) = hash_g(array![seed].span());
    let a_matrix = expand_a(rho, K);

    let mut s_hat: Array<Array<Zq>> = array![];
    let mut e_hat: Array<Array<Zq>> = array![];
    let mut i: u32 = 0;
    while i < K {
        s_hat.append(ntt_fast(sample_cbd2(sigma, i.into()).span()));
        e_hat.append(ntt_fast(sample_cbd2(sigma, (K + i).into()).span()));
        i += 1;
    };

    let mut t_hat: Array<Array<Zq>> = array![];
    let mut i: u32 = 0;
    while i < K {
        let mut row = inner_product_k3(
            a_matrix.at(i * K).span(), a_matrix.at(i * K + 1).span(), a_matrix.at(i * K + 2).span(),
            s_hat.at(0).span(), s_hat.at(1).span(), s_hat.at(2).span(),
        );
        row = poly_add(row.span(), e_hat.at(i).span());
        t_hat.append(row);
        i += 1;
    };

    let ek_hash = hash_h(serialize_ek(rho, @t_hat).span());
    (MlkemEncapsulationKey { rho, ek_hash, t_hat }, s_hat, a_matrix)
}

pub fn message_from_seed(seed: felt252) -> Array<u8> {
    let h = hash_h(array![seed].span());
    let v: u256 = h.into();
    let mut bits: Array<u8> = array![];
    let mut i: u32 = 0;
    while i < 128 { bits.append(((v.low / pow2(i)) % 2).try_into().unwrap()); i += 1; };
    let mut i: u32 = 0;
    while i < 128 { bits.append(((v.high / pow2(i)) % 2).try_into().unwrap()); i += 1; };
    bits
}

fn pow2(n: u32) -> u128 {
    let mut r: u128 = 1;
    let mut i: u32 = 0;
    while i < n { r *= 2; i += 1; };
    r
}

pub fn prepare_encaps_hint(
    ek: @MlkemEncapsulationKey, a_matrix: @Array<Array<Zq>>, m: Span<u8>,
) -> EncapsHint {
    let mut g_input: Array<felt252> = array![*ek.ek_hash];
    let mut i: u32 = 0;
    while i < 256 { g_input.append((*m.at(i)).into()); i += 1; };
    let (_k_bar, r_seed) = hash_g(g_input.span());

    let mut r_hat: Array<Array<Zq>> = array![];
    let mut e1: Array<Array<Zq>> = array![];
    let mut i: u32 = 0;
    while i < K {
        r_hat.append(ntt_fast(sample_cbd2(r_seed, i.into()).span()));
        e1.append(sample_cbd2(r_seed, (K + i).into()));
        i += 1;
    };
    let e2 = sample_cbd2(r_seed, (2 * K).into());

    let mut u_intt: Array<Array<Zq>> = array![];
    let mut i: u32 = 0;
    while i < K {
        let col_ntt = at_r_col_ntt(a_matrix, @r_hat, i);
        u_intt.append(intt(col_ntt.span()));
        i += 1;
    };

    let tr_ntt = inner_product_k3(
        ek.t_hat.at(0).span(), ek.t_hat.at(1).span(), ek.t_hat.at(2).span(),
        r_hat.at(0).span(), r_hat.at(1).span(), r_hat.at(2).span(),
    );
    let v_intt = intt(tr_ntt.span());

    EncapsHint { r_hat, e1, e2, u_intt, v_intt }
}

pub fn prepare_decaps_hint(
    ek: @MlkemEncapsulationKey,
    a_matrix: @Array<Array<Zq>>,
    s_hat: @Array<Array<Zq>>,
    ct: @MlkemCiphertext,
) -> DecapsHint {
    let mut s_hat_clone: Array<Array<Zq>> = array![];
    let mut i: u32 = 0;
    while i < K {
        let mut p: Array<Zq> = array![];
        let src = s_hat.at(i);
        let mut j: u32 = 0;
        while j < 256 { p.append(*src.at(j)); j += 1; };
        s_hat_clone.append(p);
        i += 1;
    };

    let mut u_ntt: Array<Array<Zq>> = array![];
    let mut i: u32 = 0;
    while i < K { u_ntt.append(ntt_fast(ct.u.at(i).span())); i += 1; };
    let product_ntt = inner_product_k3(
        s_hat.at(0).span(), s_hat.at(1).span(), s_hat.at(2).span(),
        u_ntt.at(0).span(), u_ntt.at(1).span(), u_ntt.at(2).span(),
    );
    let decrypt_intt = intt(product_ntt.span());

    // Recover m' for re-encryption
    let mut w: Array<Zq> = array![];
    let mut i: u32 = 0;
    while i < 256 { w.append(crate::zq::sub_mod(*ct.v.at(i), *decrypt_intt.at(i))); i += 1; };
    let mut m_prime: Array<u8> = array![];
    let mut i: u32 = 0;
    while i < 256 { m_prime.append(crate::compress::compress_1(*w.at(i))); i += 1; };

    let mut g_input: Array<felt252> = array![*ek.ek_hash];
    let mut i: u32 = 0;
    while i < 256 { g_input.append((*m_prime.at(i)).into()); i += 1; };
    let (_k_bar, r_seed) = hash_g(g_input.span());

    let mut reencrypt_r_hat: Array<Array<Zq>> = array![];
    let mut reencrypt_e1: Array<Array<Zq>> = array![];
    let mut i: u32 = 0;
    while i < K {
        reencrypt_r_hat.append(ntt_fast(sample_cbd2(r_seed, i.into()).span()));
        reencrypt_e1.append(sample_cbd2(r_seed, (K + i).into()));
        i += 1;
    };
    let reencrypt_e2 = sample_cbd2(r_seed, (2 * K).into());

    let mut reencrypt_u_intt: Array<Array<Zq>> = array![];
    let mut i: u32 = 0;
    while i < K {
        let col_ntt = at_r_col_ntt(a_matrix, @reencrypt_r_hat, i);
        reencrypt_u_intt.append(intt(col_ntt.span()));
        i += 1;
    };

    let tr_ntt = inner_product_k3(
        ek.t_hat.at(0).span(), ek.t_hat.at(1).span(), ek.t_hat.at(2).span(),
        reencrypt_r_hat.at(0).span(), reencrypt_r_hat.at(1).span(), reencrypt_r_hat.at(2).span(),
    );
    let reencrypt_v_intt = intt(tr_ntt.span());

    DecapsHint {
        s_hat: s_hat_clone, decrypt_intt,
        reencrypt_r_hat, reencrypt_e1, reencrypt_e2,
        reencrypt_u_intt, reencrypt_v_intt,
    }
}
