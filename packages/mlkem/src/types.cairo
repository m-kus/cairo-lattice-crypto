//! ML-KEM-768 type definitions.

use crate::zq::Zq;

pub const K: u32 = 3;
pub const DU: u32 = 10;
pub const DV: u32 = 4;

/// Encapsulation key with pre-computed hash.
#[derive(Drop, Serde)]
pub struct MlkemEncapsulationKey {
    pub rho: felt252,
    /// H(ek) — pre-computed Poseidon hash of the serialized key.
    /// Avoids re-serializing 768 Zq values on every encaps/decaps.
    pub ek_hash: felt252,
    /// k polynomials of 256 Zq in NTT domain
    pub t_hat: Array<Array<Zq>>,
}

/// Ciphertext.
#[derive(Drop, Serde)]
pub struct MlkemCiphertext {
    pub u: Array<Array<Zq>>,
    pub v: Array<Zq>,
}

/// Hints for encapsulate.
/// All noise and INTT values are prover-supplied. Soundness relies on:
/// - Decapsulator independently re-derives noise from r_seed
/// - INTT hints are verified via NTT roundtrip
#[derive(Drop, Serde)]
pub struct EncapsHint {
    pub r_hat: Array<Array<Zq>>,
    pub e1: Array<Array<Zq>>,
    pub e2: Array<Zq>,
    pub u_intt: Array<Array<Zq>>,
    pub v_intt: Array<Zq>,
}

/// Hints for decapsulate.
/// All noise and INTT values are prover-supplied.
/// Soundness: re-encryption check verifies consistency (wrong hints → assertion failure).
#[derive(Drop, Serde)]
pub struct DecapsHint {
    pub s_hat: Array<Array<Zq>>,
    pub decrypt_intt: Array<Zq>,
    /// Re-encryption hints (noise + INTT results)
    pub reencrypt_r_hat: Array<Array<Zq>>,
    pub reencrypt_e1: Array<Array<Zq>>,
    pub reencrypt_e2: Array<Zq>,
    pub reencrypt_u_intt: Array<Array<Zq>>,
    pub reencrypt_v_intt: Array<Zq>,
}
