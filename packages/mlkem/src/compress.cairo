//! Compression and decompression for ML-KEM (FIPS 203 Section 4.2.1).
//!
//! Compress_d(x) = round(2^d * x / q) mod 2^d
//! Decompress_d(y) = round(q * y / 2^d)
//!
//! Uses u32 arithmetic since all intermediate values fit comfortably.

use corelib_imports::bounded_int::{downcast, upcast};
use crate::zq::Zq;

const Q: u32 = 3329;
const HALF_Q: u32 = 1664; // floor(Q/2)

/// Compress_d(x) = ((2^d * x + floor(q/2)) / q) mod 2^d
#[inline(always)]
fn compress_d(x: Zq, d: u32, two_pow_d: u32) -> u32 {
    let x_u32: u32 = upcast::<Zq, felt252>(x).try_into().unwrap();
    ((x_u32 * two_pow_d + HALF_Q) / Q) % two_pow_d
}

/// Decompress_d(y) = (q * y + 2^(d-1)) / 2^d
#[inline(always)]
fn decompress_d(y: u32, d: u32, two_pow_d: u32) -> Zq {
    let half_pow: u32 = two_pow_d / 2;
    let result = (Q * y + half_pow) / two_pow_d;
    downcast(Into::<u32, felt252>::into(result)).expect('decompress out of range')
}

// =============================================================================
// d=1: message encoding
// =============================================================================

pub fn compress_1(x: Zq) -> u8 {
    compress_d(x, 1, 2).try_into().unwrap()
}

pub fn decompress_1(y: u8) -> Zq {
    decompress_d(y.into(), 1, 2)
}

// =============================================================================
// d=4: dv for ML-KEM-768
// =============================================================================

pub fn compress_4(x: Zq) -> u8 {
    compress_d(x, 4, 16).try_into().unwrap()
}

pub fn decompress_4(y: u8) -> Zq {
    decompress_d(y.into(), 4, 16)
}

// =============================================================================
// d=10: du for ML-KEM-768
// =============================================================================

pub fn compress_10(x: Zq) -> u16 {
    compress_d(x, 10, 1024).try_into().unwrap()
}

pub fn decompress_10(y: u16) -> Zq {
    decompress_d(y.into(), 10, 1024)
}

// =============================================================================
// d=11: du for ML-KEM-1024
// =============================================================================

pub fn compress_11(x: Zq) -> u16 {
    compress_d(x, 11, 2048).try_into().unwrap()
}

pub fn decompress_11(y: u16) -> Zq {
    decompress_d(y.into(), 11, 2048)
}
