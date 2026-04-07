use mlkem::compress::{
    compress_1, decompress_1, compress_4, decompress_4, compress_10, decompress_10,
};
use mlkem::zq::Zq;

fn zq(v: felt252) -> Zq {
    corelib_imports::bounded_int::downcast(v).unwrap()
}

fn zq_to_u32(v: Zq) -> u32 {
    let f: felt252 = corelib_imports::bounded_int::upcast(v);
    f.try_into().unwrap()
}

// =============================================================================
// d=1 tests
// =============================================================================

#[test]
fn test_compress_1_zero() {
    assert_eq!(compress_1(zq(0)), 0);
}

#[test]
fn test_compress_1_mid() {
    // Q/2 = 1664.5 -> x=1665 should compress to 1
    assert_eq!(compress_1(zq(1665)), 1);
}

#[test]
fn test_compress_1_max() {
    // compress_1(Q-1) = (2*3328 + 1664) / 3329 mod 2 = 2 mod 2 = 0
    assert_eq!(compress_1(zq(3328)), 0);
}

#[test]
fn test_decompress_1_zero() {
    assert_eq!(zq_to_u32(decompress_1(0)), 0);
}

#[test]
fn test_decompress_1_one() {
    // Decompress_1(1) = round(3329/2) = 1665
    assert_eq!(zq_to_u32(decompress_1(1)), 1665);
}

// =============================================================================
// d=4 tests
// =============================================================================

#[test]
fn test_compress_4_zero() {
    assert_eq!(compress_4(zq(0)), 0);
}

#[test]
fn test_compress_4_roundtrip() {
    // For d=4, check that decompress(compress(x)) is close to x
    let x = zq(1000);
    let compressed = compress_4(x);
    let decompressed = decompress_4(compressed);
    // Should be within Q/32 ~ 104 of original
    let diff = if zq_to_u32(decompressed) > 1000 {
        zq_to_u32(decompressed) - 1000
    } else {
        1000 - zq_to_u32(decompressed)
    };
    assert!(diff < 110, "Roundtrip error too large: {}", diff);
}

// =============================================================================
// d=10 tests
// =============================================================================

#[test]
fn test_compress_10_zero() {
    assert_eq!(compress_10(zq(0)), 0);
}

#[test]
fn test_compress_10_roundtrip() {
    // For d=10, roundtrip error should be small (within Q/2048 ~ 1.6)
    let x = zq(1500);
    let compressed = compress_10(x);
    let decompressed = decompress_10(compressed);
    let diff = if zq_to_u32(decompressed) > 1500 {
        zq_to_u32(decompressed) - 1500
    } else {
        1500 - zq_to_u32(decompressed)
    };
    assert!(diff <= 2, "d=10 roundtrip error too large: {}", diff);
}
