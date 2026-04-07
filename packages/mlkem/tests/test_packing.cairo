use mlkem::packing::{pack_polynomial, unpack_polynomial};
use mlkem::zq::Zq;
use snforge_std::fs::{FileTrait, read_json};

#[derive(Drop, Serde)]
struct PackingTest {
    values: Array<Zq>,
}

fn load_packing_test() -> PackingTest {
    let file = FileTrait::new("tests/data/packing_test_int.json");
    let serialized = read_json(@file);
    let mut span = serialized.span();
    let _header = span.pop_front();
    Serde::deserialize(ref span).expect('deserialize failed')
}

#[test]
fn test_pack_unpack_roundtrip() {
    let test = load_packing_test();
    let values = test.values;

    // Pack
    let packed = pack_polynomial(values.span());
    assert_eq!(packed.len(), 13, "Expected 13 packed slots");

    // Unpack
    let unpacked = unpack_polynomial(packed.span());
    assert_eq!(unpacked.len(), 256, "Expected 256 unpacked values");

    // Verify roundtrip
    let mut i: u32 = 0;
    while i < 256 {
        assert_eq!(*unpacked.at(i), *values.at(i), "Roundtrip mismatch at index {}", i);
        i += 1;
    };
}

#[test]
fn test_pack_unpack_zeros() {
    let zero: Zq = corelib_imports::bounded_int::downcast(0_felt252).unwrap();
    let mut values: Array<Zq> = array![];
    let mut i: u32 = 0;
    while i < 256 {
        values.append(zero);
        i += 1;
    };

    let packed = pack_polynomial(values.span());
    let unpacked = unpack_polynomial(packed.span());

    let mut i: u32 = 0;
    while i < 256 {
        assert_eq!(*unpacked.at(i), zero, "Zero roundtrip failed at index {}", i);
        i += 1;
    };
}
