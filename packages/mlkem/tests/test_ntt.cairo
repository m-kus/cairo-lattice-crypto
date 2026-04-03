use mlkem::ntt::ntt_fast;
use mlkem::zq::Zq;
use snforge_std::fs::{FileTrait, read_json};

#[derive(Drop, Serde)]
struct NttTest {
    input: Array<Zq>,
    expected: Array<Zq>,
}

fn load_ntt_test() -> NttTest {
    let file = FileTrait::new("tests/data/ntt_test_int.json");
    let serialized = read_json(@file);
    let mut span = serialized.span();
    let _header = span.pop_front();
    Serde::deserialize(ref span).expect('deserialize failed')
}

#[test]
fn test_ntt_256_matches_reference() {
    let test = load_ntt_test();
    let result = ntt_fast(test.input.span());
    assert_eq!(result.len(), 256);

    let mut i: u32 = 0;
    while i < 256 {
        assert_eq!(*result.at(i), *test.expected.at(i), "NTT mismatch at index {}", i);
        i += 1;
    };
}

#[test]
fn test_ntt_256_zero_input() {
    let mut input: Array<Zq> = array![];
    let zero: Zq = corelib_imports::bounded_int::downcast(0_felt252).unwrap();
    let mut i: u32 = 0;
    while i < 256 {
        input.append(zero);
        i += 1;
    };
    let result = ntt_fast(input.span());
    assert_eq!(result.len(), 256);
    let mut i: u32 = 0;
    while i < 256 {
        assert_eq!(*result.at(i), zero, "NTT(0) should be 0 at index {}", i);
        i += 1;
    };
}
