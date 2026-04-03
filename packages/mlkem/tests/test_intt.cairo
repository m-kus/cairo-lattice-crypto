use mlkem::ntt::ntt_fast;
use mlkem::intt::intt;
use mlkem::zq::Zq;
use corelib_imports::bounded_int::downcast;

#[test]
fn test_intt_roundtrip() {
    // Create a simple polynomial: [1, 2, 3, ..., 256] mod Q
    let mut input: Array<Zq> = array![];
    let mut i: u32 = 1;
    while i <= 256 {
        let f: felt252 = i.into();
        input.append(downcast(f).unwrap());
        i += 1;
    };

    // NTT then INTT should give back original
    let ntt_result = ntt_fast(input.span());
    let intt_result = intt(ntt_result.span());

    assert_eq!(intt_result.len(), 256);
    let mut i: u32 = 0;
    while i < 256 {
        assert_eq!(
            *intt_result.at(i), *input.at(i), "INTT roundtrip failed at index {}", i,
        );
        i += 1;
    };
}
