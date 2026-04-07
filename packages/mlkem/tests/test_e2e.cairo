use mlkem::ntt::{ntt_fast, intt_with_hint};
use mlkem::intt::intt;
use mlkem::zq::Zq;
use corelib_imports::bounded_int::downcast;

#[test]
fn test_intt_hint_pattern() {
    let mut input: Array<Zq> = array![];
    let mut i: u32 = 1;
    while i <= 256 {
        let f: felt252 = i.into();
        input.append(downcast(f).unwrap());
        i += 1;
    };
    let ntt_result = ntt_fast(input.span());
    let intt_result = intt(ntt_result.span());
    let _verified = intt_with_hint(ntt_result.span(), intt_result.span());
}
