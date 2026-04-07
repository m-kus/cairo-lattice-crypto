use mlkem::keygen::{keygen, message_from_seed, prepare_encaps_hint, prepare_decaps_hint};
use mlkem::mlkem::{encapsulate, decapsulate};

// ═════════════════════════════════════════════════════════════════════
// Full benchmarks (setup + on-chain operation in one test)
// Gas includes off-chain hint preparation (naive INTT).
// ═════════════════════════════════════════════════════════════════════

#[test]
fn bench_encapsulate() {
    let (ek, _s_hat) = keygen(12345);
    let m = message_from_seed(67890);
    let hint = prepare_encaps_hint(@ek, m.span());
    let (_k, _ct) = encapsulate(@ek, m.span(), hint);
}

#[test]
fn bench_decapsulate() {
    let (ek, s_hat) = keygen(12345);
    let m = message_from_seed(67890);
    let eh = prepare_encaps_hint(@ek, m.span());
    let (_k, ct) = encapsulate(@ek, m.span(), eh);
    let dh = prepare_decaps_hint(@ek, @s_hat, @ct);
    let _recovered = decapsulate(@ek, @ct, dh);
}

// ═════════════════════════════════════════════════════════════════════
// Encapsulate-only: setup is shared via keygen fixture.
// This measures ONLY the encapsulate function (on-chain cost).
// ═════════════════════════════════════════════════════════════════════

/// Baseline: just keygen + hint prep (off-chain).
/// Subtract from bench_encapsulate_with_setup to get on-chain cost.
#[test]
fn bench_setup_encaps_only() {
    let (ek, _s_hat) = keygen(12345);
    let m = message_from_seed(67890);
    let _hint = prepare_encaps_hint(@ek, m.span());
}

/// Baseline: keygen + encaps + hint prep (off-chain).
/// Subtract from bench_decapsulate to get on-chain decaps cost.
#[test]
fn bench_setup_decaps_only() {
    let (ek, s_hat) = keygen(12345);
    let m = message_from_seed(67890);
    let eh = prepare_encaps_hint(@ek, m.span());
    let (_k, ct) = encapsulate(@ek, m.span(), eh);
    let _dh = prepare_decaps_hint(@ek, @s_hat, @ct);
}
