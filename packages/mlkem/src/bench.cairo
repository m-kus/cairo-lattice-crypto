//! Executable entry points for profiling.

use crate::keygen::{keygen, message_from_seed, prepare_encaps_hint, prepare_decaps_hint};
use crate::mlkem::{encapsulate, decapsulate};

/// Profile decaps for flamegraph.
#[executable]
pub fn main() {
    let (ek, s_hat, a) = keygen(12345);
    let m = message_from_seed(67890);
    let eh = prepare_encaps_hint(@ek, @a, m.span());
    let (_k, ct) = encapsulate(@ek, @a, m.span(), eh);
    let dh = prepare_decaps_hint(@ek, @a, @s_hat, @ct);
    let _recovered = decapsulate(@ek, @a, @ct, dh);
}

/// Keygen only (baseline).
#[executable]
pub fn bench_keygen() {
    let (_ek, _s_hat, _a) = keygen(12345);
    let _m = message_from_seed(67890);
}

/// Keygen + encaps hint prep (subtract to get encapsulate cost).
#[executable]
pub fn bench_encaps_setup() {
    let (ek, _s_hat, a) = keygen(12345);
    let m = message_from_seed(67890);
    let _eh = prepare_encaps_hint(@ek, @a, m.span());
}

/// Keygen + encaps hint prep + encapsulate.
#[executable]
pub fn bench_encaps() {
    let (ek, _s_hat, a) = keygen(12345);
    let m = message_from_seed(67890);
    let eh = prepare_encaps_hint(@ek, @a, m.span());
    let (_k, _ct) = encapsulate(@ek, @a, m.span(), eh);
}

/// Full up to decaps hint prep (subtract to get decapsulate cost).
#[executable]
pub fn bench_decaps_setup() {
    let (ek, s_hat, a) = keygen(12345);
    let m = message_from_seed(67890);
    let eh = prepare_encaps_hint(@ek, @a, m.span());
    let (_k, ct) = encapsulate(@ek, @a, m.span(), eh);
    let _dh = prepare_decaps_hint(@ek, @a, @s_hat, @ct);
}

/// Full e2e.
#[executable]
pub fn bench_decaps() {
    let (ek, s_hat, a) = keygen(12345);
    let m = message_from_seed(67890);
    let eh = prepare_encaps_hint(@ek, @a, m.span());
    let (_k, ct) = encapsulate(@ek, @a, m.span(), eh);
    let dh = prepare_decaps_hint(@ek, @a, @s_hat, @ct);
    let _recovered = decapsulate(@ek, @a, @ct, dh);
}
