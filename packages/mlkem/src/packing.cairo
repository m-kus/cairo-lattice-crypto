//! Base-Q polynomial packing for storage-efficient ML-KEM polynomials.
//!
//! Packs 256 Zq values into 13 felt252 slots using base Q=3329 encoding:
//!   felt252 = pack_10(v0..v9) + pack_10(v10..v19) * 2^128
//!
//! DivRem by Q gives RemT = Zq directly — zero downcasts in the hot path.

use corelib_imports::bounded_int::bounded_int::{add, mul};
use corelib_imports::bounded_int::{
    AddHelper, BoundedInt, DivRemHelper, MulHelper, bounded_int_div_rem, downcast, upcast,
};
use crate::zq::{NZ_Q, QConst, Q_CONST, Zq};

// =============================================================================
// Constants
// =============================================================================

/// Number of Zq values per u128 half (Q^10 < 2^128)
const VALS_PER_U128: usize = 10;

/// Number of Zq values per felt252 (two u128 halves)
const VALS_PER_FELT: usize = 20;

/// Total felt252 slots for 256 values: ceil(256/20) = 13
const PACKED_SLOTS: usize = 13;

/// 2^128 as felt252 for combining u128 halves
const TWO_POW_128: felt252 = 0x100000000000000000000000000000000;

// =============================================================================
// Accumulator type chain: AccN max = Q^(N+1) - 1
// Acc0 = Zq (reused from zq.cairo)
// =============================================================================

type Acc0 = Zq; // BoundedInt<0, 3328>
type Acc1 = BoundedInt<0, 11082240>;
type Acc2 = BoundedInt<0, 36892780288>;
type Acc3 = BoundedInt<0, 122816065582080>;
type Acc4 = BoundedInt<0, 408854682322747648>;
type Acc5 = BoundedInt<0, 1361077237452426923520>;
type Acc6 = BoundedInt<0, 4531026123479129228401408>;
type Acc7 = BoundedInt<0, 15083785965062021201348290560>;
type Acc8 = BoundedInt<0, 50213923477691468579288459277568>;
type Acc9 = BoundedInt<0, 167162151257234898900451280935027200>;

// =============================================================================
// MulHelper intermediate types: MulQAccN max = Q * (Q^(N+1) - 1) = Q^(N+2) - Q
// =============================================================================

type MulQAcc0 = BoundedInt<0, 11078912>;
type MulQAcc1 = BoundedInt<0, 36892776960>;
type MulQAcc2 = BoundedInt<0, 122816065578752>;
type MulQAcc3 = BoundedInt<0, 408854682322744320>;
type MulQAcc4 = BoundedInt<0, 1361077237452426920192>;
type MulQAcc5 = BoundedInt<0, 4531026123479129228398080>;
type MulQAcc6 = BoundedInt<0, 15083785965062021201348287232>;
type MulQAcc7 = BoundedInt<0, 50213923477691468579288459274240>;
type MulQAcc8 = BoundedInt<0, 167162151257234898900451280935023872>;

// =============================================================================
// MulHelper impls: QConst * AccN -> MulQAccN
// =============================================================================

impl MulQAcc0Impl of MulHelper<QConst, Acc0> {
    type Result = MulQAcc0;
}
impl MulQAcc1Impl of MulHelper<QConst, Acc1> {
    type Result = MulQAcc1;
}
impl MulQAcc2Impl of MulHelper<QConst, Acc2> {
    type Result = MulQAcc2;
}
impl MulQAcc3Impl of MulHelper<QConst, Acc3> {
    type Result = MulQAcc3;
}
impl MulQAcc4Impl of MulHelper<QConst, Acc4> {
    type Result = MulQAcc4;
}
impl MulQAcc5Impl of MulHelper<QConst, Acc5> {
    type Result = MulQAcc5;
}
impl MulQAcc6Impl of MulHelper<QConst, Acc6> {
    type Result = MulQAcc6;
}
impl MulQAcc7Impl of MulHelper<QConst, Acc7> {
    type Result = MulQAcc7;
}
impl MulQAcc8Impl of MulHelper<QConst, Acc8> {
    type Result = MulQAcc8;
}

// =============================================================================
// AddHelper impls: Zq + MulQAccN -> Acc(N+1)
// =============================================================================

impl AddZqMulQAcc0Impl of AddHelper<Zq, MulQAcc0> {
    type Result = Acc1;
}
impl AddZqMulQAcc1Impl of AddHelper<Zq, MulQAcc1> {
    type Result = Acc2;
}
impl AddZqMulQAcc2Impl of AddHelper<Zq, MulQAcc2> {
    type Result = Acc3;
}
impl AddZqMulQAcc3Impl of AddHelper<Zq, MulQAcc3> {
    type Result = Acc4;
}
impl AddZqMulQAcc4Impl of AddHelper<Zq, MulQAcc4> {
    type Result = Acc5;
}
impl AddZqMulQAcc5Impl of AddHelper<Zq, MulQAcc5> {
    type Result = Acc6;
}
impl AddZqMulQAcc6Impl of AddHelper<Zq, MulQAcc6> {
    type Result = Acc7;
}
impl AddZqMulQAcc7Impl of AddHelper<Zq, MulQAcc7> {
    type Result = Acc8;
}
impl AddZqMulQAcc8Impl of AddHelper<Zq, MulQAcc8> {
    type Result = Acc9;
}

// =============================================================================
// DivRemHelper impls: AccN / QConst -> (Acc(N-1), Zq)
// =============================================================================

impl DivRemAcc1Impl of DivRemHelper<Acc1, QConst> {
    type DivT = Acc0;
    type RemT = Zq;
}
impl DivRemAcc2Impl of DivRemHelper<Acc2, QConst> {
    type DivT = Acc1;
    type RemT = Zq;
}
impl DivRemAcc3Impl of DivRemHelper<Acc3, QConst> {
    type DivT = Acc2;
    type RemT = Zq;
}
impl DivRemAcc4Impl of DivRemHelper<Acc4, QConst> {
    type DivT = Acc3;
    type RemT = Zq;
}
impl DivRemAcc5Impl of DivRemHelper<Acc5, QConst> {
    type DivT = Acc4;
    type RemT = Zq;
}
impl DivRemAcc6Impl of DivRemHelper<Acc6, QConst> {
    type DivT = Acc5;
    type RemT = Zq;
}
impl DivRemAcc7Impl of DivRemHelper<Acc7, QConst> {
    type DivT = Acc6;
    type RemT = Zq;
}
impl DivRemAcc8Impl of DivRemHelper<Acc8, QConst> {
    type DivT = Acc7;
    type RemT = Zq;
}
impl DivRemAcc9Impl of DivRemHelper<Acc9, QConst> {
    type DivT = Acc8;
    type RemT = Zq;
}

// =============================================================================
// Packing functions
// =============================================================================

#[inline(always)]
fn v(vals: Span<Zq>, i: usize) -> Zq {
    *vals.at(i)
}

/// Horner-encode up to 10 Zq values into a u128.
/// Encoding: v0 + Q*(v1 + Q*(v2 + ... + Q*v9))
fn pack_10(vals: Span<Zq>) -> u128 {
    let n = vals.len();
    match n {
        0 => 0_u128,
        1 => { upcast(v(vals, 0)) },
        2 => {
            let a1: Acc1 = add(v(vals, 0), mul(Q_CONST, v(vals, 1)));
            upcast(a1)
        },
        3 => {
            let a1: Acc1 = add(v(vals, 1), mul(Q_CONST, v(vals, 2)));
            let a2: Acc2 = add(v(vals, 0), mul(Q_CONST, a1));
            upcast(a2)
        },
        4 => {
            let a1: Acc1 = add(v(vals, 2), mul(Q_CONST, v(vals, 3)));
            let a2: Acc2 = add(v(vals, 1), mul(Q_CONST, a1));
            let a3: Acc3 = add(v(vals, 0), mul(Q_CONST, a2));
            upcast(a3)
        },
        5 => {
            let a1: Acc1 = add(v(vals, 3), mul(Q_CONST, v(vals, 4)));
            let a2: Acc2 = add(v(vals, 2), mul(Q_CONST, a1));
            let a3: Acc3 = add(v(vals, 1), mul(Q_CONST, a2));
            let a4: Acc4 = add(v(vals, 0), mul(Q_CONST, a3));
            upcast(a4)
        },
        6 => {
            let a1: Acc1 = add(v(vals, 4), mul(Q_CONST, v(vals, 5)));
            let a2: Acc2 = add(v(vals, 3), mul(Q_CONST, a1));
            let a3: Acc3 = add(v(vals, 2), mul(Q_CONST, a2));
            let a4: Acc4 = add(v(vals, 1), mul(Q_CONST, a3));
            let a5: Acc5 = add(v(vals, 0), mul(Q_CONST, a4));
            upcast(a5)
        },
        7 => {
            let a1: Acc1 = add(v(vals, 5), mul(Q_CONST, v(vals, 6)));
            let a2: Acc2 = add(v(vals, 4), mul(Q_CONST, a1));
            let a3: Acc3 = add(v(vals, 3), mul(Q_CONST, a2));
            let a4: Acc4 = add(v(vals, 2), mul(Q_CONST, a3));
            let a5: Acc5 = add(v(vals, 1), mul(Q_CONST, a4));
            let a6: Acc6 = add(v(vals, 0), mul(Q_CONST, a5));
            upcast(a6)
        },
        8 => {
            let a1: Acc1 = add(v(vals, 6), mul(Q_CONST, v(vals, 7)));
            let a2: Acc2 = add(v(vals, 5), mul(Q_CONST, a1));
            let a3: Acc3 = add(v(vals, 4), mul(Q_CONST, a2));
            let a4: Acc4 = add(v(vals, 3), mul(Q_CONST, a3));
            let a5: Acc5 = add(v(vals, 2), mul(Q_CONST, a4));
            let a6: Acc6 = add(v(vals, 1), mul(Q_CONST, a5));
            let a7: Acc7 = add(v(vals, 0), mul(Q_CONST, a6));
            upcast(a7)
        },
        9 => {
            let a1: Acc1 = add(v(vals, 7), mul(Q_CONST, v(vals, 8)));
            let a2: Acc2 = add(v(vals, 6), mul(Q_CONST, a1));
            let a3: Acc3 = add(v(vals, 5), mul(Q_CONST, a2));
            let a4: Acc4 = add(v(vals, 4), mul(Q_CONST, a3));
            let a5: Acc5 = add(v(vals, 3), mul(Q_CONST, a4));
            let a6: Acc6 = add(v(vals, 2), mul(Q_CONST, a5));
            let a7: Acc7 = add(v(vals, 1), mul(Q_CONST, a6));
            let a8: Acc8 = add(v(vals, 0), mul(Q_CONST, a7));
            upcast(a8)
        },
        10 => {
            let a1: Acc1 = add(v(vals, 8), mul(Q_CONST, v(vals, 9)));
            let a2: Acc2 = add(v(vals, 7), mul(Q_CONST, a1));
            let a3: Acc3 = add(v(vals, 6), mul(Q_CONST, a2));
            let a4: Acc4 = add(v(vals, 5), mul(Q_CONST, a3));
            let a5: Acc5 = add(v(vals, 4), mul(Q_CONST, a4));
            let a6: Acc6 = add(v(vals, 3), mul(Q_CONST, a5));
            let a7: Acc7 = add(v(vals, 2), mul(Q_CONST, a6));
            let a8: Acc8 = add(v(vals, 1), mul(Q_CONST, a7));
            let a9: Acc9 = add(v(vals, 0), mul(Q_CONST, a8));
            upcast(a9)
        },
        _ => core::panic_with_felt252('pack_10: count > 10'),
    }
}

/// Unpack a u128 into exactly 10 Zq values using iterated DivRem by Q.
fn unpack_10_full(packed: u128, ref output: Array<Zq>) {
    let acc9: Acc9 = downcast(packed).expect('bad pack');
    let (acc8, r0) = bounded_int_div_rem(acc9, NZ_Q);
    output.append(r0);
    let (acc7, r1) = bounded_int_div_rem(acc8, NZ_Q);
    output.append(r1);
    let (acc6, r2) = bounded_int_div_rem(acc7, NZ_Q);
    output.append(r2);
    let (acc5, r3) = bounded_int_div_rem(acc6, NZ_Q);
    output.append(r3);
    let (acc4, r4) = bounded_int_div_rem(acc5, NZ_Q);
    output.append(r4);
    let (acc3, r5) = bounded_int_div_rem(acc4, NZ_Q);
    output.append(r5);
    let (acc2, r6) = bounded_int_div_rem(acc3, NZ_Q);
    output.append(r6);
    let (acc1, r7) = bounded_int_div_rem(acc2, NZ_Q);
    output.append(r7);
    let (acc0, r8) = bounded_int_div_rem(acc1, NZ_Q);
    output.append(r8);
    output.append(acc0);
}

/// Unpack a u128 into `count` Zq values (count <= 10).
fn unpack_10(packed: u128, count: usize, ref output: Array<Zq>) {
    if count == 0 {
        return;
    }
    let acc9: Acc9 = downcast(packed).expect('bad pack');
    let (acc8, r0) = bounded_int_div_rem(acc9, NZ_Q);
    output.append(r0);
    if count == 1 {
        return;
    }
    let (acc7, r1) = bounded_int_div_rem(acc8, NZ_Q);
    output.append(r1);
    if count == 2 {
        return;
    }
    let (acc6, r2) = bounded_int_div_rem(acc7, NZ_Q);
    output.append(r2);
    if count == 3 {
        return;
    }
    let (acc5, r3) = bounded_int_div_rem(acc6, NZ_Q);
    output.append(r3);
    if count == 4 {
        return;
    }
    let (acc4, r4) = bounded_int_div_rem(acc5, NZ_Q);
    output.append(r4);
    if count == 5 {
        return;
    }
    let (acc3, r5) = bounded_int_div_rem(acc4, NZ_Q);
    output.append(r5);
    if count == 6 {
        return;
    }
    let (acc2, r6) = bounded_int_div_rem(acc3, NZ_Q);
    output.append(r6);
    if count == 7 {
        return;
    }
    let (acc1, r7) = bounded_int_div_rem(acc2, NZ_Q);
    output.append(r7);
    if count == 8 {
        return;
    }
    let (acc0, r8) = bounded_int_div_rem(acc1, NZ_Q);
    output.append(r8);
    if count == 9 {
        return;
    }
    output.append(acc0);
}

// =============================================================================
// Public API: pack/unpack 256-element polynomials
// =============================================================================

/// Pack 256 Zq values into an array of felt252 (13 slots).
pub fn pack_polynomial(values: Span<Zq>) -> Array<felt252> {
    assert(values.len() == 256, 'expected 256 values');
    let mut result: Array<felt252> = array![];
    let mut offset: usize = 0;

    // 12 full slots: 20 values each (10 low + 10 high)
    while offset + VALS_PER_FELT <= 256 {
        let lo = pack_10(values.slice(offset, 10));
        let hi = pack_10(values.slice(offset + 10, 10));
        let slot: felt252 = lo.into() + hi.into() * TWO_POW_128;
        result.append(slot);
        offset += VALS_PER_FELT;
    };

    // Partial slot: 16 remaining values (8 low + 8 high)
    if offset < 256 {
        let remaining = 256 - offset;
        let lo_count = remaining / 2;
        let hi_count = remaining - lo_count;
        let lo = pack_10(values.slice(offset, lo_count));
        let hi = pack_10(values.slice(offset + lo_count, hi_count));
        let slot: felt252 = lo.into() + hi.into() * TWO_POW_128;
        result.append(slot);
    }

    result
}

/// Unpack felt252 slots back into 256 Zq values.
pub fn unpack_polynomial(packed: Span<felt252>) -> Array<Zq> {
    assert(packed.len() == PACKED_SLOTS, 'expected 13 slots');
    let mut result: Array<Zq> = array![];
    let mut slot_idx: usize = 0;

    // 12 full slots: 20 values each
    while slot_idx < 12 {
        let slot: felt252 = *packed.at(slot_idx);
        let (hi_felt, lo) = split_felt252(slot);
        unpack_10_full(lo, ref result);
        unpack_10_full(hi_felt, ref result);
        slot_idx += 1;
    };

    // Partial slot: 16 remaining values (8 low + 8 high)
    let slot: felt252 = *packed.at(12);
    let (hi_felt, lo) = split_felt252(slot);
    unpack_10(lo, 8, ref result);
    unpack_10(hi_felt, 8, ref result);

    result
}

/// Split a felt252 into (high_u128, low_u128).
fn split_felt252(value: felt252) -> (u128, u128) {
    let wide: u256 = value.into();
    (wide.high, wide.low)
}
