//! Operations on the base ring Z_q (q=3329) using BoundedInt with lazy modular reduction

use corelib_imports::bounded_int::bounded_int::{SubHelper, add, mul, sub};
use corelib_imports::bounded_int::{
    AddHelper, BoundedInt, DivRemHelper, MulHelper, UnitInt, bounded_int_div_rem, downcast, upcast,
};

/// BoundedInt type for elements in Z_q: [0, Q-1] = [0, 3328]
pub type Zq = BoundedInt<0, 3328>;

/// Singleton type for the modulus Q
pub type QConst = UnitInt<3329>;

/// Constant Q as BoundedInt
pub const Q_CONST: QConst = 3329;

/// Q as a NonZero constant for division
pub const NZ_Q: NonZero<QConst> = 3329;

// =============================================================================
// Type conversion utilities
// =============================================================================

/// Convert u16 to Zq (requires range check - use only at deserialization boundaries)
#[inline(always)]
pub fn from_u16(x: u16) -> Zq {
    downcast(x).expect('value exceeds Q-1')
}

// =============================================================================
// Intermediate bound types for lazy reduction
// =============================================================================

/// Sum of two Zq values: [0, 6656]
pub type ZqSum = BoundedInt<0, 6656>;

/// Difference after adding offset Q: (a + Q) - b gives [1, 6657]
pub type ZqDiffOffset = BoundedInt<1, 6657>;

/// Product of two Zq values: [0, 11075584]  (3328^2)
pub type ZqProd = BoundedInt<0, 11075584>;

// =============================================================================
// AddHelper implementations
// =============================================================================

impl AddZqZqImpl of AddHelper<Zq, Zq> {
    type Result = ZqSum;
}

impl AddZqQImpl of AddHelper<Zq, QConst> {
    type Result = BoundedInt<3329, 6657>;
}

// =============================================================================
// SubHelper implementations
// =============================================================================

impl SubZqOffsetZqImpl of SubHelper<BoundedInt<3329, 6657>, Zq> {
    type Result = ZqDiffOffset;
}

// =============================================================================
// MulHelper implementations
// =============================================================================

impl MulZqZqImpl of MulHelper<Zq, Zq> {
    type Result = ZqProd;
}

// =============================================================================
// DivRemHelper implementations for modular reduction
// =============================================================================

impl DivRemZqProdImpl of DivRemHelper<ZqProd, QConst> {
    type DivT = BoundedInt<0, 3327>;
    type RemT = Zq;
}

impl DivRemZqSumImpl of DivRemHelper<ZqSum, QConst> {
    type DivT = BoundedInt<0, 1>;
    type RemT = Zq;
}

impl DivRemZqDiffOffsetImpl of DivRemHelper<ZqDiffOffset, QConst> {
    type DivT = BoundedInt<0, 1>;
    type RemT = Zq;
}

// =============================================================================
// Modular arithmetic operations (BoundedInt in, BoundedInt out)
// =============================================================================

/// Add two Zq values and reduce mod Q
#[inline(always)]
pub fn add_mod(a: Zq, b: Zq) -> Zq {
    let sum: ZqSum = add(a, b);
    let (_q, rem) = bounded_int_div_rem(sum, NZ_Q);
    rem
}

/// Subtract two Zq values and reduce mod Q
/// Uses the identity: (a - b) mod Q = (a + Q - b) mod Q
#[inline(always)]
pub fn sub_mod(a: Zq, b: Zq) -> Zq {
    let a_plus_q: BoundedInt<3329, 6657> = add(a, Q_CONST);
    let diff: ZqDiffOffset = sub(a_plus_q, b);
    let (_q, rem) = bounded_int_div_rem(diff, NZ_Q);
    rem
}

/// Multiply two Zq values and reduce mod Q
#[inline(always)]
pub fn mul_mod(a: Zq, b: Zq) -> Zq {
    let prod: ZqProd = mul(a, b);
    let (_q, rem) = bounded_int_div_rem(prod, NZ_Q);
    rem
}

// =============================================================================
// Serde implementation for Zq (felt252 <-> Zq conversion for JSON test data)
// =============================================================================

impl ZqSerde of Serde<Zq> {
    fn serialize(self: @Zq, ref output: Array<felt252>) {
        output.append(upcast(*self));
    }
    fn deserialize(ref serialized: Span<felt252>) -> Option<Zq> {
        let felt_val: felt252 = Serde::deserialize(ref serialized)?;
        downcast(felt_val)
    }
}
