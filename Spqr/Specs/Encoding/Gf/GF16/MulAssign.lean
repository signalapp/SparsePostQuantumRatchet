/-
Copyright 2026 The Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE-APACHE.
Authors: Hoang Le Truong
-/
import Spqr.Code.Funs
import Spqr.Math.Gf16.Field
import Spqr.Specs.Encoding.Gf.Unaccelerated.Mul

/-! # Spec theorem for `spqr::encoding::gf::GF16::mul_assign`

In GF(2¹⁶) — the Galois field with 65 536 elements — multiplication is polynomial multiplication
modulo the irreducible polynomial POLY = x¹⁶ + x¹² + x³ + x + 1 (0x1100b).  Each field element is
represented as a polynomial of degree < 16 with coefficients in GF(2), stored as a 16-bit unsigned
integer.

Concretely, `mul_assign self other` calls `unaccelerated.mul self.value other.value`, which:
  1. Performs `poly_mul` — carry-less (XOR-based) long multiplication
     of the two 16-bit inputs, producing a 32-bit unreduced product.
  2. Performs `poly_reduce` — reduction of the 32-bit product modulo
     POLY using a precomputed table (`REDUCE_BYTES`), yielding a
     16-bit canonical representative in GF(2¹⁶).

**Source**: spqr/src/encoding/gf.rs  -/

open Aeneas Aeneas.Std

namespace spqr.encoding.gf.GF16.Insts.CoreOpsArithMulAssignShared0GF16

/-- **Spec theorem for `encoding.gf.GF16.Insts.CoreOpsArithMulAssignShared0GF16.mul_assign`**:

• The function always succeeds (no panic) for any pair of `GF16` inputs, since `unaccelerated.mul`
  is total on `Std.U16 × Std.U16`.
• Lifting `result.value.val` into `GF216` via the canonical map
  `Nat.toGF216 = BinaryPoly.toGF216 ∘ natToBinaryPoly` yields the GF(2¹⁶) product of the
  similarly-lifted inputs:
    `result.toGF216 = self.toGF216 * other.toGF216`
  where the `*` on the right-hand side is multiplication in `GF216 = GaloisField 2 16`. -/
@[step]
theorem mul_assign_spec (self other : GF16) :
    mul_assign self other ⦃ (result : GF16) =>
      result.toGF216 = self.toGF216 * other.toGF216 ⦄ := by
  unfold mul_assign
  step*
  simp[GF16.toGF216]
  simp_all

end spqr.encoding.gf.GF16.Insts.CoreOpsArithMulAssignShared0GF16

/-! # Spec theorem for `spqr::encoding::gf::GF16::mul_assign`

In GF(2¹⁶) — the Galois field with 65 536 elements — multiplication is polynomial multiplication
modulo the irreducible polynomial POLY = x¹⁶ + x¹² + x³ + x + 1 (0x1100b).  Each field element is
represented as a polynomial of degree < 16 with coefficients in GF(2), stored as a 16-bit unsigned
integer.

The by-value `MulAssign` introduces no additional logic beyond the delegation, so its postcondition
is inherited from the by-reference `mul_assign` (and ultimately `unaccelerated.mul`) specification:
lifting the `u16` of the result into `GF216 = GaloisField 2 16` via `Nat.toGF216` yields the GF(2¹⁶)
product of the lifts of `self.value` and `other.value`.

**Source**: spqr/src/encoding/gf.rs  -/

namespace spqr.encoding.gf.GF16.Insts.CoreOpsArithMulAssignGF16

/-- **Spec theorem for `encoding.gf.GF16.Insts.CoreOpsArithMulAssignGF16.mul_assign`**:

• The function always succeeds (no panic) for any pair of `GF16` inputs, since the underlying
  `unaccelerated.mul` is total on `Std.U16 × Std.U16`.
• The by-value `MulAssign<GF16>::mul_assign` delegates to the by-reference variant and is
  observationally identical.
• Lifting `result.value.val` into `GF216` via the canonical map
  `Nat.toGF216 = BinaryPoly.toGF216 ∘ natToBinaryPoly` yields the GF(2¹⁶) product of the
  similarly-lifted inputs:
    `result.toGF216  = self.toGF216 * other.toGF216`
  where the `*` on the right-hand side is multiplication in `GF216 = GaloisField 2 16`. -/
@[step]
theorem mul_assign_spec (self other : GF16) :
    mul_assign self other ⦃ (result : GF16)=>
      result.toGF216 = self.toGF216 * other.toGF216 ⦄ := by
  unfold mul_assign
  step*

end spqr.encoding.gf.GF16.Insts.CoreOpsArithMulAssignGF16
