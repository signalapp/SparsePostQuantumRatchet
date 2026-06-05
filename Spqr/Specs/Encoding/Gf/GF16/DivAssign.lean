/-
Copyright 2026 The Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Hoang Le Truong
-/
import Spqr.Code.Funs
import Spqr.Math.Gf16.Field
import Spqr.Specs.Encoding.Gf.GF16.DivImpl

/-! # Spec theorem for `spqr.encoding.gf.GF16.Insts.CoreOpsArithDivAssignShared0GF16.div_assign`

In GF(2¹⁶) — the Galois field with 65 536 elements — every non-zero element `b` satisfies `b^(2¹⁶ −
1) = 1`, so the multiplicative inverse is `b⁻¹ = b^(2¹⁶ − 2)` and `a / b = a · b^(2¹⁶ − 2)`.  Field
multiplication is polynomial multiplication modulo the irreducible polynomial POLY = x¹⁶ + x¹² + x³
+ x + 1 (0x1100b); each field element is represented as a polynomial of degree < 16 with
coefficients in GF(2), stored as a 16-bit unsigned integer, and the `GF16` Rust type is the `u16`
wrapper providing the field operations.


The by-reference `DivAssign<&GF16>` introduces no additional logic beyond the delegation, so its
postcondition is inherited from the underlying `div_impl` specification: lifting the `u16` of the
result into `GF216 = GaloisField 2 16` via `Nat.toGF216` yields the GF(2¹⁶) Fermat-style quotient
`self · other^(2¹⁶ − 2)` of the lifts of `self.value` and `other.value`.

**Source**: spqr/src/encoding/gf.rs (lines 535:4-537:5) -/

open Aeneas Aeneas.Std

namespace spqr.encoding.gf.GF16.Insts.CoreOpsArithDivAssignShared0GF16

/-- **Spec theorem for `spqr.encoding.gf.GF16.Insts.CoreOpsArithDivAssignShared0GF16.div_assign`**:

• The function always succeeds (no panic) for any pair of `GF16` inputs, since the underlying
  `unaccelerated.mul` and the loop driver are total on `GF16 × GF16`.
• Lifting `result.value.val` into `GF216` via the canonical map
  `Nat.toGF216 = BinaryPoly.toGF216 ∘ natToBinaryPoly` yields the GF(2¹⁶) Fermat-style
  quotient of the similarly-lifted inputs:
    `result.toGF216  = self.toGF216 * other.toGF216 ^ (2 ^ 16 - 2)`
  where the operations on the right-hand side are performed in `GF216 = GaloisField 2 16`.
  When `other ≠ 0` Fermat's little theorem in GF(2¹⁶) gives `other^(2¹⁶ − 1) = 1`, so
  `other^(2¹⁶ − 2) = other⁻¹` and the right-hand side is genuinely
  the field quotient `self / other`. -/
@[step]
theorem div_assign_spec (self other : GF16) :
    div_assign self other ⦃ (result : GF16) =>
      result.toGF216 = self.toGF216 * other.toGF216 ^ (2 ^ 16 - 2) ⦄ := by
  unfold div_assign
  step*

end spqr.encoding.gf.GF16.Insts.CoreOpsArithDivAssignShared0GF16

/-! # Spec theorem for `spqr.encoding.gf.GF16.Insts.CoreOpsArithDivAssignGF16.div_assign`

The by-value `DivAssign<GF16> for GF16` takes `other` by value in the original Rust source.  In the
Aeneas extraction the by-value vs by-reference distinction is erased, so the Lean signature is
identical to the by-reference variant.  The implementation delegates directly to
`encoding.gf.GF16.div_impl`, the Fermat-style iterated-squaring GF(2¹⁶) division routine, performing
15 iterations of `out := out · square; square := square²` to compute `self · other^(2¹⁶ − 2)`.

Since the by-value `DivAssign` introduces no additional logic beyond the delegation, its
postcondition is inherited from the underlying `div_impl` specification.

**Source**: spqr/src/encoding/gf.rs (lines 542:4-544:5) -/

namespace spqr.encoding.gf.GF16.Insts.CoreOpsArithDivAssignGF16

/-- **Spec theorem for `spqr.encoding.gf.GF16.Insts.CoreOpsArithDivAssignGF16.div_assign`**:

• The function always succeeds (no panic) for any pair of `GF16` inputs, since the underlying
  `unaccelerated.mul` and the loop driver are total on `GF16 × GF16`.
• The by-value `DivAssign<GF16>::div_assign` delegates to the same `div_impl` and is observationally
  identical to the by-reference variant.
• Lifting `result.value.val` into `GF216` via the canonical map
  `Nat.toGF216 = BinaryPoly.toGF216 ∘ natToBinaryPoly` yields the GF(2¹⁶) Fermat-style
  quotient of the similarly-lifted inputs:
    `result.toGF216 = self.toGF216 * other.toGF216 ^ (2 ^ 16 - 2)`
  where the operations on the right-hand side are performed in
  `GF216 = GaloisField 2 16`.  When `other ≠ 0` Fermat's little theorem in GF(2¹⁶) gives
  `other^(2¹⁶ − 1) = 1`, so `other^(2¹⁶ − 2) = other⁻¹` and the right-hand side is genuinely
  the field quotient `self / other`. -/
@[step]
theorem div_assign_spec (self other : GF16) :
    div_assign self other ⦃ (result : GF16) =>
      result.toGF216 = self.toGF216 * other.toGF216 ^ (2 ^ 16 - 2) ⦄ := by
  unfold div_assign
  step*

end spqr.encoding.gf.GF16.Insts.CoreOpsArithDivAssignGF16
