/-
Copyright 2026 The Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Hoang Le Truong
-/
import Spqr.Code.Funs
import Spqr.Math.Gf16.Field
import Spqr.Specs.Encoding.Gf.Unaccelerated.Mul2

/-! # Spec theorem for `encoding::gf::mul2_u16`

`mul2_u16 a b1 b2 = unaccelerated.mul2 a b1 b2`, so the postcondition is
inherited from `mul2_spec'` / `mul2_spec`.

**Source**: spqr/src/encoding/gf.rs -/

open Aeneas Aeneas.Std  spqr.encoding.gf.unaccelerated spqr.math.gf

namespace spqr.encoding.gf

/-- **Spec theorem for `encoding.gf.mul2_u16`**:

Two independent GF(2¹⁶) products sharing left operand `a`. Follows from `mul2_spec'` since
`mul2_u16` reduces to `unaccelerated.mul2`. -/
theorem mul2_u16_spec_poly (a b1 b2 : U16) :
    mul2_u16 a b1 b2 ⦃ (result : U16 × U16) =>
      natToBinaryPoly result.1.val =
        (natToBinaryPoly a.val * natToBinaryPoly b1.val) %ₘ polyGF2 ∧
      natToBinaryPoly result.2.val =
        (natToBinaryPoly a.val * natToBinaryPoly b2.val) %ₘ polyGF2 ⦄ := by
  unfold mul2_u16
  have h1 := mul_spec_nat a b1
  have h2 := mul_spec_nat a b2
  step*

/-- **Spec theorem for `encoding.gf.mul2_u16`**:

Both components of `mul2_u16 a b1 b2` correspond to `a · b1` and `a · b2` in `GF216`. -/
@[step]
theorem mul2_u16_spec (a b1 b2 : U16) :
    mul2_u16 a b1 b2 ⦃ (result : U16 × U16) =>
      result.1.val.toGF216 = a.val.toGF216 * b1.val.toGF216 ∧
      result.2.val.toGF216 = a.val.toGF216 * b2.val.toGF216 ⦄ := by
  unfold mul2_u16
  step*

end spqr.encoding.gf
