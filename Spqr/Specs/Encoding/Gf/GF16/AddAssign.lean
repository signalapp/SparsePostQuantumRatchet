/-
Copyright 2026 The Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE-APACHE.
Authors: Hoang Le Truong
-/
import SrcTranslated.Funs
import Mathlib.Data.Nat.Bitwise
import Spqr.Math.Gf16.Field
/-!
# Spec theorem for `spqr::encoding::gf::{impl ops::AddAssign<&GF16> for GF16}::add_assign`

In GF(2¹⁶) — the Galois field with 65 536 elements — addition is simply bitwise XOR of the two
16-bit underlying values.  This follows from the fact that GF(2¹⁶) has characteristic 2, so
addition of polynomial coefficients is addition in GF(2), which is XOR.

Note that in GF(2¹⁶), addition and subtraction coincide:
  `a + b = a - b = a ⊕ b`
since every element is its own additive inverse (`a + a = 0`).

**Source**: spqr/src/encoding/gf.rs (lines 28:4-31:5)
-/

open Aeneas Aeneas.Std Result spqr.math.gf spqr.encoding.gf

namespace spqr.encoding.gf.GF16.Insts.CoreOpsArithAddAssignShared0GF16

/-- **Spec theorem for `spqr.encoding.gf.GF16.Insts.CoreOpsArithAddAssignShared0GF16.add_assign`**:

The result satisfies the GF(2¹⁶)-level postcondition:

  `result.value.val.toGF216 = self.value.val.toGF216 + other.value.val.toGF216` -/
@[step]
theorem add_assign_spec (self other : GF16) :
    add_assign self other ⦃ (result : GF16) =>
      result.toGF216 = self.toGF216 + other.toGF216 ⦄ := by
  unfold add_assign
  step*
  simp_all only [UScalar.val_xor, GF16.toGF216, Nat.toGF216, natToBinaryPoly_xor, map_add]

end spqr.encoding.gf.GF16.Insts.CoreOpsArithAddAssignShared0GF16

/-! # Spec theorem for `spqr::encoding::gf::{impl ops::AddAssign for GF16}::add_assign`

In GF(2¹⁶) — the Galois field with 65 536 elements — addition is simply bitwise XOR of the two
16-bit underlying values.  This follows from the fact that GF(2¹⁶) has characteristic 2, so addition
of polynomial coefficients is addition in GF(2), which is XOR.

Note that in GF(2¹⁶), addition and subtraction coincide:
  `a + b = a - b = a ⊕ b`
since every element is its own additive inverse (`a + a = 0`).

**Source**: spqr/src/encoding/gf.rs (lines 40:4-43:5)
-/

namespace spqr.encoding.gf.GF16.Insts.CoreOpsArithAddAssignGF16

/-- **Spec theorem for `spqr.encoding.gf.GF16.Insts.CoreOpsArithAddAssignGF16.add_assign`**:

The result satisfies the GF(2¹⁶)-level postcondition:

  `result.value.val.toGF216  = self.value.val.toGF216 + other.value.val.toGF216` -/
@[step]
theorem add_assign_spec (self other : GF16) :
    add_assign self other ⦃ (result : GF16) =>
      result.toGF216 = self.toGF216 + other.toGF216 ⦄ := by
  unfold add_assign
  step*

end spqr.encoding.gf.GF16.Insts.CoreOpsArithAddAssignGF16
