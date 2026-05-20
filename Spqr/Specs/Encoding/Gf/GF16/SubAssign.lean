/-
Copyright 2026 The Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Hoang Le Truong
-/
import Spqr.Code.Funs
import Spqr.Specs.Encoding.Gf.GF16.AddAssign
/-!
# Spec theorem for `spqr::encoding::gf::{impl ops::SubAssign for GF16}::sub_assign`

In GF(2¹⁶) — the Galois field with 65 536 elements — subtraction is simply bitwise XOR of the two
16-bit underlying values.  This follows from the fact that GF(2¹⁶) has characteristic 2, so every
element is its own additive inverse (`a + a = 0`), meaning subtraction and addition coincide:
  `a - b = a + b = a ⊕ b`

The by-value `SubAssign<GF16> for GF16` wrapper delegates directly to this by-reference variant,
introducing no additional logic — the two are observationally identical:
  `sub_assign_val(a, b) = sub_assign_ref(a, b)`

**Source**: spqr/src/encoding/gf.rs (lines 81:4-83:5)
-/

open Aeneas Aeneas.Std

namespace spqr.encoding.gf.GF16.Insts.CoreOpsArithSubAssignShared0GF16

/--
**Spec theorem for `spqr.encoding.gf.GF16.Insts.CoreOpsArithSubAssignShared0GF16.sub_assign`**:

• The function always succeeds (no panic) for any valid pair of GF16 inputs, since XOR is a total
  operation on bounded integers.
• The by-value `SubAssign<GF16>::sub_assign` delegates to this by-reference variant and is
  observationally identical.
• Together with the `Sub` trait implementation, the following
  identity holds:
    `(a - b).value = sub_assign(a, b).value` -/
@[step]
theorem sub_assign_spec (self other : GF16) :
    sub_assign self other ⦃ (result : GF16) =>
      result.toGF216 = self.toGF216 - other.toGF216 ⦄ := by
  unfold sub_assign
  step*

end spqr.encoding.gf.GF16.Insts.CoreOpsArithSubAssignShared0GF16

/-!
# Spec theorem for `spqr::encoding::gf::{impl ops::SubAssign for GF16}::sub_assign`

The by-value `SubAssign<GF16> for GF16` wrapper delegates directly to the by-reference
`SubAssign<&GF16> for GF16` (i.e. `CoreOpsArithSubAssignShared0GF16.sub_assign`), introducing no
additional logic — the two are observationally identical:
  `sub_assign_val(a, b) = sub_assign_ref(a, b)`

**Source**: spqr/src/encoding/gf.rs (lines 92:4-94:5)
-/

namespace spqr.encoding.gf.GF16.Insts.CoreOpsArithSubAssignGF16

/--
**Spec theorem for `spqr.encoding.gf.GF16.Insts.CoreOpsArithSubAssignGF16.sub_assign`**:

• The function always succeeds (no panic) for any pair of `GF16` inputs, since XOR is a total
  operation on bounded integers.
• Lifting `result.value.val` into `GF216` via the canonical map
  `Nat.toGF216 = BinaryPoly.toGF216 ∘ natToBinaryPoly` yields the GF(2¹⁶) difference of
  the similarly-lifted inputs:
    `(result.value.val.toGF216 : GF216) = self.value.val.toGF216 - other.value.val.toGF216`
  where the `-` on the right-hand side is subtraction in
  `GF216 = GaloisField 2 16` (which, in characteristic 2, coincides
  with addition).
-/
@[step]
theorem sub_assign_spec (self other : GF16) :
    sub_assign self other ⦃ (result : GF16) =>
      result.toGF216 = self.toGF216 - other.toGF216 ⦄ := by
  unfold sub_assign
  step*

end spqr.encoding.gf.GF16.Insts.CoreOpsArithSubAssignGF16
