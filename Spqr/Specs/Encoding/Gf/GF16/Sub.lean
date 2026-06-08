/-
Copyright 2026 The Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE-APACHE.
Authors: Hoang Le Truong
-/
import Spqr.Code.Funs
import Spqr.Specs.Encoding.Gf.GF16.SubAssign
/-!
# Spec theorem for `spqr::encoding::gf::{impl ops::Sub for GF16}::sub`

In GF(2¹⁶) — the Galois field with 65 536 elements — subtraction is simply bitwise XOR of the two
16-bit underlying values.  This follows from the fact that GF(2¹⁶) has characteristic 2, so every
element is its own additive inverse (`a + a = 0`), meaning subtraction and addition coincide:
  `a - b = a + b = a ⊕ b`

Concretely, `sub self other` calls `CoreOpsArithSubAssignShared0GF16.sub_assign self other`, which
ultimately computes `self.value ^^^ other.value` (bitwise XOR) and wraps the result back into a
`GF16`.

The by-value `Sub` introduces no additional logic beyond the delegation, so its postcondition is
inherited from the corresponding `SubAssign` specification: lifting the underlying `u16` of the
result into `GF216 = GaloisField 2 16` via `Nat.toGF216` yields the GF(2¹⁶) difference of the lifts
of `self.value` and `other.value`.

Note that in GF(2¹⁶), addition and subtraction coincide:
  `a + b = a - b = a ⊕ b`
since every element is its own additive inverse (`a + a = 0`).

**Source**: spqr/src/encoding/gf.rs (lines 104:4-108:5)
-/

open Aeneas Aeneas.Std

namespace spqr.encoding.gf.GF16.Insts.CoreOpsArithSubGF16GF16

/--
**Spec theorem for `spqr.encoding.gf.GF16.Insts.CoreOpsArithSubGF16GF16.sub`**:

• The function always succeeds (no panic) for any pair of `GF16` inputs, since XOR is a total
  operation on bounded integers.
• Lifting `result.value.val` into `GF216` via the canonical map
  `Nat.toGF216 = BinaryPoly.toGF216 ∘ natToBinaryPoly` yields the GF(2¹⁶) difference of
  the similarly-lifted inputs:
    `(result.value.val.toGF216 : GF216) = self.value.val.toGF216 - other.value.val.toGF216`
  where the `-` on the right-hand side is subtraction in `GF216 = GaloisField 2 16` (which, in
  characteristic 2, coincides with addition).

**Source**: spqr/src/encoding/gf.rs (lines 104:4-108:5)
-/
@[step]
theorem sub_spec (self other : GF16) :
    sub self other ⦃ (result : GF16) =>
      result.toGF216 = self.toGF216 - other.toGF216 ⦄ := by
  unfold sub
  step*

end spqr.encoding.gf.GF16.Insts.CoreOpsArithSubGF16GF16

/-!
# Spec theorem for `spqr::encoding::gf::{impl ops::Sub<&GF16> for GF16}::sub`

Since the by-reference `Sub` introduces no additional logic beyond the delegation, its postcondition
is inherited from the corresponding `SubAssign` specification.

**Source**: spqr/src/encoding/gf.rs (lines 118:4-122:5)
-/

namespace spqr.encoding.gf.GF16.Insts.CoreOpsArithSubShared0GF16GF16

/--
**Spec theorem for `spqr.encoding.gf.GF16.Insts.CoreOpsArithSubShared0GF16GF16.sub`**:

• The function always succeeds (no panic) for any pair of `GF16` inputs, since XOR is a total
  operation on bounded integers.
• Lifting `result.value.val` into `GF216` via the canonical map
  `Nat.toGF216 = BinaryPoly.toGF216 ∘ natToBinaryPoly` yields the GF(2¹⁶) difference of
  the similarly-lifted inputs:
    `(result.value.val.toGF216 : GF216) = self.value.val.toGF216 - other.value.val.toGF216`
  where the `-` on the right-hand side is subtraction in `GF216 = GaloisField 2 16` (which,
  in characteristic 2, coincides with addition).

**Source**: spqr/src/encoding/gf.rs (lines 118:4-122:5)
-/
@[step]
theorem sub_spec (self other : GF16) :
    sub self other ⦃ (result : GF16) =>
      result.toGF216 = self.toGF216 - other.toGF216 ⦄ := by
  unfold sub
  step*

end spqr.encoding.gf.GF16.Insts.CoreOpsArithSubShared0GF16GF16
