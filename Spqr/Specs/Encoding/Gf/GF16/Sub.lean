/-
Copyright 2026 The Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Hoang Le Truong
-/
import Spqr.Code.Funs
import Spqr.Specs.Encoding.Gf.GF16.AddAssign
/-! # Spec theorem for `spqr::encoding::gf::{impl ops::Sub<&GF16> for GF16}::sub`

Specification and proof for `encoding.gf.GF16.Insts.CoreOpsArithSubShared0GF16GF16.sub`, which
implements `Sub<&GF16> for GF16` by delegating to the by-reference variant
`SubAssign<&GF16> for GF16`.

In GF(2¹⁶) — the Galois field with 65 536 elements — subtraction is simply bitwise XOR of the
two 16-bit underlying values.  This follows from the fact that GF(2¹⁶) has characteristic 2, so
every element is its own additive inverse (`a + a = 0`), meaning subtraction and addition
coincide:
  `a - b = a + b = a ⊕ b`

This simply forwards to `SubAssign<&GF16>::sub_assign`, which in turn delegates to
`AddAssign<&GF16>::add_assign`, computing `self.value ^= other.value` (bitwise XOR).

The by-reference `Sub<&GF16>` introduces no additional logic — it is observationally identical
to the by-value version:
  `Sub<&GF16>::sub(a, b) = Sub<GF16>::sub(a, b)`

**Source**: spqr/src/encoding/gf.rs (lines 118:4-122:5)
-/

open Aeneas Aeneas.Std Result
open spqr.encoding.gf.unaccelerated

namespace spqr.encoding.gf.GF16.Insts.CoreOpsArithSubShared0GF16GF16

/-
natural language description:

• Takes two `GF16` field elements `self` and `other`, each wrapping a `u16` value representing
  an element of GF(2¹⁶).
• Delegates immediately to the by-reference `sub_assign`:
    `self.sub_assign(&other)`
  which in turn calls `add_assign` (since subtraction = addition in GF(2¹⁶)), computing
  `self.value ^= other.value` (bitwise XOR).
• Returns the result as a new `GF16` value with `value` replaced by the GF(2¹⁶) difference.

natural language specs:

• The function always succeeds (no panic) for any valid pair of GF16 inputs, since XOR is a
  total operation on bounded integers.
• The result is identical to calling the by-reference `SubAssign<&GF16>::sub_assign`:
    `sub(a, b) = sub_assign(a, b)`
• Together with the `SubAssign` trait implementation, the following identity holds:
    `(a - b).value = sub_assign(a, b).value`
-/

/-- **Spec and proof concerning `encoding.gf.GF16.Insts.CoreOpsArithSubShared0GF16GF16.sub`**:

The `Sub<&GF16> for GF16` computes GF(2¹⁶) subtraction: bitwise XOR of the two underlying `u16`
values.  Since GF(2¹⁶) has characteristic 2, subtraction is identical to addition.

The result satisfies:
  `result.value.val = Nat.xor self.value.val other.value.val`

The proof delegates to the already-established `CoreOpsArithAddAssignShared0GF16.add_assign_spec`,
since `sub` is definitionally equal to `add_assign` (via `sub_assign`).

**Source**: spqr/src/encoding/gf.rs (lines 118:4-122:5)
-/
@[step]
theorem sub_spec (self other : spqr.encoding.gf.GF16) :
    sub self other ⦃ (result : spqr.encoding.gf.GF16) =>
      result.toGF216 = self.toGF216 - other.toGF216 ⦄ := by
  unfold sub CoreOpsArithSubAssignShared0GF16.sub_assign
  step*

end spqr.encoding.gf.GF16.Insts.CoreOpsArithSubShared0GF16GF16
