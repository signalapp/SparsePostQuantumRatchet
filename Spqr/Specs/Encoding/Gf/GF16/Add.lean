/-
Copyright 2026 The Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE-APACHE.
Authors: Hoang Le Truong
-/
import Spqr.Code.Funs
import Spqr.Specs.Encoding.Gf.GF16.AddAssign
/-!
# Spec theorem for `spqr::encoding::gf::{impl ops::Add for GF16}::add`

In GF(2¹⁶) — the Galois field with 65 536 elements — addition is simply bitwise XOR of the two
16-bit underlying values.  This follows from the fact that GF(2¹⁶) has characteristic 2, so
addition of polynomial coefficients is addition in GF(2), which is XOR.

The by-value `Add<GF16> for GF16` introduces no additional logic beyond the delegation, so its
postcondition is inherited from the corresponding `AddAssign` specification.

Note that in GF(2¹⁶), addition and subtraction coincide:
  `a + b = a - b = a ⊕ b`
since every element is its own additive inverse (`a + a = 0`).

**Source**: spqr/src/encoding/gf.rs (lines 53:4-57:5)
-/

open Aeneas Aeneas.Std Result spqr.math.gf spqr.encoding.gf

namespace spqr.encoding.gf.GF16.Insts.CoreOpsArithAddGF16GF16

/-- **Spec theorem for `spqr.encoding.gf.GF16.Insts.CoreOpsArithAddGF16GF16.add`**:

• Takes two `GF16` field elements `self` and `other`, each wrapping a `u16` value representing
  an element of GF(2¹⁶).
• Delegates immediately to `add_assign`:
    `CoreOpsArithAddAssignShared0GF16.add_assign self other`
  which computes `self.value ^^^ other.value` (bitwise XOR).
• Returns the resulting `GF16` whose `value` field is the GF(2¹⁶) sum of the two inputs.

• The function always succeeds (no panic) for any valid pair of GF16 inputs, since XOR is a
  total operation on bounded integers.
• The by-reference `Add<&GF16>::add` delegates to this by-value variant and is observationally
  identical.
• Together with the `AddAssign` trait implementation, the following identity holds:
    `(a + b).value = add_assign(a, b).value`

The result satisfies the GF(2¹⁶)-level postcondition:

  `result.value.val.toGF216 =
       self.value.val.toGF216 + other.value.val.toGF216`

where `Nat.toGF216 n = φ (natToGF2Poly n)` interprets a natural number as an element of
`GF216 = GaloisField 2 16` via the chosen ring homomorphism `φ : GF2Poly →+* GF216` that
vanishes on `POLY_GF2`.

The proof unfolds `add` to expose the underlying `add_assign` call and discharges the resulting
goal with `step*`, which applies the already-registered `add_assign_spec`.

**Source**: spqr/src/encoding/gf.rs (lines 53:4-57:5)
-/
@[step]
theorem add_spec (self other : GF16) :
    add self other ⦃ (result : GF16) =>
      result.toGF216 = self.toGF216 + other.toGF216 ⦄ := by
  unfold add
  step*

end spqr.encoding.gf.GF16.Insts.CoreOpsArithAddGF16GF16

/-! # Spec theorem for `spqr::encoding::gf::{impl ops::Add<&GF16> for GF16}::add`

In GF(2¹⁶) — the Galois field with 65 536 elements — addition is simply bitwise XOR of the two
16-bit underlying values.  This follows from the fact that GF(2¹⁶) has characteristic 2, so
addition of polynomial coefficients is addition in GF(2), which is XOR.

Note that in GF(2¹⁶), addition and subtraction coincide:
  `a + b = a - b = a ⊕ b`
since every element is its own additive inverse (`a + a = 0`).

**Source**: spqr/src/encoding/gf.rs (lines 67:4-71:5)
-/

namespace spqr.encoding.gf.GF16.Insts.CoreOpsArithAddShared0GF16GF16

/-- **Spec theorem for `spqr.encoding.gf.GF16.Insts.CoreOpsArithAddShared0GF16GF16.add`**:

• Takes two `GF16` field elements `self` and `other`, each wrapping a `u16` value representing
  an element of GF(2¹⁶).  In the original Rust source `other` is passed by reference (`&GF16`);
  after Aeneas extraction the reference is erased and both arguments are plain `GF16` values.
• Delegates immediately to the by-reference `add_assign`:
    `CoreOpsArithAddAssignShared0GF16.add_assign self other`
  which computes `self.value ^^^ other.value` (bitwise XOR).
• Returns the resulting `GF16` whose `value` field is the GF(2¹⁶) sum of the two inputs.

• The function always succeeds (no panic) for any pair of `GF16` inputs, since XOR is a total
  operation on bounded integers.
• Lifting `result.value.val` into `GF216` via the canonical map `Nat.toGF216 = φ ∘ natToGF2Poly`
  yields the GF(2¹⁶) sum of the similarly-lifted inputs:
    `(result.value.val.toGF216 : GF216) =
        self.value.val.toGF216 + other.value.val.toGF216`
  where the `+` on the right-hand side is addition in `GF216 = GaloisField 2 16`.

The result satisfies the GF(2¹⁶)-level postcondition:

  `(result.value.val.toGF216 : GF216) =
       self.value.val.toGF216 + other.value.val.toGF216`

where `Nat.toGF216 n = φ (natToGF2Poly n)` interprets a natural number as an element of
`GF216 = GaloisField 2 16` via the chosen ring homomorphism `φ : GF2Poly →+* GF216` that
vanishes on `POLY_GF2`.

The proof unfolds `add` to expose the underlying `add_assign` call and discharges the resulting
goal with `step*`, which applies the already-registered `add_assign_spec`.

**Source**: spqr/src/encoding/gf.rs (lines 67:4-71:5)
-/
@[step]
theorem add_spec (self other : GF16) :
    add self other ⦃ (result : GF16) =>
      result.toGF216 = self.toGF216 + other.toGF216 ⦄ := by
  unfold add
  step*

end spqr.encoding.gf.GF16.Insts.CoreOpsArithAddShared0GF16GF16
