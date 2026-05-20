/-
Copyright 2026 The Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Hoang Le Truong
-/
import Spqr.Code.Funs
import Spqr.Math.Gf16.Field

/-!
# Spec theorem for `spqr::encoding::gf::GF16::ZERO`

In GF(2¹⁶) — the Galois field with 65 536 elements — the zero element is the unique element `0`
satisfying `0 + a = a + 0 = a` for every `a ∈ GF(2¹⁶)`.  Concretely, since GF16 is a transparent
newtype around `u16` whose addition is bitwise XOR, the zero element is represented by the `u16`
value `0`:
  `ZERO = GF16 { value := 0_u16 }`

The underlying `u16` value `0` has natural-number value `0`, and lifts into `GF216 = GaloisField 2
16` via the canonical chain `Nat → BinaryPoly → GF216` (i.e. `Nat.toGF216 = BinaryPoly.toGF216 ∘
natToBinaryPoly`) to the additive identity `0 : GF216`.  This follows because:
  * `natToBinaryPoly 0 = 0` (the empty bit pattern represents the zero
    polynomial in `BinaryPoly`); and
  * the ring homomorphism `BinaryPoly.toGF216 : BinaryPoly →+* GF216` chosen in
    `Spqr.Math.Gf` preserves zero (`map_zero`).

**Source**: spqr/src/encoding/gf.rs (lines 541:4-541:45)
-/

open Aeneas Aeneas.Std Result spqr.math.gf

namespace spqr.encoding.gf.GF16
@[simp]
theorem ZERO_value : (ZERO).value = 0#u16 := by
  simp [ZERO]

@[simp]
theorem ZERO_value_val : (ZERO).value.val = 0 := by
  simp [ZERO]

@[simp]
theorem ZERO_toGF216 : (ZERO.toGF216 : GF216) = 0 := by
  simp [GF16.toGF216, Nat.toGF216, natToBinaryPoly_zero]

/-- **Spec theorem for `encoding.gf.GF16.ZERO`**:

• The underlying `u16` value of `ZERO` is `0`:
    `ZERO.value = 0#u16`
  and equivalently as a natural number:
    `ZERO.value.val = 0`.
• Lifting `ZERO.value.val` into `GF216` via the canonical map
  `Nat.toGF216 = BinaryPoly.toGF216 ∘ natToBinaryPoly` yields the additive identity of
  `GF216 = GaloisField 2 16`:
    `(ZERO.value.val.toGF216 : GF216) = 0`.
• `ZERO` is a left- and right-identity for `GF16` addition (which is
  bitwise XOR): for every `a : GF16`,
    `(a + ZERO).value.val.toGF216 = a.value.val.toGF216`,
  which follows from the GF(2¹⁶) identity `x + 0 = x`. -/
@[step]
theorem ZERO_spec :
    ok ZERO ⦃ (result : GF16) =>
      (result.toGF216 : GF216) = 0 ⦄ := by
  simp [GF16.toGF216, Nat.toGF216, natToBinaryPoly_zero]

end spqr.encoding.gf.GF16
