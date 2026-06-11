/-
Copyright 2026 The Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE-APACHE.
Authors: Hoang Le Truong
-/
import SrcTranslated.Funs
import Spqr.Math.Gf16.Field

/-! # Spec theorem for `spqr::encoding::gf::GF16::ONE`

In GF(2¹⁶) — the Galois field with 65 536 elements — the one element is the unique element `1`
satisfying `1 * a = a * 1 = a` for every `a ∈ GF(2¹⁶)`.  Concretely, since GF16 is a transparent
newtype around `u16`, the one element is represented by the `u16` value `1`:
  `ONE = GF16 { value := 1_u16 }`

The underlying `u16` value `1` has natural-number value `1`, and lifts into `GF216 = GaloisField 2
16` via the canonical chain `Nat → BinaryPoly → GF216` (i.e. `Nat.toGF216 = BinaryPoly.toGF216 ∘
natToBinaryPoly`) to the multiplicative identity `1 : GF216`.  This follows because:
  * `natToBinaryPoly 1 = 1` (the bit pattern `0b1` represents the
    constant polynomial `1` in `BinaryPoly`); and
  * the ring homomorphism `BinaryPoly.toGF216 : BinaryPoly →+* GF216` chosen in
    `Spqr.Math.Gf` preserves one (`map_one`).

**Source**: spqr/src/encoding/gf.rs (lines 542:4-542:44)
-/

open Aeneas Aeneas.Std Result spqr.math.gf

namespace spqr.encoding.gf.GF16

@[simp]
theorem ONE_value : (ONE).value = 1#u16 := by
  simp [ONE]

theorem ONE_value_val : (ONE).value.val = 1 := by
  simp [ONE]

@[simp]
theorem ONE_toGF216 : ONE.toGF216 = 1 := by
  simp [GF16.toGF216, Nat.toGF216, natToBinaryPoly_one]

/-- **Spec theorem for `encoding.gf.GF16.ONE`**:
• The underlying `u16` value of `ONE` is `1`:
    `ONE.value = 1#u16`
  and equivalently as a natural number:
    `ONE.value.val = 1`.
• Lifting `ONE.value.val` into `GF216` via the canonical map
  `Nat.toGF216 = BinaryPoly.toGF216 ∘ natToBinaryPoly` yields the multiplicative identity
  of `GF216 = GaloisField 2 16`:
    `(ONE.value.val.toGF216 : GF216) = 1`.
• `ONE` is a left- and right-identity for `GF16` multiplication: for every `a : GF16`, `a * ONE` and
  `ONE * a` lift to `a.value.val.toGF216` in `GF216`, which follows from the GF(2¹⁶) identity `x * 1
  = x`. -/
@[step]
theorem ONE_spec :
    ok ONE ⦃ (result : GF16) =>
      result.toGF216 = 1 ⦄ := by
  simp [GF16.toGF216, Nat.toGF216, natToBinaryPoly_one]

end spqr.encoding.gf.GF16
