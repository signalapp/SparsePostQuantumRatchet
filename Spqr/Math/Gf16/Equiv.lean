/-
Copyright (c) 2026 The Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE-APACHE.
Authors: Alessandro D'Angelo
-/
import Spqr.Math.Gf16.Field
import Spqr.Math.Poly.CharTwo.ToGF216
import Spqr.Math.Gf2Poly.Basic
import Mathlib.Data.Fintype.EquivFin

open spqr.encoding.polynomial spqr.math.gf

/-- Naturals below `2 ^ 16` have distinct images in `GF216`. -/
theorem Nat.toGF216_injOn : Set.InjOn Nat.toGF216 (Set.Iio (2 ^ 16)) := by
  intro a ha b hb hab
  apply Nat.xor_eq_zero_iff.mp
  apply Nat_toGF216_eq_zero (Nat.bitwise_lt_two_pow ha hb)
  calc
    Nat.toGF216 (a ^^^ b) = Nat.toGF216 a + Nat.toGF216 b := by
      simp only [Nat.toGF216, natToBinaryPoly_xor, map_add]
    _ = Nat.toGF216 b + Nat.toGF216 b := by rw [hab]
    _ = 0 := CharTwo.add_self_eq_zero (Nat.toGF216 b)

/-- The finite type structure on `GF216`. -/
noncomputable instance GF216.instFintype : Fintype GF216 := Fintype.ofFinite GF216

/-- `GF216` has `2 ^ 16` elements. -/
theorem GF216.card_eq : Fintype.card GF216 = 2 ^ 16 := by
  rw [Fintype.card_eq_nat_card]
  exact GaloisField.card 2 16 (by norm_num)

private noncomputable def GF216.finEquiv : Fin (2 ^ 16) ≃ GF216 :=
  Equiv.ofBijective (fun n => Nat.toGF216 n.val) <|
    (Fintype.bijective_iff_injective_and_card _).2 ⟨
      fun a b h => Fin.ext (Nat.toGF216_injOn a.isLt b.isLt h),
      by simp only [Fintype.card_fin, GF216.card_eq]⟩

/-- The natural-number representative of an element of `GF216`. -/
noncomputable def GF216.toNat (x : GF216) : ℕ := (GF216.finEquiv.symm x).val

/-- The natural-number representative of a field element is a 16-bit value. -/
theorem GF216.toNat_lt (x : GF216) : x.toNat < 2 ^ 16 :=
  (GF216.finEquiv.symm x).isLt

/-- Converting the natural-number representative back to `GF216` is the identity. -/
@[simp] theorem GF216.toGF216_toNat (x : GF216) : Nat.toGF216 x.toNat = x := by
  change GF216.finEquiv (GF216.finEquiv.symm x) = x
  exact GF216.finEquiv.apply_symm_apply x

/-- Converting an in-range natural through `GF216` is the identity. -/
@[simp] theorem GF216.toNat_toGF216 {n : ℕ} (h : n < 2 ^ 16) :
    (Nat.toGF216 n).toNat = n := by
  change (GF216.finEquiv.symm (GF216.finEquiv ⟨n, h⟩)).val = n
  rw [GF216.finEquiv.symm_apply_apply]
