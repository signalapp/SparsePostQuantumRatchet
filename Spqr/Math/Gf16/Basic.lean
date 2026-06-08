/-
Copyright 2026 The Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE-APACHE.
Authors: Hoang Le Truong
-/
import Mathlib.Algebra.Polynomial.Div
import Mathlib.Data.Nat.Bitwise
import Mathlib.Tactic.ComputeDegree
import Mathlib.Tactic.IntervalCases
import Spqr.Math.Gf2Poly.Basic

/-!
# The SPQR irreducible polynomial polyGF2

Definition of `polyGF2 = X¹⁶ + X¹² + X³ + X + 1` in `(ZMod 2)[X]`, its basic properties
(monic, degree 16, ≠ 1), and the bridge lemma `natToBinaryPoly 0x1100b = polyGF2`.
-/

open Polynomial

namespace spqr.math.gf

/--
The irreducible polynomial used for GF(2¹⁶) reduction:
    `polyGF2 = X¹⁶ + X¹² + X³ + X + 1`   (0x1100b in hex).

    `GF(2¹⁶) ≅ GF(2)[X] / (polyGF2)`.
-/
noncomputable def polyGF2 : BinaryPoly :=
  X ^ 16 + X ^ 12 + X ^ 3 + X + 1

@[simp]
lemma natToBinaryPoly_polyGF2 :
    natToBinaryPoly 0x1100b = polyGF2 := by
  ext m
  simp only [natToBinaryPoly_coeff]
  unfold polyGF2
  simp only [coeff_add, coeff_X_pow, coeff_X, coeff_one]
  rcases Nat.lt_or_ge m 17 with hlt | hge
  · interval_cases m <;> decide
  · have htb : Nat.testBit (0x1100b : Nat) m = false := by
      apply Nat.testBit_eq_false_of_lt
      exact lt_of_lt_of_le (by norm_num : (0x1100b : Nat) < 2 ^ 17)
        (Nat.pow_le_pow_right (by norm_num) hge)
    simp only [htb, ↓reduceIte, show m ≠ 16 from by omega, show m ≠ 12 from by omega,
               show m ≠ 3 from by omega, show (1 : ℕ) ≠ m from by omega, show m ≠ 0 from by omega,
               add_zero]
    simp

/-! ## Properties of `polyGF2` -/

/-- **`polyGF2` is monic** (leading coefficient is 1). -/
theorem polyGF2_monic : polyGF2.Monic := by
  unfold polyGF2; monicity!

/-- **`polyGF2` has degree 16.** -/
theorem polyGF2_natDegree : polyGF2.natDegree = 16 := by
  unfold polyGF2; compute_degree!

/-- **`polyGF2 ≠ 1`** (its degree is 16, not 0). -/
theorem polyGF2_ne_one : polyGF2 ≠ 1 := by
  intro h; have := congr_arg Polynomial.natDegree h
  simp [polyGF2_natDegree] at this

/-! ## Modular-reduction utilities for `polyGF2` -/

lemma polyGF2_dvd_modByMonic_sub (p : BinaryPoly) :
    polyGF2 ∣ (p %ₘ polyGF2 - p) := by
  refine ⟨-(p /ₘ polyGF2), ?_⟩
  grind [Polynomial.modByMonic_add_div]

lemma polyGF2_modByMonic_idem (p : BinaryPoly) :
    (p %ₘ polyGF2) %ₘ polyGF2 = p %ₘ polyGF2 :=
  Polynomial.modByMonic_eq_of_dvd_sub polyGF2_monic
    (polyGF2_dvd_modByMonic_sub p)

end spqr.math.gf
