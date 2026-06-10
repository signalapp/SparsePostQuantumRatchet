/-
Copyright 2026 The Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE-APACHE.
Authors: Hoang Le Truong
-/
import Spqr.Math.Poly.Coeff.Basic
import Spqr.Math.Poly.CharTwo.Basic

/-!
# Miscellaneous polynomial identities and `Inhabited` instances

## Main statements

* `coeff_zero_eq_zero_of_X_mul_identity` — the constant term of a polynomial satisfying a factored
  identity is zero.
* `List.map_sum_eq_Finset_sum` — `List.map`/`List.sum` to `Finset.sum` bridge.

## Instances

* `Inhabited Poly`.
-/

open Aeneas Aeneas.Std Result
open Polynomial

namespace spqr.encoding.polynomial

/-! ## Generic polynomial coefficient lemmas -/

/-- Constant term of `C(a) + (X − C(b)) · P` is `a − b · P.coeff 0`. -/
theorem coeff_zero_C_add_X_sub_C_mul {R : Type*} [CommRing R]
    (a b : R) (P : R[X]) :
    (C a + (X - C b) * P).coeff 0 = a - b * P.coeff 0 := by
  rw [sub_mul, coeff_add, coeff_sub, coeff_C_zero, coeff_X_mul_zero, coeff_C_mul]
  ring

/-- Higher coefficients of `C(a) + (X − C(b)) · P`:
  `(C(a) + (X − C(b)) · P).coeff (n + 1) = P.coeff n − b · P.coeff (n + 1)`. -/
theorem coeff_succ_C_add_X_sub_C_mul {R : Type*} [CommRing R]
    (a b : R) (P : R[X]) (n : ℕ) :
    (C a + (X - C b) * P).coeff (n + 1) = P.coeff n - b * P.coeff (n + 1) := by
  rw [sub_mul, coeff_add, coeff_sub, coeff_X_mul, coeff_C_mul]
  have : (C a).coeff (n + 1) = 0 := by rw [coeff_C]; exact if_neg (by omega)
  rw [this]; ring

/-! ## Advanced polynomial identity helpers -/

/--
The constant term of a polynomial satisfying a factored identity with an X factor is zero.

From the polynomial identity
  `p · (X − C(a)) = X · C(s) · P`
the RHS has a factor of `X` and hence zero constant term.

• When `a ≠ 0`: since `GF216` is an integral domain, `p.coeff(0) = 0`.
• When `a = 0`: `(X − C(0)) = X`, and the root hypothesis `P.eval(a) = 0` gives `X ∣ P`,
  from which `p.coeff(0) = 0` follows.
-/
lemma coeff_zero_eq_zero_of_X_mul_identity
    (p : GF216[X]) (a s : GF216) (P : GF216[X])
    (h_id : p * (X - C a) = X * C s * P)
    (h_root : P.eval a = 0) :
    p.coeff 0 = 0 := by
  by_cases ha : a = 0
  · subst ha
    simp only [map_zero, sub_zero] at h_id
    have h_X_dvd_P : (X : GF216[X]) ∣ P := by
      have h_div : (X - C (0 : GF216)) ∣ P := dvd_iff_isRoot.mpr h_root
      rwa [map_zero, sub_zero] at h_div
    obtain ⟨Q, hQ⟩ := h_X_dvd_P
    have hX_ne : (X : GF216[X]) ≠ 0 := X_ne_zero
    have hp_eq : p = C s * P := by
      have h1 : p * X = (C s * P) * X := by
        ring_nf; ring_nf at h_id; exact h_id
      exact mul_right_cancel₀ hX_ne h1
    rw [hp_eq, hQ]
    simp only [Polynomial.mul_coeff_zero, coeff_C_zero, coeff_X_zero,
               zero_mul, mul_zero]
  · have h0 := congr_arg (fun q => q.coeff 0) h_id
    simp only [Polynomial.mul_coeff_zero, coeff_sub, coeff_X_zero, coeff_C_zero,
               zero_sub, zero_mul] at h0
    rw [CharTwo.neg_eq] at h0
    exact (mul_eq_zero.mp h0).elim id (absurd · ha)

/-! ## List/Finset sum bridge -/

/-- Converting `List.map/sum` to `Finset.sum` indexed by `Fin`. -/
lemma List.map_sum_eq_Finset_sum
    {α β : Type} [AddCommMonoid β]
    (l : List α) (f : α → β) :
    (l.map f).sum = Finset.sum Finset.univ (fun i : Fin l.length => f (l.get i)) := by
  induction l with
  | nil => simp
  | cons a l ih =>
    simp only [List.map_cons, List.sum_cons, List.length_cons, List.get_eq_getElem]
    rw [ih, Fin.sum_univ_succ]
    simp [Fin.val_succ, List.get_eq_getElem]

/-! ## Remaining `Inhabited` instance -/

instance : Inhabited spqr.encoding.polynomial.Poly :=
  ⟨{ coefficients := alloc.vec.Vec.new _ }⟩

end spqr.encoding.polynomial
