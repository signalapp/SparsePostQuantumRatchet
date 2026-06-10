/-
Copyright 2026 The Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE-APACHE.
Authors: Hoang Le Truong
-/
import Spqr.Math.Poly.LinearFactors.Basic

/-!
# Degree and structural properties of `prodLinearFactors`

## Main statements

* `prodLinearFactors_eval_root` — vanishing at any root.
* `prodLinearFactors_split_at` — splitting the product at a midpoint.
* `prodLinearFactors_eq_X_sub_C_mul` — factoring out the `i`-th linear factor.
* `natDegree_prodLinearFactors_le` — degree bound.
* `prodLinearFactors_coeff_eq_zero_high` — vanishing of high coefficients.
-/

open Polynomial
open spqr.encoding.gf

namespace spqr.encoding.polynomial

/-- Evaluation of `prodLinearFactors` at a root is zero. -/
lemma prodLinearFactors_eval_root (pts : List Pt) (start stop : Nat)
    (j : Nat) (hj1 : start ≤ j) (hj2 : j < stop) (hj3 : j < pts.length) :
    (prodLinearFactors pts start stop).eval
      ((pts.get ⟨j, hj3⟩).x.toGF216) = 0 := by
  suffices h : ∀ (d : Nat) (start : Nat), stop - start = d → start ≤ j →
      (prodLinearFactors pts start stop).eval
        ((pts.get ⟨j, hj3⟩).x.toGF216) = 0 from
    h (stop - start) start rfl hj1
  intro d
  induction d with
  | zero => intro start hd; omega
  | succ n ih =>
    intro start hd hj1'
    rw [prodLinearFactors_step pts start stop (by omega) (by omega)]
    simp only [eval_mul]
    by_cases hjs : j = start
    · subst hjs; simp [eval_sub, eval_X, eval_C]
    · have := ih (start + 1) (by omega) (by omega)
      rw [this]; ring

/-- Splitting `prodLinearFactors` at a midpoint. -/
lemma prodLinearFactors_split_at
    (pts : List Pt) (mid n : Nat)
    (hmid : mid ≤ n) (hn : n ≤ pts.length) :
    prodLinearFactors pts 0 n =
      prodLinearFactors pts 0 mid * prodLinearFactors pts mid n := by
  induction n with
  | zero =>
    have : mid = 0 := by omega
    subst this; simp
  | succ k ih =>
    by_cases hmk : mid = k + 1
    · subst hmk; simp
    · rw [prodLinearFactors_snoc pts 0 k (by omega) (by omega : k < pts.length),
          ih (by omega) (by omega),
          prodLinearFactors_snoc pts mid k (by omega) (by omega : k < pts.length)]
      ring

/-- The full product factors as `(X − pts[i].x) · lagrangeBasisPoly pts i`. -/
lemma prodLinearFactors_eq_X_sub_C_mul
    (pts : List Pt) (i : Nat)
    (hi : i < pts.length) :
    prodLinearFactors pts 0 pts.length =
      (X - C ((pts.get ⟨i, hi⟩).x.toGF216)) *
        (prodLinearFactors pts 0 i *
          prodLinearFactors pts (i + 1) pts.length) := by
  rw [prodLinearFactors_split_at pts (i + 1) pts.length (by omega) (le_refl _),
      prodLinearFactors_snoc pts 0 i (by omega) hi]
  ring

/-- Degree bound for `prodLinearFactors`. -/
lemma natDegree_prodLinearFactors_le
    (pts : List Pt) (s t : Nat) (hs : s ≤ t) (ht : t ≤ pts.length) :
    (prodLinearFactors pts s t).natDegree ≤ t - s := by
  induction t with
  | zero => simp [show s = 0 from by omega]
  | succ k ih =>
    by_cases hsk : s = k + 1
    · subst hsk; simp
    · rw [prodLinearFactors_snoc pts s k (by omega) (by omega : k < pts.length)]
      calc (prodLinearFactors pts s k * (X - C _)).natDegree
          ≤ (prodLinearFactors pts s k).natDegree +
              (X - C ((pts.get ⟨k, by omega⟩).x.toGF216)).natDegree :=
            Polynomial.natDegree_mul_le
        _ ≤ (k - s) + 1 := by
            have h1 := ih (by omega) (by omega)
            have h2 : (X - C ((pts.get ⟨k, by omega⟩).x.toGF216) : GF216[X]).natDegree = 1 :=
              Polynomial.natDegree_X_sub_C _
            omega
        _ = k + 1 - s := by omega

/-- Coefficients of `prodLinearFactors` beyond degree `stop − start` are zero. -/
lemma prodLinearFactors_coeff_eq_zero_high
    (pts : List Pt) (start stop m : Nat) (hm : stop - start < m) :
    (prodLinearFactors pts start stop).coeff m = 0 := by
  suffices h : ∀ d start stop m, stop - start = d → d < m →
      (prodLinearFactors pts start stop).coeff m = 0 from
    h (stop - start) start stop m rfl hm
  intro d
  induction d with
  | zero =>
    intro start stop m hd hm'
    have : ¬(start < stop ∧ start < pts.length) := by omega
    rw [prodLinearFactors_eq_one_of_not_lt _ _ _ this, coeff_one]
    exact if_neg (by omega)
  | succ n ih =>
    intro start stop m hd hm'
    by_cases h : start < stop ∧ start < pts.length
    · rw [prodLinearFactors_step _ _ _ h.1 h.2]
      cases m with
      | zero => omega
      | succ m' =>
        rw [sub_mul, coeff_sub, coeff_X_mul, coeff_C_mul,
            ih (start + 1) stop (m' + 1) (by omega) (by omega),
            ih (start + 1) stop m' (by omega) (by omega)]
        ring
    · rw [prodLinearFactors_eq_one_of_not_lt _ _ _ h, coeff_one]
      exact if_neg (by omega)

end spqr.encoding.polynomial
