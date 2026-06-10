/-
Copyright 2026 The Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE-APACHE.
Authors: Hoang Le Truong
-/
import Spqr.Math.Poly.ExpectedTrailing.Defs
import Spqr.Math.Poly.LinearFactors.Basic

/-!
# Properties of `expectedTrailingPoly`

## Main statements

* `expectedTrailingPoly_coeff_eq_zero_of_lt` — high-degree coefficients vanish.
* `expectedTrailingPoly_eq_prodLinearFactors` — collapse to `prodLinearFactors` under the
  leading-one / lower-zero hypothesis.
-/

open Polynomial
open spqr.encoding.gf

namespace spqr.encoding.polynomial

/-- Coefficients of `expectedTrailingPoly` beyond degree `k` are zero. -/
lemma expectedTrailingPoly_coeff_eq_zero_of_lt
    (p_coeffs : List GF16) (pts : List Pt)
    (offset iter_start k n : Nat) (hn : k < n) :
    (expectedTrailingPoly p_coeffs pts offset iter_start k).coeff n = 0 := by
  induction k generalizing n with
  | zero =>
    simp only [expectedTrailingPoly_zero, coeff_C]
    exact if_neg (by omega)
  | succ k ih =>
    cases n with
    | zero => omega
    | succ n' =>
      rw [expectedTrailingPoly_succ]
      -- Coefficient n'+1 of C a + (X - C b) * P
      rw [sub_mul, coeff_add, coeff_sub, coeff_X_mul, coeff_C_mul]
      have h1 := ih n' (by omega)
      have h2 := ih (n' + 1) (by omega)
      have : (C (p_coeffs[offset - (k + 1)]!.toGF216) : GF216[X]).coeff (n' + 1) = 0 := by
        rw [coeff_C]; exact if_neg (by omega)
      rw [h1, h2, this]; ring

/--
Bridge lemma: when the initial polynomial has `p[offset] = ONE` and `p[j] = ZERO` for `j <
offset`, the expected trailing polynomial collapses to `prodLinearFactors`.
-/
lemma expectedTrailingPoly_eq_prodLinearFactors
    (p_coeffs : List GF16) (pts : List Pt) (offset : Nat)
    (h_leading : p_coeffs[offset]!.toGF216 = 1)
    (h_zeros : ∀ j, j < offset → p_coeffs[j]!.toGF216 = 0)
    (h_pts : offset ≤ pts.length) :
    ∀ k, k ≤ offset →
      expectedTrailingPoly p_coeffs pts offset 0 k =
        prodLinearFactors pts 0 k := by
  intro k hk
  induction k with
  | zero =>
    rw [expectedTrailingPoly_zero, prodLinearFactors_eq_one_of_not_lt pts 0 0 (by omega),
        h_leading, map_one]
  | succ n ih =>
    rw [expectedTrailingPoly_succ]
    have hn_le : n ≤ offset := by omega
    rw [ih hn_le]
    have h_zero : p_coeffs[offset - (n + 1)]!.toGF216 = 0 := by
      apply h_zeros; omega
    rw [h_zero, map_zero, zero_add]
    have h_n_lt : n < pts.length := by omega
    rw [prodLinearFactors_snoc pts 0 n (by omega) h_n_lt]
    conv_lhs =>
      rw [show pts[0 + n]!.x.toGF216 = (pts.get ⟨n, h_n_lt⟩).x.toGF216 from by
        congr 1; congr 1; rw [Nat.zero_add]; exact getElem!_pos pts n h_n_lt]
    ring

end spqr.encoding.polynomial
