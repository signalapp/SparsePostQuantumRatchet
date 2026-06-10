/-
Copyright 2026 The Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE-APACHE.
Authors: Hoang Le Truong
-/
import Spqr.Math.Poly.Lagrange.BasisPoly

/-!
# Partial Lagrange interpolant sum

## Main definitions

* `lagrangeInterpolantSum` — the partial sum
  `∑_{i < n} C(lagrangeScaleGF216 pts[i] pts) · lagrangeBasisPoly pts i`.

## Main statements

* `lagrangeInterpolantSum_eq_finset_sum` — equivalent `Finset.sum` form.
* `lagrangeInterpolantSum_coeff_high` — coefficients beyond degree vanish.
-/

open Polynomial
open spqr.encoding.gf

namespace spqr.encoding.polynomial

/--
Sum of `lagrangeScale · lagrangeBasis` over a prefix `[0, n)` of the point list `pts`.

This is the partial Lagrange interpolant.
-/
noncomputable def lagrangeInterpolantSum
    (pts : List spqr.encoding.polynomial.Pt) : Nat → Polynomial GF216
  | 0     => 0
  | n + 1 =>
      lagrangeInterpolantSum pts n +
        (if h : n < pts.length then
          C (lagrangeScaleGF216 (pts.get ⟨n, h⟩) pts) *
            lagrangeBasisPoly pts n
        else 0)

/-- `lagrangeInterpolantSum` equals a `Finset.sum`. -/
lemma lagrangeInterpolantSum_eq_finset_sum
    (pts : List Pt) (n : Nat) (hn : n ≤ pts.length) :
    lagrangeInterpolantSum pts n =
      Finset.sum (Finset.range n) (fun i =>
        if h : i < pts.length then
          C (lagrangeScaleGF216 (pts.get ⟨i, h⟩) pts) *
            lagrangeBasisPoly pts i
        else 0) := by
  induction n with
  | zero => simp [lagrangeInterpolantSum]
  | succ k ih =>
    rw [lagrangeInterpolantSum, ih (by omega), Finset.sum_range_succ]

/-- Coefficient of `lagrangeInterpolantSum` beyond degree is zero. -/
lemma lagrangeInterpolantSum_coeff_high
    (pts : List Pt) (n j : Nat) (hn : n ≤ pts.length)
    (hj : pts.length ≤ j) :
    (lagrangeInterpolantSum pts n).coeff j = 0 := by
  rw [lagrangeInterpolantSum_eq_finset_sum pts n hn]
  simp only [Polynomial.finset_sum_coeff]
  apply Finset.sum_eq_zero
  intro i hi
  rw [Finset.mem_range] at hi
  have hi' : i < pts.length := by omega
  rw [dif_pos hi']
  exact Polynomial.coeff_eq_zero_of_natDegree_lt (by
    calc (C _ * lagrangeBasisPoly pts i).natDegree
        ≤ (lagrangeBasisPoly pts i).natDegree := Polynomial.natDegree_C_mul_le _ _
      _ ≤ pts.length - 1 := natDegree_lagrangeBasisPoly_le pts i hi' (by omega)
      _ < j := by omega)

end spqr.encoding.polynomial
