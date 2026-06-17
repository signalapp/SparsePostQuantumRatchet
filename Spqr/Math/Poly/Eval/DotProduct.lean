/-
Copyright 2026 The Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE-APACHE.
Authors: Hoang Le Truong
-/
import Spqr.Math.Poly.CharTwo.ToGF216
import Spqr.Math.Poly.Eval

/-!
# Dot-product to evaluation bridge

Links dot product of coefficient/power vectors to polynomial evaluation.
-/

open Aeneas.Std  spqr.math.gf spqr.encoding.gf

namespace spqr.encoding.polynomial

/-- Dot product of coefficients and power vector equals polynomial evaluation. -/
theorem dot_product_eq_eval
  (x : GF16) (v : List GF16) (xs : List GF16)
  (h_pow : ∀ j, j < xs.length → (xs[j]!).toGF216 = x.toGF216 ^ j)
  (h_len : v.length ≤ xs.length) :
  (∑ j ∈ Finset.range v.length, (v[j]!).toGF216 * (xs[j]!).toGF216) =
    (listToGF216Poly v).eval (x.toGF216) := by
  have h_sub : ∀ j ∈ Finset.range v.length,
      (v[j]!).toGF216 * (xs[j]!).toGF216 =
      (v[j]!).toGF216 * x.toGF216 ^ j := by
    intro j hj; rw [Finset.mem_range] at hj
    congr 1; exact h_pow j (by omega)
  rw [Finset.sum_congr rfl h_sub]
  have h_coeff : ∀ j ∈ Finset.range v.length,
      (v[j]!).toGF216 * x.toGF216 ^ j =
      (listToGF216Poly v).coeff j * x.toGF216 ^ j := by
    intro j hj
    congr 1; exact getElem!_toGF216_eq_coeff v j
  rw [Finset.sum_congr rfl h_coeff]
  exact (eval_eq_range_sum (listToGF216Poly v) (x.toGF216) v.length
    (fun j hj => listToGF216Poly_coeff_eq_zero v j hj)).symm

/-- `GF16.ZERO.toGF216` equals an empty sum. -/
theorem zero_toGF216_eq_empty_sum
  (v xs : alloc.vec.Vec GF16) :
  GF16.ZERO.toGF216 = ∑ j ∈ Finset.range 0, (v[j]!).toGF216 * (xs[j]!).toGF216 := by
  simp [GF16.ZERO, GF16.toGF216, Nat.toGF216, natToBinaryPoly_zero, map_zero]

/-- `max 2 n + 1 ≤ Usize.max` when `n + 1 ≤ Usize.max`. -/
theorem max_two_succ_le_usize_max (n : Nat) (h : n + 1 ≤ Usize.max) :
    Nat.max 2 n + 1 ≤ Usize.max := by
  simp only [Nat.max_def]
  split_ifs
  · exact h
  · scalar_tac

end spqr.encoding.polynomial
