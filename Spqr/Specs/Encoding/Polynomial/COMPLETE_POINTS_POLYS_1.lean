/-
Copyright 2026 The Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE-APACHE.
Authors: Hoang Le Truong
-/
import Spqr.Specs.Encoding.Polynomial.LagrangePolysForCompletePoints

/-! # Spec theorem for `spqr::encoding::polynomial::COMPLETE_POINTS_POLYS_1`

`lagrange_polys_for_complete_points` at `N = 1`: one point with `y = GF16::ONE`, so
`lagrangeDenomProd` and `condProdLinearFactors` are trivial and the result is the
constant polynomial `1 : GF216[X]`.

**Source**: spqr/src/encoding/polynomial.rs -/

open Aeneas Aeneas.Std spqr.encoding.gf
open spqr.encoding.polynomial.PolyConst.lagrange_interpolate_pt_loop

namespace spqr.encoding.polynomial

/-- **Spec theorem for `encoding.polynomial.COMPLETE_POINTS_POLYS_1`**:

• Evaluation is total (`N = 1` satisfies `0 < N ≤ 65536`).

• The sole Lagrange basis polynomial is `1 : GF216[X]`, since `y = GF16.ONE` and both
  `lagrangeDenomProd` / `condProdLinearFactors` are empty products. -/
@[step]
theorem COMPLETE_POINTS_POLYS_1_spec :
    COMPLETE_POINTS_POLYS_1 ⦃ result =>
      result.length = 1 ∧
      (result.val[0]).degree = 0 ∧
      listToGF216Poly (result.val[0]).coefficients.val = 1 ⦄ := by
  unfold COMPLETE_POINTS_POLYS_1
  step*
  have h := result_post2 0 (by omega) (by grind) (by grind)
  rw [condProdLinearFactors_skip _ _ 0 (by grind [List.length_take]),
      condProdLinearFactors_ge _ _ 1 (by simp [List.length_take]),
      lagrangeDenomProd_skip _ _ 0 (by grind [List.length_take]) ,
      lagrangeDenomProd_eq_one_of_le _ _ 1 (by simp [List.length_take])] at h
  · simp only [Nat.reducePow, Nat.reduceSub, one_pow, mul_one] at h
    have h_y := (result_post1 0 (by omega)).2
    constructor
    · grind
    · constructor
      · unfold PolyConst.degree
        rw [h]
        simp
      · grind [ GF16.ONE_toGF216]
  · grind
  · grind

end spqr.encoding.polynomial
