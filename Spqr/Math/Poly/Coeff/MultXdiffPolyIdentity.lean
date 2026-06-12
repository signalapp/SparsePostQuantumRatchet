/-
Copyright 2026 The Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE-APACHE.
Authors: Hoang Le Truong
-/
import Spqr.Math.List

/-! # Polynomial identity for `mult_xdiff_assign_trailing`

Closed-form identity for the in-place recurrence `v[i−1] −= v[i] * d`
used by `mult_xdiff_assign_trailing`.

`listToGF216Poly rs = listToGF216Poly cs − C(d.toGF216) · X^(s−1) · listToGF216Poly (cs.drop s)`. -/

open Polynomial spqr.encoding.gf

namespace spqr.encoding.polynomial

theorem mult_xdiff_poly_identity (cs rs : List GF16) (s : Nat) (d : GF16) (h_s_pos : 1 ≤ s)
    (h_len : rs.length = cs.length)
    (h_coeff : ∀ j, j < cs.length →
      (rs[j]!).toGF216 = (cs[j]!).toGF216 -
          (if s ≤ j + 1 ∧ j + 1 < cs.length then (cs[j + 1]!).toGF216 * d.toGF216 else 0)) :
    listToGF216Poly rs =
      listToGF216Poly cs - C d.toGF216 * X ^ (s - 1) * listToGF216Poly (cs.drop s) := by
  ext m
  rw [coeff_sub, listToGF216Poly_coeff, listToGF216Poly_coeff,
      show C d.toGF216 * X ^ (s - 1) * listToGF216Poly (cs.drop s) =
        C d.toGF216 * (listToGF216Poly (cs.drop s) * X ^ (s - 1)) by ring,
      coeff_C_mul, coeff_mul_X_pow']
  by_cases hm : m < cs.length
  · rw [dif_pos (by omega), dif_pos hm]
    by_cases hs : s - 1 ≤ m
    · rw [if_pos hs, listToGF216Poly_coeff]
      grind
    · grind
  · push Not at hm
    rw [dif_neg (by omega), dif_neg (by omega)]
    by_cases hs : s - 1 ≤ m
    · rw [if_pos hs, listToGF216Poly_coeff,
          dif_neg (by rw [List.length_drop]; omega), mul_zero]; ring
    · grind

end spqr.encoding.polynomial
