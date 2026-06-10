/-
Copyright 2026 The Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE-APACHE.
Authors: Hoang Le Truong
-/
import Spqr.Math.Poly.Coeff.Basic

/-!
# Linking lemmas: `listToGF216Poly` and list operations

This file links list operations (append, pointwise addition, drop) on `GF16` coefficient
lists to polynomial operations in `GF216[X]`.

## Main statements

* `listToGF216Poly_append_singleton` — appending a coefficient adds a top-degree term.
* `listToGF216Poly_add` — pointwise addition lifts to polynomial addition.
* `listToGF216Poly_eq_X_mul_listToGF216Poly_drop_one` — if the constant term is zero, divide by `X`.
* `listToGF216Poly_eq_of_coeffs` — coefficient-matching characterization.
-/

open Polynomial
open spqr.encoding.gf

namespace spqr.encoding.polynomial

/-! ## Linking lemmas: `listToGF216Poly` and list operations -/

/--
Extending the coefficient list by one element corresponds to adding a new highest-degree term.
-/
lemma listToGF216Poly_append_singleton
    (cs : List spqr.encoding.gf.GF16) (a : spqr.encoding.gf.GF16) :
    listToGF216Poly (cs ++ [a]) =
      listToGF216Poly cs + C (a.toGF216) * X ^ cs.length := by
  ext m
  simp only [listToGF216Poly_coeff, coeff_add, coeff_C_mul, coeff_X_pow]
  by_cases hm1 : m < cs.length
  · -- m < cs.length < cs.length + 1: LHS = cs[m], RHS = cs[m] + 0
    have hm2 : m < (cs ++ [a]).length := by simp; omega
    have hm3 : m ≠ cs.length := by omega
    rw [dif_pos hm2, dif_pos hm1]
    simp only [hm3, if_false, mul_zero, add_zero]
    congr 1
    simp [List.get_eq_getElem, List.getElem_append_left hm1]
  · push Not at hm1
    by_cases hm2 : m = cs.length
    · -- m = cs.length: LHS = a, RHS = 0 + a
      subst hm2
      have hlt : cs.length < (cs ++ [a]).length := by simp
      have hnotlt : ¬(cs.length < cs.length) := by omega
      rw [dif_pos hlt, dif_neg hnotlt]
      simp only [ite_true, mul_one, zero_add]
      congr 1
      simp [List.get_eq_getElem, List.getElem_append_right (Nat.le_refl cs.length)]
    · -- m > cs.length: LHS = 0, RHS = 0 + 0
      have hm3 : ¬(m < cs.length) := by omega
      have hm4 : ¬(m < (cs ++ [a]).length) := by simp; omega
      rw [dif_neg hm4, dif_neg hm3]
      simp [hm2]

/--
Pointwise addition of equal-length coefficient lists corresponds to polynomial addition in
`GF216[X]`.
-/
lemma listToGF216Poly_add (cs ds : List spqr.encoding.gf.GF16)
    (hlen : cs.length = ds.length)
    (rs : List spqr.encoding.gf.GF16)
    (hrs : rs.length = cs.length)
    (hcoeff : ∀ i (hi : i < cs.length),
      (rs.get ⟨i, by omega⟩).toGF216 =
        (cs.get ⟨i, hi⟩).toGF216 +
        (ds.get ⟨i, by omega⟩).toGF216) :
    listToGF216Poly rs =
      listToGF216Poly cs + listToGF216Poly ds := by
  ext m
  simp only [listToGF216Poly_coeff, coeff_add]
  by_cases hm : m < cs.length
  · simp only [hm, show m < ds.length from by omega, show m < rs.length from by omega, dif_pos]
    exact hcoeff m hm
  · push Not at hm
    simp [show ¬(m < cs.length) from by omega,
          show ¬(m < ds.length) from by omega,
          show ¬(m < rs.length) from by omega]

/--
`listToGF216Poly` of `drop 1` relates to the original polynomial by division by `X`.

If the constant-term coefficient of a `GF16` list has `toGF216 = 0`, then
`listToGF216Poly cs = X · listToGF216Poly (cs.drop 1)`.
-/
lemma listToGF216Poly_eq_X_mul_listToGF216Poly_drop_one
    (cs : List spqr.encoding.gf.GF16)
    (h0 : (listToGF216Poly cs).coeff 0 = 0) :
    listToGF216Poly cs = X * listToGF216Poly (cs.drop 1) := by
  ext m
  cases m with
  | zero =>
    simp only [coeff_X_mul_zero, h0]
  | succ n =>
    rw [coeff_X_mul, listToGF216Poly_coeff, listToGF216Poly_coeff]
    by_cases hn : n + 1 < cs.length
    · have hdn : n < (cs.drop 1).length := by rw [List.length_drop]; omega
      rw [dif_pos hn, dif_pos hdn]
      congr 1
      simp only [List.get_eq_getElem]
      simp only [List.getElem_drop]
      grind
    · have hdn : ¬(n < (cs.drop 1).length) := by rw [List.length_drop]; omega
      rw [dif_neg hn, dif_neg hdn]

/--
If all coefficients of a list, interpreted via `GF16.toGF216`, match those of a polynomial `q`
at in-range positions, and `q` has zero coefficients beyond the list length, then
`listToGF216Poly cs = q`.
-/
lemma listToGF216Poly_eq_of_coeffs
    (cs : List GF16) (q : GF216[X])
    (h_in : ∀ (m : Nat) (hm : m < cs.length),
      (cs.get ⟨m, hm⟩).toGF216 = q.coeff m)
    (h_out : ∀ m, cs.length ≤ m → q.coeff m = 0) :
    listToGF216Poly cs = q := by
  ext m
  rw [listToGF216Poly_coeff]
  split
  · rename_i hm; exact h_in m hm
  · rename_i hm; push Not at hm; exact (h_out m hm).symm

end spqr.encoding.polynomial
