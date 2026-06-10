/-
Copyright 2026 The Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE-APACHE.
Authors: Hoang Le Truong
-/
import Spqr.Math.Poly.Basic.Defs

/-!
# Coefficient characterization of `listToGF216Poly`

This file collects the coefficient and structural lemmas for `listToGF216Poly`:
the in-range and out-of-range coefficients, the singleton and cons decomposition.

## Main statements

* `listToGF216Poly_coeff` — formula for coefficient `m`.
* `listToGF216Poly_coeff_eq_zero` — out-of-range coefficients vanish.
* `listToGF216Poly_singleton` — `listToGF216Poly [a] = C a.toGF216`.
* `listToGF216Poly_cons` — Horner-like decomposition for a cons cell.
-/

open Polynomial

namespace spqr.encoding.polynomial

/-! ## Coefficient characterization -/

/--
The coefficient of `listToGF216Poly cs` at position `m` is `cs[m].toGF216` when `m < cs.length`,
and `0` otherwise.
-/
lemma listToGF216Poly_coeff (cs : List spqr.encoding.gf.GF16) (m : Nat) :
    (listToGF216Poly cs).coeff m =
      if hm : m < cs.length
      then (cs.get ⟨m, hm⟩).toGF216
      else 0 := by
  unfold listToGF216Poly
  simp only [finset_sum_coeff, coeff_C_mul, coeff_X_pow]
  split
  · rename_i hm
    rw [Finset.sum_eq_single_of_mem ⟨m, hm⟩ (Finset.mem_univ _)
        (fun ⟨j, hj⟩ _ hjm => by simp [show m ≠ j from fun h => hjm (Fin.ext h.symm)])]
    simp
  · rename_i hm
    push Not at hm
    exact Finset.sum_eq_zero fun ⟨i, hi⟩ _ => by
      simp [show m ≠ i from by omega]

/-- Coefficients at positions `≥ cs.length` are zero. -/
lemma listToGF216Poly_coeff_eq_zero (cs : List spqr.encoding.gf.GF16)
    (m : Nat) (hm : cs.length ≤ m) :
    (listToGF216Poly cs).coeff m = 0 := by
  rw [listToGF216Poly_coeff]
  simp [show ¬(m < cs.length) from by omega]

/-! ## Singleton and cons decomposition -/

/--
A single-coefficient list `[a]` produces the constant polynomial `C (a.toGF216)` in `GF(2¹⁶)[X]`. -/
lemma listToGF216Poly_singleton (a : spqr.encoding.gf.GF16) :
    listToGF216Poly [a] = C (a.toGF216) := by
  simp [listToGF216Poly, Finset.univ_unique]

/-- Decomposition: `listToGF216Poly (c :: cs) = C(c.toGF216) + X · listToGF216Poly cs`.

This is the cons-cell decomposition that mirrors the Horner-scheme evaluation pattern. -/
lemma listToGF216Poly_cons
    (c : spqr.encoding.gf.GF16)
    (cs : List spqr.encoding.gf.GF16) :
    listToGF216Poly (c :: cs) =
      C (c.toGF216) + X * listToGF216Poly cs := by
  ext m
  cases m with
  | zero =>
    simp only [coeff_add, listToGF216Poly_coeff,
               dif_pos (show 0 < (c :: cs).length from by simp)]
    simp only [List.get_eq_getElem, List.getElem_cons_zero,
               coeff_C_zero, coeff_X_mul_zero, add_zero]
  | succ n =>
    simp only [coeff_add, coeff_C_succ, zero_add, coeff_X_mul,
               listToGF216Poly_coeff]
    by_cases hlt : n + 1 < (c :: cs).length
    · rw [dif_pos hlt, dif_pos (show n < cs.length from by simp at hlt; omega)]
      congr 1
    · rw [dif_neg hlt, dif_neg (show ¬(n < cs.length) from by simp at hlt ⊢; omega)]

end spqr.encoding.polynomial
