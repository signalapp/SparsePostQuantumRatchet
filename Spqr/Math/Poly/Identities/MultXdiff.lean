/-
Copyright 2026 The Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE-APACHE.
Authors: Hoang Le Truong
-/
import Spqr.Math.List

/-!
# Polynomial identities for `mult_xdiff`

This file collects the pure-mathematical polynomial identity lemmas used by the
`PolyConst::mult_xdiff` specification proof.

## Main statements

* `getElem!_value_val_eq_zero_of_natDegree_lt` — if a polynomial's `natDegree + 1 < n` and
  `n ≤ cs.length`, then the GF16 element at position `n − 1` has underlying `u16` value `0`.
* `mult_xdiff_result_eq` — the polynomial identity
  `listToGF216Poly xp2.val = (X − C d.toGF216) * listToGF216Poly a.val`
  derived from the loop 0 and loop 1 postconditions.
-/

open Aeneas Aeneas.Std spqr.encoding.gf Polynomial

namespace spqr.encoding.polynomial

/--
If the polynomial `listToGF216Poly cs` has `natDegree + 1 < n` and `n ≤ cs.length`,
then the GF16 element at position `n − 1` has underlying `u16` value `0`.

This bridges from a mathematical degree bound to the bit-level representation,
composing `Polynomial.coeff_eq_zero_of_natDegree_lt`, `getElem!_toGF216_eq_coeff`,
and `GF16_toGF216_eq_zero_imp`.
-/
lemma getElem!_value_val_eq_zero_of_natDegree_lt
    (cs : List GF16) (n : Nat)
    (h_pos : 0 < n)
    (h_deg : listGF216Degree cs + 1 < n) :
    (cs[n - 1]!).value.val = 0 := by
  unfold listGF216Degree at h_deg
  have h_coeff : (listToGF216Poly cs).coeff (n - 1) = 0 :=
    Polynomial.coeff_eq_zero_of_natDegree_lt (by omega)
  have h_toGF216 : (cs[n - 1]!).toGF216 = 0 := by
    rw [getElem!_toGF216_eq_coeff]; exact h_coeff
  exact GF16_toGF216_eq_zero_imp _ h_toGF216

/-- **Polynomial identity lemma**: the result polynomial equals
`(X - C d.toGF216) * listToGF216Poly a.val` -/
lemma mult_xdiff_result_eq
    {N : Usize} (a : Array GF16 N) (d : GF16) (i : Usize) (xp1 dp1 xp2 : Array GF16 N)
    (h_N_pos : 0 < N.val)
    (h_i_val : i.val = N - 1)
    (h_deg : listGF216Degree a.val + 1 < N)
    (h_dp : ∀ (j : Nat), j < N →
      ∀ (_ : j < dp1.length), (dp1[j]!).toGF216 = (a[j]!).toGF216 * d.toGF216)
    (h_xp_shift : ∀ (j : Nat), j < i →
      ∀ (_ : j + 1 < xp1.length), xp1[j + 1]! = a.val[j]!)
    (h_xp_unch : ∀ (j : Nat), ¬(0 < j ∧ j ≤ i) →
      xp1[j]? = (Array.repeat N GF16.ZERO)[j]?)
    (h_sub : ∀ (j : Nat), 0 ≤ j ∧ j < N →
      ∀ (hj : j < xp2.length),
        (xp2.val.get ⟨j, hj⟩).toGF216 = (xp1.val[j]!).toGF216 - (dp1.val[j]!).toGF216) :
    listToGF216Poly xp2.val = (X - C d.toGF216) * listToGF216Poly a.val := by
  apply listToGF216Poly_eq_of_coeffs
  · intro m hm
    rw [sub_mul, coeff_sub, coeff_C_mul, ← getElem!_toGF216_eq_coeff]
    cases m with
    | zero =>
      rw [coeff_X_mul_zero]
      have h_xp1_0 : (xp1.val[0]!).toGF216 = 0 := by
        have h_unch := h_xp_unch 0 (by omega)
        have h_len_xp1 : 0 < xp1.val.length := by
          simp [List.Vector.length_val]; omega
        have h_len_rep : 0 < (Array.repeat N GF16.ZERO).val.length := by
          simp [Array.repeat_val]; omega
        have h_eq := list_get_of_getElem?_eq h_unch h_len_xp1 h_len_rep
        rw [getElem!_pos xp1.val 0 h_len_xp1]
        simp only [List.get_eq_getElem] at h_eq
        rw [h_eq]
        exact GF16.toGF216_eq_zero _ (by simp [GF16.ZERO])
      grind
    | succ n => grind [coeff_X_mul, ← getElem!_toGF216_eq_coeff]
  · intro m hm
    rw [sub_mul, coeff_sub, coeff_C_mul, listToGF216Poly_coeff_eq_zero _ m (by grind),
        mul_zero, sub_zero]
    cases m with
    | zero => grind
    | succ n =>
      rw [coeff_X_mul, listToGF216Poly_coeff]
      have h_val_zero := getElem!_value_val_eq_zero_of_natDegree_lt a.val N.val h_N_pos h_deg
      grind [GF16.toGF216_eq_zero]

end spqr.encoding.polynomial
