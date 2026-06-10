/-
Copyright 2026 The Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE-APACHE.
Authors: Hoang Le Truong
-/
import Spqr.Math.Poly.Horner.Eval

/-!
# Polynomial identity from loop 1 (lagrange_interpolate_complete)

The polynomial identity `listToGF216Poly v * (X - C g) = X * C s *
listToGF216Poly coeffs` arising from the Horner-scheme loop in
`lagrange_interpolate_complete`.

## Main statements

* `poly_identity_from_loop1` — the Horner-scheme division + scaling identity.
-/

open Aeneas Aeneas.Std Result Polynomial
open spqr.math.gf spqr.encoding.gf spqr.encoding.polynomial

namespace spqr.encoding.polynomial

/-! ## Polynomial identity -/

/--
The mathematical polynomial identity from the Horner-scheme loop.

Given a coefficient list `coeffs`, a result list `v` of the same length,
a field element `g : GF16`, a scale `s : GF216`, and the conditions that
`v[0].toGF216 = 0`, `hornerAccum g coeffs 0 = 0`, and
`v[k].toGF216 = s * hornerAccum g coeffs k` for `k > 0`, then
`listToGF216Poly v * (X - C g.toGF216) = X * C s * listToGF216Poly coeffs`.
-/
theorem poly_identity_from
    (coeffs v : List GF16)
    (g : GF16) (s : GF216)
    (hlen : v.length = coeffs.length)
    (hpos : 0 < coeffs.length)
    (hv0_zero : ∀ (h0 : 0 < v.length),
        (v.get ⟨0, h0⟩).toGF216 = 0)
    (hH0 : hornerAccum g coeffs 0 = 0)
    (hvk : ∀ k (hk : k < v.length), 0 < k →
        (v.get ⟨k, hk⟩).toGF216 =
          s * hornerAccum g coeffs k) :
    listToGF216Poly v * (X - C (g.toGF216)) =
      X * C s * listToGF216Poly coeffs := by
  rw [GF216Poly.sub_eq_add, mul_add, mul_comm (listToGF216Poly v) (C (g.toGF216)),
      show X * C s * listToGF216Poly coeffs =
        C s * (X * listToGF216Poly coeffs) from by ring]
  ext m
  simp only [coeff_add, coeff_C_mul]
  set α := g.toGF216
  by_cases hm0 : m = 0
  · subst hm0
    rw [coeff_mul_X_zero, coeff_X_mul_zero, zero_add, mul_zero]
    simp only [listToGF216Poly_coeff]
    split
    · rename_i h0v
      rw [hv0_zero h0v, mul_zero]
    · rename_i h0v; push Not at h0v; omega
  · have hm_pos : 0 < m := Nat.pos_of_ne_zero hm0
    have hcoeff_v_X : (listToGF216Poly v * X).coeff m =
        (listToGF216Poly v).coeff (m - 1) := by
      conv_lhs => rw [show m = m - 1 + 1 from by omega]
      rw [coeff_mul_X]
    have hcoeff_X_c : (X * listToGF216Poly coeffs).coeff m =
        (listToGF216Poly coeffs).coeff (m - 1) := by
      conv_lhs => rw [show m = m - 1 + 1 from by omega]
      rw [coeff_X_mul]
    rw [hcoeff_v_X, hcoeff_X_c]
    simp only [listToGF216Poly_coeff]
    by_cases hm_lt : m < coeffs.length
    · have hm1_lt_c : m - 1 < coeffs.length := by omega
      have hm1_lt_v : m - 1 < v.length := by omega
      have hm_lt_v : m < v.length := by omega
      rw [dif_pos hm1_lt_v, dif_pos hm_lt_v, dif_pos hm1_lt_c]
      by_cases hm1_zero : m - 1 = 0
      · have hm_eq_1 : m = 1 := by omega
        subst hm_eq_1; simp only [Nat.sub_self]
        rw [hv0_zero (by omega),
            hvk 1 (by omega) (by omega), zero_add]
        have hH0_unf :=
          hornerAccum_unfold g coeffs 0 (by omega)
        rw [hH0] at hH0_unf
        have hcoeff0 :
            (coeffs.get ⟨0, by omega⟩).toGF216 =
              α * hornerAccum g coeffs 1 :=
          GF216_eq_of_add_eq_zero hH0_unf.symm
        rw [hcoeff0]; ring
      · have hm1_pos : 0 < m - 1 := by omega
        rw [hvk (m - 1) hm1_lt_v hm1_pos,
            hvk m hm_lt_v hm_pos]
        rw [show s * hornerAccum g coeffs (m - 1) +
              α * (s * hornerAccum g coeffs m) =
            s * (hornerAccum g coeffs (m - 1) +
              α * hornerAccum g coeffs m) from by ring]
        congr 1
        have hm_succ : m - 1 + 1 = m := by omega
        have := hornerAccum_cancel g coeffs (m - 1) hm1_lt_c
        rw [hm_succ] at this
        exact this
    · push Not at hm_lt
      by_cases hm_eq : m = coeffs.length
      · subst hm_eq
        have hm1_lt_c : coeffs.length - 1 < coeffs.length :=
          by omega
        have hm1_lt_v : coeffs.length - 1 < v.length := by omega
        rw [dif_pos hm1_lt_v,
            dif_neg (show ¬(coeffs.length < v.length) from
              by omega),
            dif_pos hm1_lt_c]
        rw [mul_zero, add_zero]
        have hH_last :=
          hornerAccum_unfold g coeffs (coeffs.length - 1) hm1_lt_c
        have hsucc : coeffs.length - 1 + 1 = coeffs.length :=
          by omega
        rw [hsucc] at hH_last
        rw [hornerAccum_eq_zero_of_le g coeffs coeffs.length (le_refl _)] at hH_last
        simp [mul_zero, add_zero] at hH_last
        have hH_last_get : (coeffs.get ⟨coeffs.length - 1, hm1_lt_c⟩).toGF216 =
            hornerAccum g coeffs (coeffs.length - 1) := by
          simp only [List.get_eq_getElem]; exact hH_last.symm
        rw [hH_last_get]
        by_cases h_pos : 0 < coeffs.length - 1
        · exact hvk (coeffs.length - 1) hm1_lt_v h_pos
        · have h0 : coeffs.length - 1 = 0 := by omega
          have hv_eq : v.get ⟨coeffs.length - 1, hm1_lt_v⟩ =
              v.get ⟨0, by omega⟩ := by
            congr 1; exact Fin.ext h0
          rw [show (v.get ⟨coeffs.length - 1, hm1_lt_v⟩).toGF216 =
              (v.get ⟨0, by omega⟩).toGF216 from by rw [hv_eq]]
          rw [hv0_zero (by omega), h0, hH0, mul_zero]
      · have hm_gt : coeffs.length < m := by omega
        rw [dif_neg (show ¬(m - 1 < v.length) from by omega),
            dif_neg (show ¬(m < v.length) from by omega),
            dif_neg (show ¬(m - 1 < coeffs.length) from by omega)]
        ring

end spqr.encoding.polynomial
