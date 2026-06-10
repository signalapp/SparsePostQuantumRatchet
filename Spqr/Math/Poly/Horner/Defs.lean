/-
Copyright 2026 The Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE-APACHE.
Authors: Hoang Le Truong
-/
import Spqr.Math.Poly.Basic.Defs

/-!
# Horner-scheme accumulator

## Main definitions

* `hornerAccum` — Horner-scheme accumulator for polynomial evaluation.

## Main statements

* `hornerAccum_eq_zero_of_le` — out-of-range index gives `0`.
* `hornerAccum_unfold` — one-step unfolding.
* `hornerAccum_cons` — shifting lemma on a `cons` cell.
-/

open Polynomial
open spqr.encoding.gf

namespace spqr.encoding.polynomial

/--
Horner-scheme accumulator for polynomial evaluation.

`hornerAccum g_x coeffs pos` computes the Horner evaluation of the polynomial with
coefficients `coeffs[pos], coeffs[pos+1], …` at the point `g_x.toGF216`.
-/
noncomputable def hornerAccum (g_x : spqr.encoding.gf.GF16)
    (coeffs : List spqr.encoding.gf.GF16) (pos : Nat) : GF216 :=
  if h : pos < coeffs.length then
    (coeffs.get ⟨pos, h⟩).toGF216 +
      g_x.toGF216 * hornerAccum g_x coeffs (pos + 1)
  else 0
termination_by coeffs.length - pos

@[simp]
lemma hornerAccum_eq_zero_of_le (g_x : spqr.encoding.gf.GF16)
    (coeffs : List spqr.encoding.gf.GF16) (pos : Nat)
    (h : coeffs.length ≤ pos) :
    hornerAccum g_x coeffs pos = 0 := by
  unfold hornerAccum
  simp [show ¬(pos < coeffs.length) from by omega]

lemma hornerAccum_unfold (g_x : spqr.encoding.gf.GF16)
    (coeffs : List spqr.encoding.gf.GF16) (pos : Nat)
    (h : pos < coeffs.length) :
    hornerAccum g_x coeffs pos =
      (coeffs.get ⟨pos, h⟩).toGF216 +
        g_x.toGF216 * hornerAccum g_x coeffs (pos + 1) := by
  conv_lhs => unfold hornerAccum
  rw [dif_pos h]

/--
Shifting lemma: evaluating `hornerAccum` on `c :: cs` at position `pos + 1` is the same as
evaluating on `cs` at position `pos`.
-/
lemma hornerAccum_cons
    (g c : GF16)
    (cs : List GF16)
    (pos : Nat) :
    hornerAccum g (c :: cs) (pos + 1) =
      hornerAccum g cs pos := by
  by_cases hlt : pos < cs.length
  · rw [hornerAccum_unfold g (c :: cs) (pos + 1) (by simp; omega),
        hornerAccum_unfold g cs pos hlt]
    have hget : (c :: cs).get ⟨pos + 1, by simp; omega⟩ = cs.get ⟨pos, hlt⟩ := by
      simp [List.get_eq_getElem]
    rw [hget]; congr 1; congr 1
    exact hornerAccum_cons g c cs (pos + 1)
  · rw [hornerAccum_eq_zero_of_le g (c :: cs) (pos + 1) (by simp; omega),
        hornerAccum_eq_zero_of_le g cs pos (by omega)]
termination_by cs.length - pos
decreasing_by omega

end spqr.encoding.polynomial
