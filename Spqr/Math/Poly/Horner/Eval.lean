/-
Copyright 2026 The Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE-APACHE.
Authors: Hoang Le Truong
-/
import Spqr.Math.Poly.Horner.Defs
import Spqr.Math.Poly.CharTwo.Basic
import Spqr.Math.Poly.Coeff.Basic
import Spqr.Math.Poly.Basic.Zero

/-!
# Horner-scheme evaluation bridge

## Main statements

* `hornerAccum_cancel` — characteristic-2 cancellation identity.
* `hornerAccum_zero_eq_eval` — `hornerAccum g coeffs 0` equals `Polynomial.eval`.
-/

open Polynomial
open spqr.encoding.gf

namespace spqr.encoding.polynomial

/--
Horner cancellation: `hornerAccum g coeffs k + g.toGF216 * hornerAccum g coeffs (k + 1) =
coeffs[k].toGF216`.

In characteristic 2, the intermediate terms cancel out.
-/
lemma hornerAccum_cancel (g : spqr.encoding.gf.GF16)
    (coeffs : List spqr.encoding.gf.GF16) (k : Nat)
    (hk : k < coeffs.length) :
    hornerAccum g coeffs k +
      g.toGF216 * hornerAccum g coeffs (k + 1) =
      (coeffs.get ⟨k, hk⟩).toGF216 := by
  conv_lhs => rw [hornerAccum_unfold g coeffs k hk]
  set c := (coeffs.get ⟨k, hk⟩).toGF216
  set t := g.toGF216 * hornerAccum g coeffs (k + 1)
  rw [show (c + t) + t = c + (t + t) from by ring]
  rw [GF216.add_self_eq_zero t, add_zero]

/--
`hornerAccum` at position 0 equals polynomial evaluation.

This connects the Horner-scheme computation `hornerAccum g coeffs 0`
to the Mathlib `Polynomial.eval` of `listToGF216Poly coeffs`.
-/
lemma hornerAccum_zero_eq_eval
    (g : GF16) (coeffs : List GF16) :
    hornerAccum g coeffs 0 =
      (listToGF216Poly coeffs).eval (g.toGF216) := by
  induction coeffs with
  | nil =>
    rw [hornerAccum_eq_zero_of_le g [] 0 (by simp)]
    simp
  | cons c cs ih =>
    rw [hornerAccum_unfold g (c :: cs) 0 (by simp)]
    simp only [List.get_eq_getElem, List.getElem_cons_zero]
    rw [hornerAccum_cons g c cs 0, ih, listToGF216Poly_cons]
    simp [eval_add, eval_mul, eval_C, eval_X]

theorem hornerAccum_eq_of_idx_eq
    {g_x : GF16} {v_list xs : List GF16}
    {a b : Nat} {ha : a < xs.length} {hb : b < xs.length}
    (h_eq : a = b)
    (hsuff : (xs.get ⟨b, hb⟩).toGF216 =
      hornerAccum g_x v_list b) :
    (xs.get ⟨a, ha⟩).toGF216 =
      hornerAccum g_x v_list a := by
  subst h_eq; exact hsuff


end spqr.encoding.polynomial
