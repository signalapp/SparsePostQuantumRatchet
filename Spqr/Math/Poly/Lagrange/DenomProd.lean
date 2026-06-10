/-
Copyright 2026 The Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE-APACHE.
Authors: Hoang Le Truong
-/
import Spqr.Math.Poly.Basic.Defs

/-!
# Lagrange denominator product

`lagrangeDenomProd pi_x pts start` computes the product
`∏_{j = start}^{pts.length - 1} (if pi_x = pts[j].x then 1 else pi_x.toGF216 - pts[j].x.toGF216)`.

## Main definitions

* `lagrangeDenomProd` — the recursive denominator product.

## Main statements

* `lagrangeDenomProd_eq_one_of_le` — out-of-range index gives `1`.
* `lagrangeDenomProd_skip`, `lagrangeDenomProd_accum` — one-step unfoldings.
-/

namespace spqr.encoding.polynomial

/--
Lagrange denominator product over a suffix of the point list.

Given a distinguished x-coordinate `pi_x : GF16`, a list of points `pts`, and a starting index
`start`, compute the product
  `∏_{j = start}^{pts.length - 1}
      (if pi_x.value = pts[j].x.value then 1
       else pi_x.toGF216 - pts[j].x.toGF216)`
over the remaining points in the list.
-/
noncomputable def lagrangeDenomProd (pi_x : spqr.encoding.gf.GF16)
    (pts : List spqr.encoding.polynomial.Pt) (start : Nat) : GF216 :=
  if h : start < pts.length then
    if pi_x.value = (pts.get ⟨start, h⟩).x.value
    then lagrangeDenomProd pi_x pts (start + 1)
    else (pi_x.toGF216 - (pts.get ⟨start, h⟩).x.toGF216) *
         lagrangeDenomProd pi_x pts (start + 1)
  else 1
termination_by pts.length - start

/-- When `start ≥ pts.length`, the product is `1` (empty product). -/
@[simp]
lemma lagrangeDenomProd_eq_one_of_le (pi_x : spqr.encoding.gf.GF16)
    (pts : List spqr.encoding.polynomial.Pt) (start : Nat)
    (h : pts.length ≤ start) :
    lagrangeDenomProd pi_x pts start = 1 := by
  unfold lagrangeDenomProd
  simp [show ¬(start < pts.length) from by omega]

/-- One-step unfolding when the current point matches `pi_x`. -/
lemma lagrangeDenomProd_skip (pi_x : spqr.encoding.gf.GF16)
    (pts : List spqr.encoding.polynomial.Pt) (start : Nat)
    (h : start < pts.length)
    (heq : pi_x.value = (pts.get ⟨start, h⟩).x.value) :
    lagrangeDenomProd pi_x pts start =
      lagrangeDenomProd pi_x pts (start + 1) := by
  conv_lhs => unfold lagrangeDenomProd
  rw [dif_pos h, if_pos heq]

/-- One-step unfolding when the current point differs from `pi_x`. -/
lemma lagrangeDenomProd_accum (pi_x : spqr.encoding.gf.GF16)
    (pts : List spqr.encoding.polynomial.Pt) (start : Nat)
    (h : start < pts.length)
    (hne : pi_x.value ≠ (pts.get ⟨start, h⟩).x.value) :
    lagrangeDenomProd pi_x pts start =
      (pi_x.toGF216 - (pts.get ⟨start, h⟩).x.toGF216) *
        lagrangeDenomProd pi_x pts (start + 1) := by
  conv_lhs => unfold lagrangeDenomProd
  rw [dif_pos h, if_neg hne]

end spqr.encoding.polynomial
