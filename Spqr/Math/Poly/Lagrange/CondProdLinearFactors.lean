/-
Copyright 2026 The Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE-APACHE.
Authors: Hoang Le Truong
-/
import Spqr.Math.Poly.Basic.Defs

/-!
# Conditional product of linear factors

`condProdLinearFactors pi_x pts start` computes the product
`∏_{k ≥ start, pts[k].x ≠ pi_x} (X − C(pts[k].x.toGF216))`,
skipping indices where `pi_x.value = pts[k].x.value`.  Returns `1` when
`start ≥ pts.length` (empty product).

This is the polynomial built by the inner loop of
`PolyConst::lagrange_interpolate_pt` — one factor `(X − α_j)` for every
evaluation point whose x-coordinate differs from the interpolation point.

## Main definitions

* `condProdLinearFactors` — the recursive product.

## Main statements

* `condProdLinearFactors_ge` — out-of-range index gives `1`.
* `condProdLinearFactors_skip` — one-step skip unfolding.
* `condProdLinearFactors_accum` — one-step accumulate unfolding.
-/

open Polynomial spqr.encoding.gf

namespace spqr.encoding.polynomial.PolyConst.lagrange_interpolate_pt_loop

/-- **Conditional product of linear factors**
`∏_{k ≥ start, pts[k].x ≠ pi_x} (X − C(pts[k].x.toGF216))`.
Returns `1` when `start ≥ pts.length`. Skips when `pi_x.value = pts[start].x.value`.
-/
noncomputable def condProdLinearFactors (pi_x : GF16)
    (pts : List Pt) (start : Nat) : GF216[X] :=
  if h : start < pts.length then
    if pi_x.value = pts[start].x.value
    then condProdLinearFactors pi_x pts (start + 1)
    else (X - C (pts[start].x.toGF216)) *
         condProdLinearFactors pi_x pts (start + 1)
  else 1
termination_by pts.length - start

@[simp]
lemma condProdLinearFactors_ge (pi_x : GF16)
    (pts : List Pt) (start : Nat)
    (h : pts.length ≤ start) :
    condProdLinearFactors pi_x pts start = 1 := by
  unfold condProdLinearFactors
  simp [show ¬(start < pts.length) from by omega]

lemma condProdLinearFactors_skip (pi_x : GF16) (pts : List Pt) (start : Nat)
    (h : start < pts.length)
    (heq : pi_x.value = pts[start].x.value) :
    condProdLinearFactors pi_x pts start =
      condProdLinearFactors pi_x pts (start + 1) := by
  conv_lhs => unfold condProdLinearFactors
  rw [dif_pos h, if_pos heq]

lemma condProdLinearFactors_accum (pi_x : GF16) (pts : List Pt) (start : Nat)
    (h : start < pts.length)
    (hne : pi_x.value ≠ pts[start].x.value) :
    condProdLinearFactors pi_x pts start =
      (X - C (pts[start].x.toGF216)) *
        condProdLinearFactors pi_x pts (start + 1) := by
  conv_lhs => unfold condProdLinearFactors
  rw [dif_pos h, if_neg hne]

end spqr.encoding.polynomial.PolyConst.lagrange_interpolate_pt_loop
