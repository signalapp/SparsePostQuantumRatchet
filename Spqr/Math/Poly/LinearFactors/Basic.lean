/-
Copyright 2026 The Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE-APACHE.
Authors: Hoang Le Truong
-/
import Spqr.Math.Poly.Basic.Defs

/-!
# Product of linear factors

`prodLinearFactors pts start stop` computes the product
`∏_{j = start}^{stop − 1} (X − C(pts[j].x.toGF216))` over a contiguous range of points.

## Main definitions

* `prodLinearFactors` — the recursive product.

## Main statements

* `prodLinearFactors_eq_one_of_not_lt` — empty product equals `1`.
* `prodLinearFactors_step` — left unfolding.
* `prodLinearFactors_snoc` — right unfolding.
-/

open Polynomial
open spqr.encoding.gf

namespace spqr.encoding.polynomial

/--
Product of linear factors `∏_{j=start}^{stop−1} (X − C(pts[j].x.toGF216))`.

This is the target polynomial that `lagrange_interpolate_prepare` constructs.  It returns `1`
when `start ≥ stop` or `start ≥ pts.length` (empty product).
-/
noncomputable def prodLinearFactors
    (pts : List Pt) (start stop : Nat) : GF216[X] :=
  if h : start < stop ∧ start < pts.length then
    (X - C ((pts.get ⟨start, h.2⟩).x.toGF216)) *
      prodLinearFactors pts (start + 1) stop
  else 1
termination_by stop - start

/-- When `start ≥ stop` or `start ≥ pts.length`, the product is `1` (empty product). -/
@[simp]
lemma prodLinearFactors_eq_one_of_not_lt (pts : List Pt) (start stop : Nat)
    (h : ¬(start < stop ∧ start < pts.length)) :
    prodLinearFactors pts start stop = 1 := by
  unfold prodLinearFactors; rw [dif_neg h]

/-- One-step unfolding of `prodLinearFactors` from the left. -/
lemma prodLinearFactors_step (pts : List Pt) (start stop : Nat)
    (h1 : start < stop) (h2 : start < pts.length) :
    prodLinearFactors pts start stop =
      (X - C ((pts.get ⟨start, h2⟩).x.toGF216)) *
        prodLinearFactors pts (start + 1) stop := by
  conv_lhs => unfold prodLinearFactors
  rw [dif_pos ⟨h1, h2⟩]

/-- One-step unfolding of `prodLinearFactors` from the right (snoc form). -/
private lemma prodLinearFactors_snoc_aux (pts : List Pt) (stop : Nat)
    (h2 : stop < pts.length) :
    ∀ d s, s + d = stop → s ≤ stop →
      prodLinearFactors pts s (stop + 1) =
        prodLinearFactors pts s stop *
          (X - C ((pts.get ⟨stop, h2⟩).x.toGF216)) := by
  intro d
  induction d with
  | zero =>
    intro s hs hle
    have hseq : stop = s := by omega
    subst hseq
    rw [prodLinearFactors_step pts stop (stop + 1) (by omega) h2,
        prodLinearFactors_eq_one_of_not_lt pts (stop + 1) (stop + 1) (by omega),
        prodLinearFactors_eq_one_of_not_lt pts stop stop (by omega)]
    ring
  | succ n ih =>
    intro s hs hle
    rw [prodLinearFactors_step pts s (stop + 1) (by omega) (by omega),
        prodLinearFactors_step pts s stop (by omega) (by omega)]
    rw [ih (s + 1) (by omega) (by omega)]
    ring

lemma prodLinearFactors_snoc (pts : List Pt) (start stop : Nat)
    (h1 : start ≤ stop) (h2 : stop < pts.length) :
    prodLinearFactors pts start (stop + 1) =
      prodLinearFactors pts start stop *
        (X - C ((pts.get ⟨stop, h2⟩).x.toGF216)) :=
  prodLinearFactors_snoc_aux pts stop h2 (stop - start) start (by omega) h1

end spqr.encoding.polynomial
