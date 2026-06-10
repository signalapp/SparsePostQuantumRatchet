/-
Copyright 2026 The Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE-APACHE.
Authors: Hoang Le Truong
-/
import Spqr.Math.Poly.LinearFactors.Degree
import Spqr.Math.Poly.Lagrange.DenomProd

/-!
# Lagrange scaling factor and basis polynomial

## Main definitions

* `lagrangeScaleGF216` — the field scaling factor `pi.y · denomProd^(2^16 − 2)`.
* `lagrangeBasisPoly` — `∏_{j ≠ i} (X − pts[j].x)`.

## Main statements

* `natDegree_lagrangeBasisPoly_le` — degree bound for the basis polynomial.
-/

open Polynomial
open spqr.encoding.gf

namespace spqr.encoding.polynomial

/--
Lagrange scaling factor in `GF216`.

Given a distinguished point `pi` and the full point list `pts`,
`lagrangeScaleGF216 pi pts = pi.y.toGF216 * (lagrangeDenomProd pi.x pts 0) ^ (2^16 − 2)`.

In a field of order `q`, `x^(q−2)` is the multiplicative inverse of `x` (for `x ≠ 0`) by
Fermat's little theorem, so this equals
`pi.y / ∏_{j, pts[j].x ≠ pi.x} (pi.x − pts[j].x)`.
-/
noncomputable def lagrangeScaleGF216
    (pi : spqr.encoding.polynomial.Pt)
    (pts : List spqr.encoding.polynomial.Pt) : GF216 :=
  pi.y.toGF216 *
    (lagrangeDenomProd pi.x pts 0) ^ (2 ^ 16 - 2)

/--
Lagrange basis polynomial: the product `∏_{j ≠ i} (X − pts[j].x)` of linear factors over all
points except the `i`-th.
-/
noncomputable def lagrangeBasisPoly
    (pts : List spqr.encoding.polynomial.Pt) (i : Nat) :
    Polynomial GF216 :=
  if i < pts.length then
    prodLinearFactors pts 0 i *
      prodLinearFactors pts (i + 1) pts.length
  else 1

/-- Degree bound for `lagrangeBasisPoly`. -/
lemma natDegree_lagrangeBasisPoly_le
    (pts : List Pt) (i : Nat) (hi : i < pts.length) (hn : 0 < pts.length) :
    (lagrangeBasisPoly pts i).natDegree ≤ pts.length - 1 := by
  simp only [lagrangeBasisPoly, if_pos hi]
  calc (prodLinearFactors pts 0 i * prodLinearFactors pts (i + 1) pts.length).natDegree
      ≤ (prodLinearFactors pts 0 i).natDegree +
          (prodLinearFactors pts (i + 1) pts.length).natDegree :=
        Polynomial.natDegree_mul_le
    _ ≤ (i - 0) + (pts.length - (i + 1)) := by
        have h1 := natDegree_prodLinearFactors_le pts 0 i (by omega) (by omega)
        have h2 := natDegree_prodLinearFactors_le pts (i + 1) pts.length (by omega) (by omega)
        omega
    _ = pts.length - 1 := by omega

end spqr.encoding.polynomial
