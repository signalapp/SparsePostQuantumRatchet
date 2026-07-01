/-
Copyright 2026 The Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE-APACHE.
Authors: Hoang Le Truong
-/
import Spqr.Specs.Encoding.Polynomial.Poly.LagrangeInterpolatePrepare
import Spqr.Specs.Encoding.Polynomial.Poly.LagrangeInterpolateComplete

/-! # Spec theorem for
`spqr::encoding::polynomial::{spqr::encoding::polynomial::Poly}::lagrange_interpolate_pt`

Returns the i-th scaled Lagrange basis polynomial over GF(2¹⁶) for a point set `pts` at index `i`.

The function proceeds in three steps:

1. **Prepare template**: compute `template = ∏_j (X − pts[j].x)` via
   `lagrange_interpolate_prepare` (degree `pts.len()`, leading `GF16::ONE`).

2. **Complete for point `i`**: call `template.lagrange_interpolate_complete(pts, i)` to get
   `result1` with `result1 · (X − pts[i].x) = X · lagrangeScale(pts[i], pts) · template`.
   The Horner-style division introduces an X-artifact, so `result1.coefficients[0] = 0`.

3. **Remove leading zero**: `remove(0)` strips the zero constant term (divides by `X`).

The result satisfies:

  `result.toGF216Poly = C(lagrangeScaleGF216(pts[i], pts)) · lagrangeBasisPoly pts i`

which is the i-th term in the Lagrange interpolation formula. With distinct x-coordinates
this equals
`pᵢ.y / (∏_{j≠i} (pᵢ.x − pⱼ.x)) · ∏_{j≠i} (X − pⱼ.x)`.

**Source**: spqr/src/encoding/polynomial.rs -/

open Aeneas Aeneas.Std spqr.encoding.gf Polynomial

namespace spqr.encoding.polynomial.Poly

/-- **Spec theorem for `spqr.encoding.polynomial.Poly.lagrange_interpolate_pt`**:

For `pts.len() + 1 ≤ Usize.max` and `i < pts.len()`, the function succeeds and returns
`result : Poly` with:

• **Length**: `result.coefficients.val.length = pts.val.length`.

• **Polynomial identity**:
    `result.toGF216Poly * (X − C(GF16.toGF216(pts[i].x))) =
       C(lagrangeScaleGF216(pts[i], pts)) · prodLinearFactors pts.val 0 pts.val.length` -/
@[step]
theorem lagrange_interpolate_pt_spec
    (pts : Slice Pt) (i : Usize)
    (hi : i < pts.length)
    (h_len : pts.length + 1 ≤ Usize.max) :
    lagrange_interpolate_pt pts i ⦃ (result : Poly) =>
      result.degree = pts.length ∧
      result.toGF216Poly * (X - C (GF16.toGF216 (pts[i]).x)) =
        C (lagrangeScaleGF216 (pts[i]) pts) * prodLinearFactors pts 0 pts.length ⦄ := by
  unfold lagrange_interpolate_pt
  step with lagrange_interpolate_prepare_spec pts h_len as
    ⟨template, h_template_len, _, _,  h_template_eq⟩
  simp_all only [Slice.length, Order.add_one_le_iff, degree, alloc.vec.Vec.length,
    Slice.getElem_Usize_eq]
  have h_template_pos : 0 < template.degree:= by grind[degree]
  have h_root_template : template.evalAt (pts[i]!).x = 0 := by
    unfold Poly.evalAt
    grind[prodLinearFactors_eval_root]
  step with lagrange_interpolate_complete_spec template pts i hi h_template_pos h_root_template as
    ⟨result1, h_r1_len, h_r1_id⟩
  step
  · grind[degree]
  constructor
  · grind[degree]
  · have h_prod_root : (prodLinearFactors pts 0 pts.length).eval (GF16.toGF216 (pts[i]).x) = 0 := by
      unfold Poly.evalAt at h_root_template
      grind
    have h_r1_coeff0 : result1.toGF216Poly.coeff 0 = 0 :=
      coeff_zero_eq_zero_of_X_mul_identity result1.toGF216Poly
        (GF16.toGF216 (pts[i]!).x) (lagrangeScaleGF216 (pts[i]!) pts.val)
        (prodLinearFactors pts 0 pts.length) (by grind) (by grind)
    have h_r1_X_factor : result1.toGF216Poly =
      X * listToGF216Poly (result1.coefficients.val.drop 1) := by
      unfold Poly.toGF216Poly
      exact listToGF216Poly_eq_X_mul_listToGF216Poly_drop_one result1.coefficients.val h_r1_coeff0
    unfold Poly.toGF216Poly
    apply mul_left_cancel₀ Polynomial.X_ne_zero
    grind

end spqr.encoding.polynomial.Poly
