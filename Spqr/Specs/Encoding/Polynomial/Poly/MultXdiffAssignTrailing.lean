/-
Copyright 2026 The Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE-APACHE.
Authors: Hoang Le Truong
-/
import Spqr.Math.Poly.Coeff.MultXdiffPolyIdentity
import Spqr.Specs.Encoding.Gf.GF16.Mul
import Spqr.Specs.Encoding.Gf.GF16.SubAssign
import Spqr.Specs.Aeneas.RangeIteratorNext
/-! # Spec theorem for `mult_xdiff_assign_trailing`: loop body 0

Let `v = [c₀, c₁, …, cₙ₋₁]` be a polynomial over `GF(2¹⁶)` stored in ascending degree order, and let
`difference : GF16`. The function `Poly.mult_xdiff_assign_trailing(start, difference)` updates the
trailing sub-polynomial `self[start..]` in place by multiplying it with `(x − difference)`.

Since `GF(2¹⁶)` has characteristic 2, subtraction equals addition, so
`(x − difference) = (x + difference)`. The update follows the recurrence:

`v[i − 1] -= v[i] * difference` for `i ∈ start..l`

where `l = self.coefficients.len()`.

For a polynomial `p(x) = ∑ᵢ cᵢxⁱ`, multiplication by `(x − d)` expands to `x · p(x) − d · p(x)`:
the `x · p(x)` term shifts coefficients by one degree, while `−d · p(x)` contributes `cᵢ · d` to
position `i − 1`. The loop performs this update in place over the trailing range.

**Source**: `spqr/src/encoding/polynomial.rs`-/


open Aeneas Aeneas.Std  spqr.encoding.gf

namespace spqr.encoding.polynomial.Poly.mult_xdiff_assign_trailing_loop

@[step]
theorem body_spec
    (difference : GF16)
    (iter : core.ops.range.Range Usize)
    (v : alloc.vec.Vec GF16)
    (h_start_ge : 1 ≤ iter.start.val)
    (h_end_eq : iter.end.val = v.val.length) :
    body difference iter v ⦃ cf =>
      match cf with
      | ControlFlow.done r =>
          r = v ∧ ¬ (iter.start.val < iter.end.val)
      | ControlFlow.cont (iter1, v1) =>
          iter.start.val < iter.end.val ∧
          iter1.start.val = iter.start.val + 1 ∧
          iter1.end = iter.end ∧
          v1.val.length = v.val.length ∧
          (∀ (h_idx : iter.start.val - 1 < v1.val.length),
            (v1.val.get ⟨iter.start.val - 1, h_idx⟩).toGF216 =
              (v.val[iter.start.val - 1]!).toGF216 -
              (v.val[iter.start.val]!).toGF216 * difference.toGF216) ∧
          (∀ j ≠ iter.start.val - 1, v1.val[j]? = v.val[j]?) ⦄ := by
  unfold body
  obtain ⟨opt, iter1, hnext, h_none, h_some⟩ := core.iter.range.IteratorRange.next_Usize_spec iter
  rw [hnext]
  simp only [bind_tc_ok]
  by_cases h_lt : iter.start.val < iter.end.val
  · obtain ⟨h_opt_eq, h_start1, h_end1⟩ := h_some h_lt
    rw [h_opt_eq]
    step*
    simp_all
  · grind

end spqr.encoding.polynomial.Poly.mult_xdiff_assign_trailing_loop

/-! # Spec theorem for `mult_xdiff_assign_trailing`: loop 0

Let `v = [c₀, c₁, …, cₙ₋₁]` be a polynomial over `GF(2¹⁶)` in ascending degree order, and let
`difference : GF16`. The loop `Poly.mult_xdiff_assign_trailing_loop` iterates over `start..l`
(where `l = v.length`) and updates `self[start..]` in place to multiply the trailing
sub-polynomial by `(x − difference)`.

Since `GF(2¹⁶)` has characteristic 2, `(x − difference) = (x + difference)`. The update follows:

`v[i − 1] -= v[i] * difference` for `i ∈ start..l`

corresponding to the expansion `(x − d)p(x) = x · p(x) − d · p(x)`, where `x · p(x)` shifts
coefficients and `−d · p(x)` updates position `i − 1`. The loop performs this propagation in place.

**Source**: `spqr/src/encoding/polynomial.rs`
-/


namespace spqr.encoding.polynomial.Poly.mult_xdiff_assign_trailing_loop

@[step]
theorem loop_spec
    (difference : GF16) (iter : core.ops.range.Range Usize) (v : alloc.vec.Vec GF16)
    (h_start_ge : 1 ≤ iter.start.val)
    (h_end_eq : iter.end.val = v.val.length)
    (h_le : iter.start.val ≤ iter.end.val) :
    mult_xdiff_assign_trailing_loop iter v difference ⦃ result =>
      result.val.length = v.val.length ∧
      (∀ (j : Nat),
        iter.start.val ≤ j + 1 ∧  j + 1 < iter.end.val →
        ∀ (hj : j < result.val.length),
          (result.val.get ⟨j, hj⟩).toGF216 =
            (v.val[j]!).toGF216 - (v.val[j + 1]!).toGF216 * difference.toGF216) ∧
      (∀ (j : Nat), ¬(iter.start.val ≤ j + 1 ∧ j + 1 < iter.end.val) →
        result.val[j]? = v.val[j]?) ⦄ := by
  unfold mult_xdiff_assign_trailing_loop
  apply loop.spec_decr_nat
    (measure := fun (p : core.ops.range.Range Usize × alloc.vec.Vec GF16) =>
                  p.1.end.val - p.1.start.val)
    (inv := fun (p : core.ops.range.Range Usize × alloc.vec.Vec GF16) =>
        p.1.end = iter.end ∧
        iter.start.val ≤ p.1.start.val ∧
        p.1.start.val ≤ iter.end.val ∧
        p.2.val.length = v.val.length ∧
        (∀ (j : Nat), iter.start.val ≤ j + 1 ∧  j + 1 < p.1.start.val →
          ∀ (hj : j < p.2.val.length),
          (p.2.val.get ⟨j, hj⟩).toGF216 =
            (v.val[j]!).toGF216 - (v.val[j + 1]!).toGF216 * difference.toGF216) ∧
        (∀ (j : Nat),
          ¬(iter.start.val ≤ j + 1 ∧ j + 1 < p.1.start.val) →
          p.2.val[j]? = v.val[j]?))
  · rintro ⟨iter', v'⟩ ⟨h_end', h_ge', h_le', h_len', h_processed, h_unchanged⟩
    step*
    split
    · grind
    · grind
  · grind

end spqr.encoding.polynomial.Poly.mult_xdiff_assign_trailing_loop

/-! # Spec theorem for `mult_xdiff_assign_trailing`

Let `v = [c₀, c₁, …, cₙ₋₁]` be a polynomial over `GF(2¹⁶)` in ascending degree order, and let
`difference : GF16`. The function `Poly.mult_xdiff_assign_trailing(start, difference)` updates
`self[start..]` in place by multiplying the trailing sub-polynomial with `(x − difference)`.

Since `GF(2¹⁶)` has characteristic 2, subtraction equals addition, so
`(x − difference) = (x + difference)`. The multiplication follows:

`v[i − 1] -= v[i] * difference` for `i ∈ start..l`

where `l = self.coefficients.len()`. This corresponds to
`(x − d)p(x) = x · p(x) − d · p(x)`: the `x · p(x)` term shifts coefficients, while
`−d · p(x)` updates position `i − 1`. The loop performs this propagation in place.

**Source**: `spqr/src/encoding/polynomial.rs`-/


namespace spqr.encoding.polynomial.Poly


open Polynomial

/-- **Spec theorem for `encoding.polynomial.Poly.mult_xdiff_assign_trailing`**:

• The function never panics for any `Poly`, `start`, and `difference` satisfying
`1 ≤ start` and `start ≤ self.coefficients.length`.
• The coefficient vector length is preserved:
`result.coefficients.length = self.coefficients.length`.
• For updated positions (`start ≤ j + 1 ∧ j + 1 < l`):
`result.toGF216.coefficients[j] =
  self.toGF216.coefficients[j] − self.toGF216.coefficients[j+1] * difference.toGF216`
• All other coefficients remain unchanged:
`result.coefficients[j]? = self.coefficients[j]?`.
• Polynomial identity:
`result.toGF216Poly =
      self.toGF216Poly −
      C(difference.toGF216) · X^(start − 1) ·
      listToGF216Poly(self.coefficients.val.drop start)`
This captures the in-place recurrence `v[i−1] −= v[i] * difference` for `i ∈ start..l`: the trailing
 sub-polynomial is scaled by `difference`, shifted down by one degree, and subtracted from
 the original polynomial. Since `GF(2¹⁶)` has characteristic 2, subtraction equals addition. -/
@[step]
theorem mult_xdiff_assign_trailing_spec
    (self : Poly) (start : Usize) (difference : GF16)
    (h_start_pos : 1 ≤ start.val)
    (h_start_le : start.val ≤ self.coefficients.val.length) :
    mult_xdiff_assign_trailing self start difference
      ⦃ (result : Poly) =>
      result.coefficients.val.length = self.coefficients.val.length ∧
      (∀ (j : Nat),
        start.val ≤ j + 1 ∧  j + 1 < self.coefficients.val.length →
        ∀ (hj : j < result.coefficients.val.length),
          (result.coefficients.val.get ⟨j, hj⟩).toGF216 =
            (self.coefficients.val[j]!).toGF216 -
            (self.coefficients.val[j + 1]!).toGF216 * difference.toGF216) ∧
      (∀ (j : Nat),
        ¬(start.val ≤ j + 1 ∧ j + 1 < self.coefficients.val.length) →
        result.coefficients.val[j]? = self.coefficients.val[j]?) ∧
      result.toGF216Poly = self.toGF216Poly -
        C (difference.toGF216) * X ^ (start.val - 1) *
          listToGF216Poly (self.coefficients.val.drop start.val) ⦄ := by
  unfold mult_xdiff_assign_trailing
  step*
  simp_all only [alloc.vec.Vec.len, Usize.ofNatCore_val_eq, List.get_eq_getElem, getElem!_pos,
    not_and, not_lt, implies_true, toGF216Poly, true_and]
  apply mult_xdiff_poly_identity
  all_goals grind

end spqr.encoding.polynomial.Poly
