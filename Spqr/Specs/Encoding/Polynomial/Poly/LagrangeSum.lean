/-
Copyright 2026 The Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE-APACHE.
Authors: Hoang Le Truong
-/
import Spqr.Specs.Encoding.Polynomial.Poly.Zero
import Spqr.Specs.Encoding.Polynomial.Poly.AddAssign
import Spqr.Specs.Encoding.Polynomial.Poly.MultAssign
import Spqr.Specs.Encoding.Polynomial.Poly.Clone
import Spqr.Specs.Aeneas.RangeIteratorNext

/-!
# Spec theorem for `Poly::lagrange_sum`: loop body 0

Given points `pts` and parallel basis polynomials `polys`, it builds the GF(2¹⁶)[X] combination
`out = Σ_i pts[i].y · polys[i]`, one term per loop step.

**Source**: spqr/src/encoding/polynomial.rs -/

open Aeneas Aeneas.Std Result Polynomial

namespace spqr.encoding.polynomial.Poly.lagrange_sum_loop

/-- **Spec theorem for `encoding.polynomial.Poly.lagrange_sum_loop.body`**:

One step of the accumulation loop.  Reads the next index `i` from the range iterator and either
stops or extends the partial sum.

• **done** (iterator exhausted): `out` is returned unchanged and `¬ (iter.start < iter.end)`.
• **cont** (index `i = iter.start`): advances the iterator by one and updates the accumulator with
  one Lagrange term in `GF216[X]`:
    `out1.toGF216Poly = out.toGF216Poly + C (pts[i].y.toGF216) * polys[i].toGF216Poly`.

Preconditions keep the index reads in bounds and the scalar multiply / addition from overflowing. -/
@[step]
theorem body_spec
    (pts : Slice Pt) (polys : Slice Poly) (iter : core.ops.range.Range Usize) (out : Poly)
    (h_end_le_pts : iter.end ≤ pts.length)
    (h_end_le_polys : iter.end ≤ polys.length)
    (h_poly_len : ∀ (_ : iter.start < iter.end), (polys[iter.start]!).degree + 2 ≤ Usize.max)
    (h_max_len : ∀ (_ : iter.start < iter.end),
        max out.degree (polys[iter.start]!).degree < Usize.max) :
    body pts polys iter out ⦃ cf =>
      match cf with
      | ControlFlow.done out' => out' = out ∧ ¬ (iter.start < iter.end)
      | ControlFlow.cont (iter1, out1) =>
          iter.start < iter.end ∧
          iter1.start = iter.start.val + 1 ∧
          iter1.end = iter.end ∧
          out1.degree = max out.degree (polys[iter.start]!).degree ∧
          out1.toGF216Poly = out.toGF216Poly +
            C ((pts[iter.start]!).y.toGF216) * (polys[iter.start]!).toGF216Poly ⦄ := by
  unfold body
  obtain ⟨⟨opt, iter1'⟩, hnext, h_none, h_some⟩ :=
    WP.spec_imp_exists (core.iter.range.IteratorRange.next_Usize_spec' iter)
  rw [hnext]
  simp only [bind_tc_ok]
  by_cases h_lt : iter.start < iter.end.val
  · step*
    all_goals grind
  · grind

/-! # Spec theorem for `Poly::lagrange_sum`: loop 0

After all iterations the accumulator holds the full Lagrange sum
`∑ j ∈ Finset.range pts.len(), C (pts[j].y.toGF216) * polys[j].toGF216Poly` in `GF216[X]`.

The loop invariant says `out` holds the partial sum over `Finset.range iter.start`; each step
adds one term (`Finset.sum_range_succ`), keeping the range end fixed and the position within
bounds, with a uniform length bound `M` discharging the `add_assign` precondition.

**Source**: spqr/src/encoding/polynomial.rs -/
@[step]
theorem loop_spec
    (pts : Slice Pt) (polys : Slice Poly) (iter : core.ops.range.Range Usize) (out : Poly)
    (h_end_le_pts : iter.end ≤ pts.length)
    (h_end_le_polys : iter.end ≤ polys.length)
    (h_out : out.degree < Usize.max)
    (h_polys : ∀ i < iter.end, (polys.val[i]!).degree + 2 ≤ Usize.max)
    (h_sum : out.toGF216Poly = ∑ j ∈ Finset.range iter.start,
      C ((pts[j]!).y.toGF216) * (polys[j]!).toGF216Poly) :
    lagrange_sum_loop iter pts polys out ⦃ (result : Poly) =>
      result.toGF216Poly = ∑ j ∈ Finset.range (max iter.start iter.end),
        C ((pts[j]!).y.toGF216) * (polys[j]!).toGF216Poly ⦄ := by
  unfold lagrange_sum_loop
  apply loop.spec_decr_nat
    (measure := fun (p : core.ops.range.Range Usize × Poly) =>
                  p.1.end - p.1.start)
    (inv := fun (p : core.ops.range.Range Usize × Poly) =>
        p.1.end = iter.end ∧
        iter.start ≤ p.1.start ∧
        p.1.start ≤ max iter.start iter.end ∧
        p.2.degree < Usize.max ∧
        p.2.toGF216Poly = ∑ j ∈ Finset.range p.1.start,
          C ((pts[j]!).y.toGF216) * (polys.val[j]!).toGF216Poly)
  · rintro ⟨iter', out'⟩
      ⟨h_end', h_start_le', h_bound', h_out_M', h_sum'⟩
    simp only [] at h_end' h_start_le' h_bound' h_out_M' h_sum' ⊢
    have h_poly_len' : ∀ (_hi : iter'.start < iter'.end),
        (polys.val[iter'.start]!).degree + 2 ≤ Usize.max := by grind
    have h_max_len' : ∀ (_hi : iter'.start < iter'.end.val),
        max out'.degree (polys.val[iter'.start]!).degree < Usize.max := by grind
    have h_body := body_spec pts polys iter' out'
      (by grind) (by grind) h_poly_len' h_max_len'
    apply WP.spec_mono h_body
    intro cf h_cf
    match cf with
    | ControlFlow.done result => grind
    | ControlFlow.cont (iter1, out1) =>
      simp only [] at h_cf ⊢
      obtain ⟨h_lt, h_start1, h_end1, h_len1, h_out1⟩ := h_cf
      constructor
      · refine ⟨by grind , by grind, by grind, ?_, ?_⟩
        · rw [h_len1]
          apply h_max_len'
          grind
        · rw [h_out1, h_sum', h_start1]
          simp [Finset.sum_range_succ]
      · grind
  · grind

end spqr.encoding.polynomial.Poly.lagrange_sum_loop

/-!
# Spec theorem for `spqr::encoding::polynomial::{spqr::encoding::polynomial::Poly}::lagrange_sum`

The function allocates the zero accumulator `out := Poly::zero(pts.len())` and delegates to
`lagrange_sum_loop` over `0..pts.len()`.  Composing `Zero.zero_spec` (`out = 0`, empty sum
invariant at `iter.start = 0`) with `loop_spec` gives
  `result.toGF216Poly = ∑ j ∈ Finset.range pts.length, C (pts[j].y.toGF216) * polys[j].toGF216Poly`
in `GF216[X]`, the combination used by `lagrange_polynomial_from_complete_points`.

Since every `polys[i]` for `i < pts.len()` is read, the spec requires `polys` at least as long
as `pts`, with the per-polynomial length bounds for `mult_assign` / `add_assign`.

**Source**: spqr/src/encoding/polynomial.rs -/

namespace spqr.encoding.polynomial.Poly

/-- **Spec theorem for `spqr.encoding.polynomial.Poly.lagrange_sum`**:

Given points `pts` and parallel basis polynomials `polys` (at least as long as `pts`, with the
per-polynomial length bound for the scalar multiply), the function returns `result` with
  `result.toGF216Poly = ∑ j ∈ Finset.range pts.length, C (pts[j].y.toGF216) * polys[j].toGF216Poly`
in `GF216[X]`, where `C` is the constant-polynomial embedding and `toGF216Poly` reads the
coefficient vector as a polynomial (addition is coefficient-wise XOR in characteristic 2). -/
@[step]
theorem lagrange_sum_spec
    (pts : Slice Pt)
    (polys : Slice Poly)
    (h_len_le : pts.length ≤ polys.length)
    (h_polys : ∀ i < pts.length, (polys[i]!).degree + 2 ≤ Usize.max) :
    lagrange_sum pts polys ⦃ (result : Poly) =>
      result.toGF216Poly =
        ∑ j ∈ Finset.range pts.length, C ((pts[j]!).y.toGF216) * (polys[j]!).toGF216Poly ⦄ := by
  unfold lagrange_sum
  step with zero_spec (Slice.len pts) as ⟨out, h_out_len, h_out_zero⟩
  have h_end_le_pts : (Slice.len pts).val ≤ pts.val.length := by simp
  have h_end_le_polys : (Slice.len pts).val ≤ polys.val.length := by grind
  have h_out : out.coefficients.val.length < Usize.max := by grind
  have h_polys' : ∀ i < (Slice.len pts), (polys[i]!).degree + 2 ≤ Usize.max := by grind
  have h_sum_init :
      out.toGF216Poly =
        ∑ j ∈ Finset.range (0#usize), C ((pts[j]!).y.toGF216) * (polys[j]!).toGF216Poly := by
    rw [h_out_zero]
    simp
  apply WP.spec_mono (lagrange_sum_loop.loop_spec pts polys
    { start := 0#usize, «end» := Slice.len pts } out
    h_end_le_pts h_end_le_polys h_out h_polys' h_sum_init)
  intro result h_result
  simp only [UScalar.ofNatCore_val_eq, Usize.ofNatCore_val_eq, zero_le, sup_of_le_right,
    Slice.getElem!_Nat_eq, List.getElem!_eq_getElem?_getD] at h_result
  exact h_result

end spqr.encoding.polynomial.Poly
