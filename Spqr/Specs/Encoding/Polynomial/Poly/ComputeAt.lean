/-
Copyright 2026 The Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE-APACHE.
Authors: Hoang Le Truong
-/
import Spqr.Math.Poly.Eval.DotProduct
import Spqr.Math.Poly.Eval.PowerVector
import Spqr.Specs.Encoding.Gf.GF16.Mul
import Spqr.Specs.Encoding.Gf.GF16.AddAssign
import Spqr.Specs.Aeneas.RangeIteratorNext

/-! # Spec theorem for `Poly::compute_at`: loop body 0

One step of the power-vector construction loop. Calls `next` on the range iterator and either:

  1. **Done** (`none`): iterator exhausted, `xs` returned unchanged.
  2. **Continue** (`some i`): computes `g = xs[i/2] * xs[i/2 + i%2]` in GF(2¹⁶) and appends `g`
     to `xs`.

Maintains the invariant `xs[j].toGF216 = x.toGF216 ^ j` for all `j < xs.length`, using the
identity `x^i = x^(i/2) · x^(i/2 + i%2)`.

**Source**: spqr/src/encoding/polynomial.rs -/

open Aeneas Aeneas.Std spqr.encoding.gf

namespace spqr.encoding.polynomial.Poly.compute_at_loop0

@[step]
theorem body_spec
    (iter : core.ops.range.Range Usize)
    (xs : alloc.vec.Vec GF16)
    (h_ge2 : 2 ≤ iter.start.val)
    (h_inv : iter.start = xs.length)
    (h_len : xs.length + 1 ≤ Usize.max) :
    body iter xs ⦃ cf =>
      match cf with
      | ControlFlow.done xs' =>
          xs' = xs ∧ ¬(iter.start < iter.end)
      | ControlFlow.cont (iter1, xs1) =>
          iter.start < iter.end ∧
          iter1.start = iter.start.val + 1 ∧
          iter1.end = iter.end ∧
          ∃ (g : GF16), xs1 = xs ++ [g] ∧
            g.toGF216 =
              (xs[xs.length / 2]!).toGF216 * (xs[xs.length / 2 + xs.length % 2]!).toGF216 ⦄ := by
  unfold body
  obtain ⟨⟨opt, iter1'⟩, hnext, h_none, h_some⟩ :=
    WP.spec_imp_exists (core.iter.range.IteratorRange.next_Usize_spec' iter)
  rw [hnext]
  simp only [bind_tc_ok]
  by_cases h_lt : iter.start < iter.end
  · step*
    grind
  · grind


/-! # Spec theorem for `Poly::compute_at`: loop 0

Iterates the range `2..n`, extending `xs` by one element per step until exhausted.
Each step computes `xs[i] = xs[i/2] * xs[i/2 + i%2]`.

**Loop invariant**: `xs.val.length = iter.start.val` and
`∀ j < xs.val.length, (xs[j]!).toGF216 = x.toGF216 ^ j`.

**Source**: spqr/src/encoding/polynomial.rs -/

@[step]
theorem loop_spec
    (x : GF16)
    (iter : core.ops.range.Range Usize)
    (xs : alloc.vec.Vec GF16)
    (h_ge2 : 2 ≤ iter.start.val)
    (h_inv : iter.start = xs.length)
    (h_pow : ∀ j < xs.length, (xs[j]!).toGF216 = x.toGF216 ^ j)
    (h_len : max xs.length iter.end + 1 ≤ Usize.max) :
    compute_at_loop0 iter xs ⦃ (result : alloc.vec.Vec GF16) =>
      (∀ j < result.length, (result[j]!).toGF216 = x.toGF216 ^ j) ∧
      result.length = max xs.length iter.end ⦄ := by
  unfold compute_at_loop0
  apply loop.spec_decr_nat
    (measure := fun (p : core.ops.range.Range Usize × alloc.vec.Vec GF16) => p.1.end - p.1.start)
    (inv := fun (p : core.ops.range.Range Usize ×
                     alloc.vec.Vec GF16) =>
        p.1.end = iter.end ∧
        2 ≤ p.1.start.val ∧
        p.1.start = p.2.length ∧
        iter.start ≤ p.1.start ∧
        p.1.start ≤ max iter.start iter.end ∧
        p.2.length + 1 ≤ Usize.max ∧
        (∀ j < p.2.length, (p.2[j]!).toGF216 = x.toGF216 ^ j))
  · rintro ⟨iter', xs'⟩ ⟨h_end', h_ge2', h_inv', h_start_le', h_bound', h_len', h_pow'⟩
    simp only  at h_end' h_ge2' h_inv' h_start_le' h_bound' h_len' h_pow' ⊢
    have h_body := body_spec iter' xs' h_ge2' h_inv' h_len'
    apply WP.spec_mono h_body
    intro cf h_cf
    match cf with
    | ControlFlow.done result => grind
    | ControlFlow.cont (iter1, xs1) => grind  [power_invariant_step]
  · grind

end spqr.encoding.polynomial.Poly.compute_at_loop0

/-! # Spec theorem for `Poly::compute_at`: loop body 1

One step of the accumulation loop. Calls `next` on the range iterator and either:

  1. **Done** (`none`): iterator exhausted, accumulator `out` returned unchanged.
  2. **Continue** (`some i`): computes `out += v[i] * xs[i]` in GF(2¹⁶).

Maintains the invariant
`out.toGF216 = Σ_{j < iter.start.val} v[j].toGF216 * xs[j].toGF216`.

**Source**: spqr/src/encoding/polynomial.rs -/

namespace spqr.encoding.polynomial.Poly.compute_at_loop1

@[step]
theorem body_spec
    (v : alloc.vec.Vec GF16)
    (xs : alloc.vec.Vec GF16)
    (iter : core.ops.range.Range Usize)
    (out : GF16)
    (h_v_len : iter.end ≤ v.length)
    (h_xs_len : iter.end ≤ xs.length) :
    body v xs iter out ⦃ (cf : ControlFlow (core.ops.range.Range Usize × GF16) GF16) =>
      match cf with
      | ControlFlow.done out' => out' = out ∧ ¬(iter.start < iter.end)
      | ControlFlow.cont (iter1, out1) =>
          iter.start < iter.end ∧
          iter1.start = iter.start.val + 1 ∧
          iter1.end = iter.end ∧
          out1.toGF216 = out.toGF216 + (v[iter.start]!).toGF216 * (xs[iter.start]!).toGF216 ⦄ := by
  unfold body
  obtain ⟨⟨opt, iter1'⟩, hnext, h_none, h_some⟩ :=
    WP.spec_imp_exists (core.iter.range.IteratorRange.next_Usize_spec' iter)
  rw [hnext]
  simp only [bind_tc_ok]
  by_cases h_lt : iter.start < iter.end
  · step*
    grind
  · grind

/-! # Spec theorem for `Poly::compute_at`: loop 1

Iterates the range `0..n`, accumulating one coefficient–power product per step.
After all iterations:
  `out.toGF216 = ∑ j ∈ Finset.range n, v[j].toGF216 * xs[j].toGF216`

**Loop invariant**: the accumulator holds the partial sum of the first `iter.start.val`
coefficient–power products, using `Finset.sum_range_succ` at each step.

**Source**: spqr/src/encoding/polynomial.rs -/

@[step]
theorem loop_spec
    (v : alloc.vec.Vec GF16)
    (xs : alloc.vec.Vec GF16)
    (iter : core.ops.range.Range Usize)
    (out : GF16)
    (h_v_len : iter.end ≤ v.length)
    (h_xs_len : iter.end ≤ xs.length)
    (h_sum : out.toGF216 = ∑ j ∈ Finset.range iter.start, (v[j]!).toGF216 * (xs[j]!).toGF216) :
    compute_at_loop1 iter v xs out ⦃ (result : GF16) =>
      result.toGF216 = ∑ j ∈ Finset.range (max iter.start iter.end),
      (v[j]!).toGF216 * (xs[j]!).toGF216 ⦄ := by
  unfold compute_at_loop1
  apply loop.spec_decr_nat
    (measure := fun (p : core.ops.range.Range Usize × GF16) => p.1.end - p.1.start)
    (inv := fun (p : core.ops.range.Range Usize × GF16) =>
        p.1.end = iter.end ∧
        iter.start ≤ p.1.start ∧
        p.1.start ≤ max iter.start iter.end ∧
        p.2.toGF216 = ∑ j ∈ Finset.range p.1.start,
          (v[j]!).toGF216 * (xs.val[j]!).toGF216)
  · rintro ⟨iter', out'⟩ ⟨h_end', h_start_le', h_bound', h_sum'⟩
    simp only at h_end' h_start_le' h_bound' h_sum' ⊢
    have h_body := body_spec v xs iter' out'
      (by rw [h_end']; exact h_v_len) (by rw [h_end']; exact h_xs_len)
    apply WP.spec_mono h_body
    intro cf h_cf
    match cf with
    | ControlFlow.done result => grind
    | ControlFlow.cont (iter1, out1) =>
      simp only at h_cf ⊢
      obtain ⟨h_lt, h_start1, h_end1, h_out1⟩ := h_cf
      constructor
      · refine ⟨by rw [h_end1, h_end'], by grind, by grind, ?_⟩
        rw [h_out1, h_sum', h_start1]
        apply (Finset.sum_range_succ _ _).symm
      · grind
  · exact ⟨rfl, le_refl _, le_max_left _ _, h_sum⟩

end spqr.encoding.polynomial.Poly.compute_at_loop1

/-! # Spec theorem for `spqr::encoding::polynomial::{spqr::encoding::polynomial::Poly}::compute_at`

Evaluates a polynomial `self` at point `x` in GF(2¹⁶), computing
`p(x) = a₀ + a₁·x + a₂·x² + … + aₙ₋₁·xⁿ⁻¹`.

Two phases:
  1. **Power-vector construction** (loop 0): builds `xs` with `xs[j] = x^j` using
     `x^i = x^(i/2) · x^(i/2 + i%2)`.
  2. **Dot-product accumulation** (loop 1): computes `out = Σ coeff[j] · xs[j]`.

The final result satisfies `result.toGF216 = (self.toGF216Poly).eval (x.toGF216)`.

**Source**: spqr/src/encoding/polynomial.rs -/

namespace spqr.encoding.polynomial.Poly

/-- **Spec theorem for `encoding.polynomial.Poly.compute_at`**:

• Always succeeds when `self.coefficients.val.length + 1 ≤ Usize.max`.

• **Polynomial evaluation postcondition**:
    `result.toGF216 = self.evalAt x`
  i.e. the returned value equals the Mathlib polynomial evaluation
  `(self.toGF216Poly).eval (x.toGF216)` in `GF216 = GaloisField 2 16`. -/
@[step]
theorem compute_at_spec
    (self : Poly) (x : GF16)
    (h_len : self.degree + 1 ≤ Usize.max) :
    compute_at self x ⦃ (result : GF16) =>
      result.toGF216  = self.evalAt x ⦄ := by
  unfold compute_at
  step
  · grind [alloc.vec.Vec.with_capacity]
  step
  · grind [alloc.vec.Vec.with_capacity]
  have h_pow_init := initial_power_invariant x
  have h_xs2_val : xs2 = [GF16.ONE, x] := by
    have h_wc : (alloc.vec.Vec.with_capacity GF16
                    self.coefficients.len).val = [] := by
      simp [alloc.vec.Vec.with_capacity]
    rw [xs2_post, result_post, h_wc]; simp
  have h_xs2_len : xs2.length = 2 := by grind
  have h_xs2_pow : ∀ j < xs2.length, (xs2[j]!).toGF216 = x.toGF216 ^ j := by grind
  step with compute_at_loop0.loop_spec x { start := 2#usize, «end» := self.coefficients.len }
    xs2 (by scalar_tac) h_xs2_len.symm h_xs2_pow (by simp_all [degree]; grind)
    as ⟨xs3, h_xs3_pow, h_xs3_len⟩
  have h_xs3_ge : self.degree ≤ xs3.length := by
    have hle := h_xs3_len
    change self.coefficients.length ≤ xs3.length
    grind
  apply WP.spec_mono (compute_at_loop1.loop_spec self.coefficients xs3
    { start := 0#usize, «end» := self.coefficients.len }
    GF16.ZERO (by simp) h_xs3_ge (by simp [GF16.ZERO, GF16.toGF216, Nat.toGF216]))
  intro result h_result
  have h_max : max (0#usize).val (self.coefficients.len).val =
    self.coefficients.val.length := by simp
  rw [h_max] at h_result
  rw [h_result]
  exact dot_product_eq_eval x self.coefficients.val xs3.val h_xs3_pow h_xs3_ge

end spqr.encoding.polynomial.Poly
