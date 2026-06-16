/-
Copyright 2026 The Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE-APACHE.
Authors: Hoang Le Truong
-/
import Spqr.Math.List
import Spqr.Math.Gf16.Field
import Spqr.Specs.Encoding.Polynomial.Pt.Deserialize
import Spqr.Specs.Aeneas.RangeIteratorNext


/-! # Spec theorem for `Poly::deserialize`: loop body 0

One step of the coefficient deserialization loop. Calls `next` on the range iterator and either:

  1. **Done**: iterator exhausted, `coefficients` returned unchanged.
  2. **Continue**: reads two bytes at `serialized[2*i]` and `serialized[2*i+1]`, decodes them
     as a big-endian `u16`, wraps as `GF16`, and pushes onto `coefficients`.

Loop invariant: `coefficients.len() == i`, with each coefficient satisfying
  `coefficients[k].value.val = serialized[2*k].val * 256 + serialized[2*k+1].val`
for all `k < iter.start`. -/

open Aeneas Aeneas.Std spqr.encoding.gf

namespace spqr.encoding.polynomial.Poly.deserialize_loop

@[step]
private lemma GF16_new_value_spec (value : U16) :
    GF16.new value ⦃ (result : GF16) =>
      result.value = value ⦄ := by
  simp [GF16.new]

@[step]
theorem body_spec
    (serialized : Slice Std.U8)
    (iter : core.ops.range.Range Usize)
    (coefficients : alloc.vec.Vec GF16)
    (h_end_le : 2 * iter.end ≤ serialized.length)
    (h_coeff_overflow : coefficients.length + 1 ≤ Usize.max) :
    body serialized iter coefficients ⦃ (cf : ControlFlow (core.ops.range.Range Usize ×
    alloc.vec.Vec GF16) (alloc.vec.Vec GF16)) =>
      match cf with
      | ControlFlow.done coefficients' =>
          coefficients' = coefficients ∧ ¬(iter.start.val < iter.end.val)
      | ControlFlow.cont (iter1, coefficients1) =>
          iter.start < iter.end ∧
          iter1.start = iter.start.val + 1 ∧
          iter1.end = iter.end ∧
          ∃ (g : GF16),
            coefficients1 = coefficients ++ [g] ∧
            g.value = 256 * (serialized[2 * iter.start.val]!).val  +
              (serialized[2 * iter.start.val + 1]!).val ⦄ := by
  unfold body
  obtain ⟨opt, iter1', hnext, h_none, h_some⟩ := core.iter.range.IteratorRange.next_Usize_spec iter
  rw [hnext]
  simp only [bind_tc_ok]
  by_cases h_lt : iter.start < iter.end
  · obtain ⟨h_opt_eq, h_start1, h_end1⟩ := h_some h_lt
    rw [h_opt_eq]
    have h_2i_lt : 2 * iter.start < serialized.length := by grind
    have h_2i1_lt : 2 * iter.start + 1 < serialized.length := by grind
    step*
    exact ⟨h_lt, h_start1, h_end1, g, coefficients1_post, by
      simp_all [Array.make, Nat.mul_comm]⟩
  · grind

end spqr.encoding.polynomial.Poly.deserialize_loop

/-!
# Spec theorem for `Poly::deserialize`: loop 0

The full deserialization loop that drives `deserialize_loop.body` to completion. Each iteration
reads a byte pair from `serialized`, decodes it as a big-endian `u16`, wraps it as `GF16`,
and appends it to the coefficient vector.

**Loop invariant** (after processing up to `iter'`):
  * `coefficients'.val.length = iter'.start.val`
  * `iter'.end = iter.end`
  * For every `j < iter'.start.val`:
(coefficients'.val[j]!).value.val = (serialized.val[2*j]!).val * 256 + (serialized.val[2*j+1]!).val`

At termination, the coefficient vector contains the complete deserialization of all byte pairs.
The proof lifts the body spec via `loop.spec_decr_nat` with measure
`iter'.end.val − iter'.start.val`. -/


namespace spqr.encoding.polynomial.Poly.deserialize_loop

@[step]
theorem loop_spec
    (serialized : Slice U8)
    (iter : core.ops.range.Range Usize)
    (coefficients : alloc.vec.Vec GF16)
    (h_end_le : 2 * iter.end ≤ serialized.length)
    (h_coeff_len : coefficients.length = iter.start)
    (h_start_le : iter.start ≤ iter.end)
    (h_overflow : iter.end + 1 ≤ Usize.max)
    (h_pre : ∀ j < iter.start.val,
      (coefficients[j]!).value.val = 256 * serialized[2 * j]! + serialized[2 * j + 1]!) :
    deserialize_loop iter serialized coefficients ⦃ (result : alloc.vec.Vec GF16) =>
      result.length = iter.end ∧
      ∀ j < iter.end.val,
        result[j]!.value.val = 256 * serialized[2 * j]! + serialized[2 * j + 1]! ⦄ := by
  unfold deserialize_loop
  apply loop.spec_decr_nat
    (measure := fun (p : core.ops.range.Range Usize × alloc.vec.Vec GF16) => p.1.end - p.1.start)
    (inv := fun (p : core.ops.range.Range Usize × alloc.vec.Vec GF16) =>
        let iter' := p.1
        let coefficients' := p.2
        iter'.end = iter.end ∧
        iter'.start ≤ iter'.end ∧
        coefficients'.length = iter'.start ∧
        (∀ j < iter'.start.val,
          coefficients'[j]!.value.val = 256 * serialized[2 * j]! + serialized[2 * j + 1]!))
  · rintro ⟨iter', coefficients'⟩ ⟨h_end', h_start_le', h_coeff_len', h_pre'⟩
    have h_body := body_spec serialized iter' coefficients' (by grind) (by grind)
    apply WP.spec_mono h_body
    grind
  · grind

end spqr.encoding.polynomial.Poly.deserialize_loop

/-! # Spec theorem for `spqr::encoding::polynomial::{Poly}::deserialize`

Deserializes a byte slice into a polynomial over GF(2¹⁶) by decoding consecutive byte pairs
as big-endian `u16` values wrapped as `GF16` elements.

Three stages:
  1. **Validation**: rejects empty or odd-length input.
  2. **Allocation**: pre-allocates a coefficient vector of capacity `serialized.len() / 2`.
  3. **Deserialization loop**: decodes each byte pair and appends the `GF16` coefficient.

This is the inverse of `Poly::serialize`. -/


namespace spqr.encoding.polynomial.Poly

/-- **Spec theorem for `encoding.polynomial.Poly.deserialize`**:

Deserializes a byte slice into a `Poly` over GF(2¹⁶).

Rejects empty or odd-length input. Otherwise, drives the deserialization loop to produce a
coefficient vector satisfying:
  * `poly.degree = serialized.length / 2`
  * For every `j < serialized.length / 2`:
      `(poly.coefficients.val[j]!).value.val = 256 * serialized[2*j]! + serialized[2*j+1]!`

Preconditions: input is non-empty with even length, and operations do not overflow `Usize`. -/
@[step]
theorem deserialize_spec
    (serialized : Slice U8)
    (h_nonempty : serialized.length ≠ 0)
    (h_even : serialized.length % 2 = 0)
    (h_overflow : serialized.length / 2 + 1 ≤ Usize.max) :
    deserialize serialized ⦃ (result : core.result.Result Poly PolynomialError) =>
      match result with
      | core.result.Result.Ok poly =>
          poly.degree = serialized.length / 2 ∧
          ∀ j < serialized.length / 2,
            poly.coefficients[j]!.value.val = 256 * serialized[2 * j]! + serialized[2 * j + 1]!
      | core.result.Result.Err _ => False ⦄ := by
  unfold Poly.deserialize degree
  step*
  simp [alloc.vec.Vec.with_capacity]

end spqr.encoding.polynomial.Poly
