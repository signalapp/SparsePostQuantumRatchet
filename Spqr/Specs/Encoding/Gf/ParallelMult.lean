/-
Copyright 2026 The Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Hoang Le Truong
-/
import Spqr.Code.Funs
import Spqr.Math.Gf16.Field
import Spqr.Specs.Encoding.Gf.Mul2U16
import Spqr.Specs.Encoding.Gf.GF16.MulAssign
/-! # Spec theorem for `spqr::encoding::gf::parallel_mult`

Processes the slice in two phases: a pair loop (`parallel_mult_loop`) using `mul2_u16` in
strides of two, then a `MulAssign` fix-up for the trailing element if length is odd.

**Source**: spqr/src/encoding/gf.rs (lines 566:0-579:1)
-/


open Aeneas Aeneas.Std

deriving instance Inhabited for spqr.encoding.gf.GF16

namespace spqr.encoding.gf


/-- **Spec theorem for `encoding.gf.parallel_mult_loop.body`**:

Either `done` with unchanged state, or `cont` advancing `i` by 2 with the two written entries
equal to `a · into[i]`, `a · into[i+1]` in GF(2¹⁶), and all other slice positions unchanged
(frame condition). -/
@[step]
theorem parallel_mult_loop_body_spec
    (a : GF16) (into : Slice GF16) (i : Usize)
    (hi : i.val + 2 ≤ Usize.max) :
    parallel_mult_loop.body a into i ⦃
      (cf : ControlFlow (Slice GF16 × Usize) (GF16 × Slice GF16 × Usize)) =>
      match cf with
      | ControlFlow.done (a', into', i') =>
          a' = a ∧ into' = into ∧ i' = i ∧ into.length < i.val + 2
      | ControlFlow.cont (s, i') =>
          i.val + 2 ≤ into.length ∧
          i'.val = i.val + 2 ∧
          s.length = into.length ∧
          s.val[i.val]!.toGF216 = a.toGF216 * into.val[i.val]!.toGF216 ∧
          s.val[i.val + 1]!.toGF216 = a.toGF216 * into.val[i.val + 1]!.toGF216 ∧
          ∀ j ≠ i.val,  j ≠ i.val + 1 → s.val[j]! = into.val[j]! ⦄ := by
  unfold parallel_mult_loop.body
  step*
  simp_all[GF16.toGF216]
  grind

/-! # Spec theorem for `spqr::encoding::gf::parallel_mult` — loop 0

The `while i + 2 <= into.len()` loop processes the slice in strides of two via `mul2_u16`,
advancing `i += 2` until `i + 2 > into.len()`. Termination uses measure `into.length − i.val`.

Requires `into.length + 2 ≤ Usize.max` and `i.val ≤ into.length`. Returns `(a, into', i')` with:
preserved multiplier and length, `into.length < i'.val + 2`, `i.val ≤ i'.val ≤ into'.length`,
elements in `[i.val, i'.val)` multiplied by `a` in GF(2¹⁶), and elements outside unchanged. -/
@[step]
theorem parallel_mult_loop_spec
    (a : GF16) (into : Slice GF16) (i : Usize)
    (hlen : into.length + 2 ≤ Usize.max)
    (hi : i.val ≤ into.length) :
    parallel_mult_loop a into i ⦃ (a', into', i') =>
      a' = a ∧
      into'.length = into.length ∧
      into.length < i'.val + 2 ∧
      i.val ≤ i'.val ∧
      i'.val ≤ into'.length ∧
      (∀ j < i'.val, i.val ≤ j → into'.val[j]!.toGF216 = a.toGF216 * into.val[j]!.toGF216) ∧
      (∀ j < into'.length, i'.val ≤ j → into'.val[j]! = into.val[j]!) ∧
      (∀ j < i.val, into'.val[j]! = into.val[j]!) ⦄ := by
  unfold parallel_mult_loop
  apply loop.spec_decr_nat
    (measure := fun (p : Slice GF16 × Usize) => p.1.length - p.2.val)
    (inv := fun (p : Slice GF16 × Usize) =>
      p.1.length = into.length ∧ i.val ≤ p.2.val ∧ p.2.val ≤ p.1.length ∧
      (∀ j < p.2.val, i.val ≤ j →  p.1.val[j]!.toGF216 = a.toGF216 * into.val[j]!.toGF216) ∧
      (∀ j < p.1.length, p.2.val ≤ j →
        p.1.val[j]! = into.val[j]!) ∧ (∀ j < i.val, p.1.val[j]! = into.val[j]!))
  · intro _ _
    step*
    simp_all
    grind
  · simp_all

/-- **Spec theorem for `encoding.gf.parallel_mult`**:

Requires `into.length + 2 ≤ Usize.max`. Returns a slice of the same length where every element
equals `a · into[j]` in GF(2¹⁶). -/
@[step]
theorem parallel_mult_spec
    (a : GF16) (into : Slice GF16)
    (hlen : into.length + 2 ≤ Usize.max) :
    parallel_mult a into ⦃ (result : Slice GF16) =>
      result.length = into.length ∧
      ∀ j < result.length, result.val[j]!.toGF216 = a.toGF216 * (into.val[j]!).toGF216 ⦄ := by
  unfold parallel_mult
  step*
  simp_all
  grind

end spqr.encoding.gf
