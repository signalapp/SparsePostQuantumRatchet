/-
Copyright 2026 The Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE-APACHE.
Authors: Hoang Le Truong
-/
import SrcTranslated.Funs
import SrcTranslated.FunsExternal
import Spqr.Math.Gf16.Field
import Spqr.Specs.Encoding.Gf.GF16.Mul
import Spqr.Aux.Aeneas.StdNextStepUsize
import Spqr.Aux.Aeneas.StdNextCoreIterRangeStep

/-! # Spec theorem for `spqr::encoding::gf::{impl ops::Div for GF16}::div_impl`

In GF(2¹⁶) — the Galois field with 65 536 elements — multiplication is polynomial multiplication
modulo the irreducible polynomial POLY = x¹⁶ + x¹² + x³ + x + 1 (0x1100b).  Each field element is
represented as a polynomial of degree < 16 with coefficients in GF(2), stored as a 16-bit unsigned
integer; the `GF16` Rust type is the `u16` wrapper providing the field operations.

The extracted Lean body advances the `1..16` iterator by one step and, depending on whether the
iterator is exhausted, either returns the accumulated `out` (loop exit) or computes the new
`(square', out')` state for the next iteration:
  1. `out1 ← MulAssignGF16.mul_assign out square` — in-place
     `out *= square` delegating to the by-reference `MulAssign`
     instance, which itself delegates to the software (unaccelerated)
     carry-less multiplication `encoding.gf.unaccelerated.mul`.
  2. `square1 ← MulGF16GF16.mul square square` — by-value
     `square = square * square` delegating to the same software
     multiplication kernel.

**Source**: spqr/src/encoding/gf.rs (lines 451:8-454:9)
-/

open Aeneas Aeneas.Std Result core.ops.range

namespace spqr.encoding.gf.GF16

/-- **Spec theorem for `encoding.gf.GF16.div_impl_loop.body`**:

• The function always succeeds (no panic) for any `(iter, square, out)`, since the underlying
  iterator advance and `unaccelerated.mul` are total.
• On `done` the result accumulator coincides with the input `out`:
    `(result.value.val.toGF216 : GF216) = out.value.val.toGF216`.
• On `cont (_, square', out')` the new state satisfies the iterated-
  squaring recurrence
    `out'.toGF216 = out.toGF216 * square.toGF216`,
    `square'.toGF216 = square.toGF216 * square.toGF216`.

**Per-iteration postcondition for `encoding.gf.GF16.div_impl_loop.body`**:

One iteration of the iterated-squaring loop driving `GF16::div_impl`. Both branches are
characterised at the GF(2¹⁶) level via `Nat.toGF216 = BinaryPoly.toGF216 ∘ natToBinaryPoly`:

* **`done`** — the `1..16` iterator is exhausted; the returned
  accumulator is the unchanged `out`:
    `result.toGF216 = out.toGF216`.

* **`cont`** — the iterator yielded another index; the new state
  `(_, square', out')` satisfies the squaring recurrence (note that,
  unlike `const_div`, the `*=` precedes the squaring, so `out'`
  involves the *old* `square`):
    `out'.toGF216 = out.toGF216 * square.toGF216`,
    `square'.toGF216 = square.toGF216 * square.toGF216`.

**Source**: spqr/src/encoding/gf.rs (lines 451:8-454:9) -/
@[step]
theorem div_impl_loop_body_spec
    (iter : Range I32)
    (square out : GF16) :
    div_impl_loop.body iter square out ⦃ (cf : ControlFlow (Range I32 × GF16 × GF16) GF16) =>
      match cf with
      | ControlFlow.done result => result.toGF216 = out.toGF216
      | ControlFlow.cont (_, square', out') =>
          out'.toGF216 = out.toGF216 * square.toGF216 ∧
          square'.toGF216 = square.toGF216 * square.toGF216 ⦄ := by
  unfold div_impl_loop.body
  step*

/-- **spec theorem for `encoding.gf.GF16.div_impl_loop`**:

The iterated-squaring loop driving `GF16::div_impl`, specified at the GF(2¹⁶) level by the
closed-form iterated-squaring identity:

  `result.toGF216 = out.toGF216 * square.toGF216 ^ (2 ^ (iter.end.val - iter.start.val).toNat - 1)`.

Specialised to the entry point `(iter, square, out) = (1..16, other², self)` this collapses to `self
· (other²)^(2¹⁵ − 1) = self · other^(2¹⁶ − 2)`, i.e. division in GF(2¹⁶).
  If I use the 1[step]1, it takes 2 minutes and 21 seconds. While without the `[step]`,
  it takes about 3 seconds. -/
theorem div_impl_loop_spec (iter : Range I32) (square out : GF16)
    (h_le : iter.start.val ≤ iter.end.val) :
    div_impl_loop iter square out ⦃ (result : GF16) =>
      result.toGF216 = out.toGF216 *
        square.toGF216 ^ (2 ^ (iter.end.val - iter.start.val).toNat - 1) ⦄ := by
  unfold div_impl_loop
  apply loop.spec_decr_nat
    (measure := fun p : Range I32 × GF16 × GF16 => (p.1.end.val - p.1.start.val).toNat)
    (inv := fun p : Range I32 × GF16 × GF16 =>
      p.1.end = iter.end ∧
      iter.start.val ≤ p.1.start.val ∧
      p.1.start.val ≤ iter.end.val ∧
      p.2.1.toGF216 = square.toGF216 ^ (2 ^ (p.1.start.val - iter.start.val).toNat) ∧
      p.2.2.toGF216 = out.toGF216 *
        square.toGF216 ^ (2 ^ (p.1.start.val - iter.start.val).toNat - 1))
  · rintro ⟨iter', sq', out'⟩ ⟨h_end, h_ge, h_le', h_sq, h_out⟩
    unfold div_impl_loop.body
    step*
    have hk1 : (iter1.start.val - iter.start.val).toNat =
        (iter'.start.val - iter.start.val).toNat + 1 := by grind
    refine ⟨by grind, by grind, by grind, ?_, ?_, by grind⟩
    · rw [square1_post, h_sq, ← pow_add, hk1]; grind
    · rw [out1_post, h_sq, h_out, mul_assoc, ← pow_add]; grind
  · grind

/-! # Spec theorem for `encoding.gf.GF16.div_impl` (Fermat-style division via iterated squaring)

In GF(2¹⁶) — the Galois field with 65536 elements — every non-zero element `b` satisfies `b^(2¹⁶ −
1) = 1`, so the multiplicative inverse is `b⁻¹ = b^(2¹⁶ − 2)` and `a / b = a · b^(2¹⁶ − 2)`.  The
exponent `2¹⁶ − 2 = 2 · (2¹⁵ − 1)` is computed by iterated squaring: starting from `square = b²` and
`out = a`, one repeats
  `out = out · square;  square = square²`
for the 15 indices `i = 1, …, 15`, after which
  `out = a · (b²)^(2¹⁵ − 1) = a · b^(2¹⁶ − 2) = a / b`.

**Source**: spqr/src/encoding/gf.rs -/

/-- **Spec theorem for `encoding.gf.GF16.div_impl`**:

• Total (no panic) on all `GF16` inputs.
• `result.toGF216 = self.toGF216 * other.toGF216 ^ (2 ^ 16 − 2)` in `GF216 = GaloisField 2 16`.
  For `other ≠ 0`, Fermat gives `other^(2¹⁶ − 2) = other⁻¹`, so this is `self / other`. -/
@[step]
theorem div_impl_spec (self other : GF16) :
    div_impl self other ⦃ (result : GF16) =>
      result.toGF216 = self.toGF216 * other.toGF216 ^ (2 ^ 16 - 2) ⦄ := by
  unfold div_impl
  step*
  have h_loop :=  div_impl_loop_spec { start := 1#i32, «end» := 16#i32 } square self (by norm_num)
  simp [square_post, ← pow_two, ← pow_mul ] at h_loop
  simp [h_loop]

end spqr.encoding.gf.GF16
