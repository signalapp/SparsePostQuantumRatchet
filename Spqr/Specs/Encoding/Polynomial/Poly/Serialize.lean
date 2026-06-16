/-
Copyright 2026 The Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE-APACHE.
Authors: Hoang Le Truong
-/
import Spqr.Math.List
import Spqr.Math.Gf16.Field
import Spqr.Specs.Encoding.Polynomial.Pt.Serialize
import Spqr.Specs.Aeneas.RangeIteratorNext

/-!
# Spec theorem for `Poly::serialize`: loop body 0

One step of the coefficient serialization loop: either the iterator is exhausted (output
unchanged) or the next coefficient is encoded as 2 big-endian bytes appended to the output.
Invariant: `out.len() == 2 * i`, with `out[2*j] * 256 + out[2*j+1] = v[j].value.val` for `j < i`.

**Source**: spqr/src/encoding/polynomial.rs -/

open Aeneas Aeneas.Std Result spqr.encoding.polynomial spqr.encoding.gf

namespace spqr.encoding.polynomial.Poly.serialize_loop

/--
**Spec for `alloc.vec.Vec.extend_from_slice` specialised to `U8`**:

Cloning `U8` is the identity, so appending `s` yields `v.val ++ s.val`. The precondition
`v.val.length + s.val.length ≤ Usize.max` discharges the overflow guard. -/
@[step]
private lemma extend_from_slice_U8_spec
    (v : alloc.vec.Vec U8) (s : Slice U8)
    (h : v.length + s.length ≤ Usize.max) :
    alloc.vec.Vec.extend_from_slice core.clone.CloneU8 v s
      ⦃ (r : alloc.vec.Vec U8) => r = v ++ s.val ⦄ := by
  have h_clone_x :
      ∀ x ∈ s.val, core.clone.CloneU8.clone x = ok x := by
    intros _ _; rfl
  have h_slclone :
      Slice.clone core.clone.CloneU8.clone s = ok s := by
    obtain ⟨s', h_eq, hs⟩ := WP.spec_imp_exists (Slice.clone_spec h_clone_x)
    rw [h_eq, ← hs]
  unfold alloc.vec.Vec.extend_from_slice
  grind

/-! ## Helper: big-endian byte pair arithmetic -/

/--
**Big-endian byte-pair identity for `u16`**:

If the 2-byte big-endian encoding of a `u16` value `x` is `[b0, b1]`, then
`b0.val * 256 + b1.val = x.val`.
-/
private lemma toBEBytes_pair (x : U16) (b0 b1 : U8)
    (h : [b0, b1] = List.map (@UScalar.mk UScalarTy.U8) x.bv.toBEBytes) :
    256 * b0 + b1 = x.val := by
  have h0 : b0 = (List.map (@UScalar.mk UScalarTy.U8) x.bv.toBEBytes)[0]! := by rw [← h]; simp
  have h1 : b1 = (List.map (@UScalar.mk UScalarTy.U8) x.bv.toBEBytes)[1]! := by rw [← h]; simp
  subst h0 h1
  simp only [Std.UScalar.val]
  simp [BitVec.toBEBytes, BitVec.toLEBytes, Nat.shiftRight_eq_div_pow]
  grind

/-- **Spec theorem for `encoding.polynomial.Poly.serialize_loop.body`**:

One step of the serialize loop. Preconditions: `iter.end.val ≤ v.len` and room for two more
bytes. In the **done** case `out` is unchanged and `¬(iter.start.val < iter.end.val)`. In the
**cont** case the iterator advances by one (`iter1.start = iter.start + 1`, `iter1.end = iter.end`)
and `out` gains the two big-endian bytes of the current coefficient:
`out1.val = out.val ++ [hi, lo]` with `hi.val * 256 + lo.val = (v.val[iter.start.val]!).value.val`.

**Source**: spqr/src/encoding/polynomial.rs -/
@[step]
theorem body_spec
    (v : alloc.vec.Vec GF16)
    (iter : core.ops.range.Range Usize)
    (out : alloc.vec.Vec U8)
    (h_end_le : iter.end ≤ v.val.length)
    (h_out_overflow : out.length + 2 ≤ Usize.max) :
    body v iter out ⦃ cf =>
      match cf with
      | ControlFlow.done out' =>
          out' = out ∧ ¬(iter.start < iter.end)
      | ControlFlow.cont (iter1, out1) =>
          iter.start < iter.end ∧
          iter1.start = iter.start.val + 1 ∧
          iter1.end = iter.end ∧
          ∃ (hi lo : Std.U8),
            out1.val = out.val ++ [hi, lo] ∧
            256 * hi  + lo = (v.val[iter.start.val]!).value.val ⦄ := by
  unfold body
  obtain ⟨opt, iter1', hnext, h_none, h_some⟩ := core.iter.range.IteratorRange.next_Usize_spec iter
  rw [hnext]
  simp only [bind_tc_ok]
  by_cases h_lt : iter.start < iter.end.val
  · obtain ⟨h_opt_eq, h_start1, h_end1⟩ := h_some h_lt
    rw [h_opt_eq]
    have h_i_lt : iter.start.val < v.val.length := by omega
    step*
    obtain ⟨b0, b1, h_a_eq⟩ : ∃ b0 b1, a.val = [b0, b1] :=
      match a.val, a.property with | [b0, b1], _ => ⟨b0, b1, rfl⟩
    refine ⟨h_lt, h_start1, h_end1, b0, b1, ?_, ?_⟩
    · simp_all [Array.to_slice]
    · have e0 : (a[0]!).val = b0.val := by simp [Array.getElem!_Nat_eq, h_a_eq]
      have e1 : (a[1]!).val = b1.val := by simp [Array.getElem!_Nat_eq, h_a_eq]
      grind
  · grind

end spqr.encoding.polynomial.Poly.serialize_loop

/-! # Spec theorem for `Poly::serialize`: loop 0

The full top-level `serialize_loop`, which drives the body to completion. Each coefficient's
`u16` value is encoded as two big-endian bytes. Loop invariant: `out'.len = 2 * iter'.start`,
`iter'.end` unchanged, and `hi * 256 + lo = v[j].value` for every processed index `j`. The
proof lifts `body_spec` via `loop.spec_decr_nat` with measure `iter'.end.val − iter'.start.val`.

**Source**: spqr/src/encoding/polynomial.rs -/

namespace spqr.encoding.polynomial.Poly.serialize_loop

/-- **Spec theorem for `encoding.polynomial.Poly.serialize_loop`**:

The full serialization loop driving the body to completion. Preconditions: `iter.end.val ≤ v.len`,
`out.len = 2 * iter.start`, `iter.start ≤ iter.end`, and no overflow. Postcondition:
`result.len = 2 * iter.end.val` and for every `j < iter.end.val` the bytes satisfy
`hi * 256 + lo = (v.val[j]!).value.val`. Proved via `loop.spec_decr_nat` with measure
`iter'.end.val − iter'.start.val`. -/
@[step]
theorem loop_spec
    (v : alloc.vec.Vec GF16)
    (iter : core.ops.range.Range Usize)
    (out : alloc.vec.Vec U8)
    (h_end_le : iter.end ≤ v.val.length)
    (h_out_len : out.length = 2 * iter.start)
    (h_start_le : iter.start ≤ iter.end)
    (h_overflow : 2 * v.val.length + 2 ≤ Usize.max)
    (h_pre : ∀ (j : Nat), j < iter.start.val →
          256 * out[2 * j]! + out[2 * j + 1]! = (v[j]!).value.val) :
    serialize_loop iter v out ⦃ (result : alloc.vec.Vec Std.U8) =>
      result.length = 2 * iter.end ∧
      ∀ (j : Nat), j < iter.end →
          256 * result[2 * j]! + result[2 * j + 1]! = (v[j]!).value.val ⦄ := by
  unfold serialize_loop
  apply loop.spec_decr_nat
    (measure := fun (p : core.ops.range.Range Usize × alloc.vec.Vec U8) => p.1.end - p.1.start)
    (inv := fun (p : core.ops.range.Range Usize × alloc.vec.Vec U8) =>
        let iter' := p.1
        let out' := p.2
        iter'.end = iter.end ∧
        iter'.start ≤ iter'.end.val ∧
        out'.val.length = 2 * iter'.start ∧
        (∀ (j : Nat), j < iter'.start →
          256 * out'[2 * j]! + out'[2 * j + 1]! = (v.val[j]!).value.val))
  · rintro ⟨iter', out'⟩ ⟨h_end', h_start_le', h_out_len', h_pre'⟩
    simp only [] at h_end' h_start_le' h_out_len' h_pre' ⊢
    have h_end_val : iter'.end = iter.end := by rw [h_end']
    have h_body := body_spec v iter' out' (by grind) (by grind)
    apply WP.spec_mono h_body
    grind
  · exact ⟨rfl, h_start_le, h_out_len, (by grind)⟩

end spqr.encoding.polynomial.Poly.serialize_loop

/-! # Spec theorem for `spqr::encoding::polynomial::{Poly}::serialize`

Serializes a polynomial's GF(2¹⁶) coefficients into a byte vector: allocate a vector of capacity
`2 * n`, then encode each coefficient's `u16` value as two big-endian bytes. The result has length
`2 * n` with `result[2*j] * 256 + result[2*j+1] = coefficients[j].value` for every `j`.

**Source**: spqr/src/encoding/polynomial.rs -/

namespace spqr.encoding.polynomial.Poly

/-- **Spec theorem for `encoding.polynomial.Poly.serialize`**:

Serializes a `Poly`'s GF(2¹⁶) coefficients into a big-endian byte vector by allocating an empty
vector and running `serialize_loop` to completion. Result: length `2 * n` with
`hi * 256 + lo = (coefficients[j]!).value.val` for every `j < n`. The precondition
`2 * n + 2 ≤ Usize.max` guards both the capacity computation and the per-step append. Proved by
composing `Vec.with_capacity` with `serialize_loop.loop_spec`. -/
@[step]
theorem serialize_spec
    (self : Poly)
    (h_overflow : 2 * self.degree + 2 ≤ Usize.max) :
    serialize self ⦃ (result : alloc.vec.Vec U8) =>
      result.length = 2 * self.degree ∧
      ∀ j < self.degree,
        256 * result[2 * j]! + result[2 * j +1]! = (self.coefficients[j]!).value.val ⦄ := by
  unfold serialize degree
  step*
  all_goals (simp_all [degree]; grind [alloc.vec.Vec.with_capacity])


end spqr.encoding.polynomial.Poly
