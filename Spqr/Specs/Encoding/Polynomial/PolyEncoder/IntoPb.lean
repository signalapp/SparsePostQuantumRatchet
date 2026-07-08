/-
Copyright 2026 The Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE-APACHE.
Authors: Hoang Le Truong
-/
import Spqr.Math.Poly.ModByMonic
import Spqr.Math.Poly.Identities.Basic
import Spqr.Specs.Encoding.Polynomial.Poly.Serialize
import Spqr.Specs.Aeneas.SliceIteratorNext
import Spqr.Specs.Encoding.Polynomial.Pt.Serialize
import Spqr.Specs.Aeneas.RangeIteratorNext
import Spqr.Specs.Aeneas.VecExtendFromSlice

/-! # Spec theorem for `PolyEncoder::into_pb`: loop body 1

One step of the inner coefficient-serialization loop. Calls `next` on a `Range<usize>` iterator
and either returns `v` unchanged (done) or appends the 2-byte big-endian encoding of `pts[i]` to
`v` (continue). Invariant: `v.len() == 2 * i` with `v[2*k]*256 + v[2*k+1] = pts[k].value.val`.

**Source**: spqr/src/encoding/polynomial.rs -/

open Aeneas Aeneas.Std Result spqr.encoding.polynomial spqr.encoding.gf spqr.math.gf

namespace spqr.encoding.polynomial.PolyEncoder.into_pb_loop0_loop0

/-- **Spec theorem for `encoding.polynomial.PolyEncoder.into_pb_loop0_loop0.body`**:

One step of the inner serialization loop. Retrieves index `i` from the range iterator and either
returns `v` unchanged (done, `¬(iter.start < iter.end)`) or appends `[hi, lo]` — the big-endian
bytes of `pts[i].value` — to `v` (continue, with iterator advanced by one). -/
@[step]
theorem body_spec
    (pts : alloc.vec.Vec GF16)
    (iter : core.ops.range.Range Usize)
    (v : alloc.vec.Vec U8)
    (h_end_le : iter.end ≤ pts.length)
    (h_out_overflow : v.length + 2 ≤ Usize.max) :
    body pts iter v ⦃ cf =>
      match cf with
      | ControlFlow.done v' =>
          v' = v ∧ ¬(iter.start < iter.end)
      | ControlFlow.cont (iter1, v1) =>
          iter.start < iter.end ∧
          iter1.start = iter.start.val + 1 ∧
          iter1.end = iter.end ∧
          ∃ (hi lo : U8),
            v1 = v ++ [hi, lo] ∧
            256 * hi  + lo = (pts[iter.start]!).value.val ⦄ := by
  unfold body
  obtain ⟨⟨opt, iter1'⟩, hnext, h_none, h_some⟩ :=
    WP.spec_imp_exists (core.iter.range.IteratorRange.next_Usize_spec' iter)
  rw [hnext]
  simp only [bind_tc_ok]
  by_cases h_lt : iter.start < iter.end
  · obtain ⟨h_opt_eq, h_start1, h_end1⟩ := h_some h_lt
    step*
    obtain ⟨b0, b1, h_a_eq⟩ : ∃ b0 b1, a.val = [b0, b1] :=
      match a.val, a.property with | [b0, b1], _ => ⟨b0, b1, rfl⟩
    refine ⟨h_lt, h_start1, h_end1, b0, b1, ?_, ?_⟩
    · simp_all [Array.to_slice]
    · have e0 : (a[0]!).val = b0.val := by simp [Array.getElem!_Nat_eq, h_a_eq]
      have e1 : (a[1]!).val = b1.val := by simp [Array.getElem!_Nat_eq, h_a_eq]
      grind
  · grind

/-!# Spec theorem for `PolyEncoder::into_pb`: loop 1

Full inner coefficient-serialization loop. Iterates over `pts` via a range iterator, appending
2-byte big-endian encodings to the output. Postcondition: `out.len = 2 * iter.end` with each
pair `(hi, lo)` satisfying `hi*256 + lo = pts[j].value.val`. Proof via `loop.spec_decr_nat`.

**Source**: spqr/src/encoding/polynomial.rs-/
@[step]
theorem loop_spec
    (pts : alloc.vec.Vec GF16)
    (iter : core.ops.range.Range Usize)
    (v : alloc.vec.Vec U8)
    (h_end_le : iter.end ≤ pts.length)
    (h_out_len : v.length = 2 * iter.start)
    (h_start_le : iter.start ≤ iter.end)
    (h_overflow : 2 * pts.length + 2 ≤ Usize.max)
    (h_pre : ∀ (j : Nat), j < iter.start →
          256 * v[2 * j]! + v[2 * j + 1]! = (pts[j]!).value.val) :
    into_pb_loop0_loop0 iter pts v ⦃ (result : alloc.vec.Vec U8) =>
      result.length = 2 * iter.end ∧
      ∀ (j : Nat), j < iter.end →
          256 * result[2 * j]! + result[2 * j + 1]! = (pts[j]!).value.val ⦄ := by
  unfold into_pb_loop0_loop0
  apply loop.spec_decr_nat
    (measure := fun (p : core.ops.range.Range Usize × alloc.vec.Vec U8) => p.1.end - p.1.start)
    (inv := fun (p : core.ops.range.Range Usize × alloc.vec.Vec U8) =>
        p.1.end = iter.end ∧
        p.1.start ≤ p.1.end ∧
        p.2.length = 2 * p.1.start ∧
        (∀ (j : Nat), j < p.1.start →
            256 * p.2[2 * j]! + p.2[2 * j + 1]! = (pts[j]!).value.val))
  · rintro ⟨iter', out'⟩ ⟨h_end', h_start_le', h_out_len', h_pre'⟩
    simp only [] at h_end' h_start_le' h_out_len' h_pre' ⊢
    have h_end_val : iter'.end.val = iter.end.val := by rw [h_end']
    have h_body := body_spec pts iter' out' (by grind) (by grind)
    apply WP.spec_mono h_body
    intro cf h_cf
    match cf with
    | ControlFlow.done out'' => grind
    | ControlFlow.cont (iter'', out'') => grind
  · grind

end spqr.encoding.polynomial.PolyEncoder.into_pb_loop0_loop0

/-! # Spec theorem for `PolyEncoder::into_pb`: loop body 0

One step of the outer point-serialization loop. Calls `next` on a range iterator over `points`
and either returns `v` unchanged (done) or serializes `points[j].value` via the inner loop
(`into_pb_loop0_loop0`) and pushes the resulting byte vector onto `v` (continue).
Invariant: `v.val.length == iter.start.val`.

**Source**: spqr/src/encoding/polynomial.rs -/

namespace spqr.encoding.polynomial.PolyEncoder.into_pb_loop0

instance : Inhabited encoding.polynomial.Point := ⟨⟨alloc.vec.Vec.new _⟩⟩

/-- **Spec theorem for `encoding.polynomial.PolyEncoder.into_pb_loop0.body`**:

One step of the outer serialization loop. Retrieves index `j` from the range iterator, serializes
`points[j].value` into a big-endian byte vector via the inner loop, and pushes it onto `v`.
Done case returns `v` unchanged; cont case appends one serialized entry with iterator advanced. -/
@[step]
theorem body_spec
    (points : Array Point 16#usize)
    (iter : core.ops.range.Range Usize)
    (v : alloc.vec.Vec (alloc.vec.Vec U8))
    (h_end_le : iter.end ≤ points.val.length)
    (h_out_overflow : v.length + 1 ≤ Usize.max)
    (h_inner_overflow : ∀ (j : Nat), j < points.length →
        2 * (points.val[j]!).value.length + 2 ≤ Usize.max) :
    body points iter v ⦃ cf =>
      match cf with
      | ControlFlow.done v' => v' = v ∧ ¬(iter.start < iter.end)
      | ControlFlow.cont (iter1, v1) =>
          iter.start < iter.end ∧
          iter1.start = iter.start.val + 1 ∧
          iter1.end = iter.end ∧
          ∃ (serialized : alloc.vec.Vec U8),
            v1 = v ++ [serialized] ∧
            serialized.length = 2 * (points[iter.start]!).value.val.length ∧
            ∀ (k : Nat),
              k < (points.val[iter.start.val]!).value.length →
                256 * (serialized[2 * k]!) + serialized[2 * k + 1]! =
                  ((points[iter.start]!).value.val[k]!).value.val ⦄ := by
  unfold body
  obtain ⟨⟨opt, iter1'⟩, hnext, h_none, h_some⟩ :=
    WP.spec_imp_exists (core.iter.range.IteratorRange.next_Usize_spec' iter)
  rw [hnext]
  simp only [bind_tc_ok]
  by_cases h_lt : iter.start.val < iter.end.val
  · obtain ⟨h_opt_eq, h_start1, h_end1⟩ := h_some h_lt
    rw [h_opt_eq]
    have h_j_lt : iter.start.val < points.val.length := by omega
    have h_inner := h_inner_overflow iter.start.val h_j_lt
    step*
    · simp_all
      grind
    · simp_all [alloc.vec.Vec.with_capacity]
    · simp_all
      grind
    · simp_all
      grind
  · obtain ⟨h_opt_eq, _⟩ := h_none (by omega)
    rw [h_opt_eq]
    exact ⟨rfl, h_lt⟩

end spqr.encoding.polynomial.PolyEncoder.into_pb_loop0

/-! # Spec theorem for `PolyEncoder::into_pb`: loop 0

Full outer point-serialization loop. Iterates over `points[0..iter.end]`, serializing each
point's GF(2¹⁶) coefficients into a byte vector. Postcondition: `result.len = iter.end` with
each entry encoding the corresponding point's coefficients in big-endian.

**Source**: spqr/src/encoding/polynomial.rs -/

namespace spqr.encoding.polynomial.PolyEncoder.into_pb_loop0

/-- **Spec theorem for `encoding.polynomial.PolyEncoder.into_pb_loop0`**:

Full outer serialization loop. Drives the body to completion, producing a vector of byte vectors
with `result.len = iter.end`, one serialized entry per point. -/
@[step]
theorem loop_spec
    (points : Array Point 16#usize)
    (iter : core.ops.range.Range Usize)
    (v : alloc.vec.Vec (alloc.vec.Vec U8))
    (h_end_le : iter.end ≤ points.length)
    (h_out_len : v.length = iter.start)
    (h_start_le : iter.start ≤ iter.end.val)
    (h_overflow : points.length + 1 ≤ Usize.max)
    (h_inner_overflow : ∀ (j : Nat), j < points.length →
        2 * (points.val[j]!).value.length + 2 ≤ Usize.max)
    (h_pre : ∀ (j : Nat), j < iter.start →
          (v.val[j]!).length = 2 * (points[j]!).value.length ∧
          ∀ (k : Nat), k < (points[j]!).value.length →
              256 * ((v[j]!)[2 * k]!) + (v[j]!)[2 * k + 1]! = ((points[j]!).value[k]!).value.val) :
    into_pb_loop0 iter points v ⦃ (result : alloc.vec.Vec (alloc.vec.Vec U8)) =>
      result.length = iter.end ∧
      ∀ (j : Nat), j < iter.end →
          (result[j]!).length = 2 * (points[j]!).value.length ∧
          ∀ (k : Nat), k < (points[j]!).value.length →
              256 * ((result[j]!)[2 * k]!)  + (result[j]!)[2 * k + 1]! =
                ((points[j]!).value[k]!).value.val ⦄ := by
  unfold into_pb_loop0
  apply loop.spec_decr_nat
    (measure := fun (p : core.ops.range.Range Usize ×
                       alloc.vec.Vec (alloc.vec.Vec U8)) =>
                  p.1.end - p.1.start)
    (inv := fun (p : core.ops.range.Range Usize ×
                     alloc.vec.Vec (alloc.vec.Vec U8)) =>
        p.1.end = iter.end ∧
        p.1.start ≤ p.1.end ∧
        p.2.length = p.1.start ∧
        (∀ (j : Nat), j < p.1.start →
            (p.2.val[j]!).length = 2 * (points[j]!).value.length ∧
            ∀ (k : Nat),
              k < (points[j]!).value.length →
                256 * (p.2.val[j]!)[2 * k]!  + (p.2.val[j]!)[2 * k + 1]! =
                  ((points[j]!).value.val[k]!).value.val))
  · rintro ⟨iter', out'⟩ ⟨h_end', h_start_le', h_out_len', h_pre'⟩
    simp only [] at h_end' h_start_le' h_out_len' h_pre' ⊢
    have h_end_val : iter'.end.val = iter.end.val := by rw [h_end']
    have h_body := body_spec points iter' out' (by grind) (by grind) h_inner_overflow
    apply WP.spec_mono h_body
    intro cf h_cf
    match cf with
    | ControlFlow.done out'' => grind
    | ControlFlow.cont (iter'', out'') =>
      simp only [] at h_cf ⊢
      obtain ⟨h_lt, h_start1, h_end1, serialized, h_out_eq, h_ser_len, h_ser_encode⟩ := h_cf
      have h_end1_val : iter''.end.val = iter'.end.val := by rw [h_end1]
      constructor
      · grind
      · grind
  · grind

end spqr.encoding.polynomial.PolyEncoder.into_pb_loop0

/-! # Spec theorem for `PolyEncoder::into_pb`: loop body 2

One step of the polynomial-serialization loop (the `EncoderState::Polys` branch). Calls `next`
on a slice iterator over `Poly` values and either returns `v` unchanged (done) or serializes
the polynomial's coefficients via `Poly::serialize` and pushes the result onto `v` (continue).

**Source**: spqr/src/encoding/polynomial.rs -/

namespace spqr.encoding.polynomial.PolyEncoder.into_pb_loop1

/-- **Spec theorem for `encoding.polynomial.PolyEncoder.into_pb_loop1.body`**:

One step of the polynomial-serialization loop. Retrieves the next `Poly` from the slice iterator,
serializes its coefficients via `Poly::serialize`, and pushes the result onto `v`. Done case
returns `v` unchanged; cont case appends one serialized entry with iterator advanced. -/
@[step]
theorem body_spec
    (iter : core.slice.iter.Iter Poly)
    (v : alloc.vec.Vec (alloc.vec.Vec U8))
    (h_out_overflow : v.length + 1 ≤ Usize.max)
    (h_ser_overflow : ∀ j < iter.slice.length,
        2 * (iter.slice[j]!).degree + 2 ≤ Usize.max) :
    body iter v ⦃ cf =>
      match cf with
      | ControlFlow.done v' =>
          v' = v ∧ ¬(iter.i < iter.slice.length)
      | ControlFlow.cont (iter1, v1) =>
          iter.i < iter.slice.length ∧
          iter1.i = iter.i + 1 ∧
          iter1.slice = iter.slice ∧
          ∃ (serialized : alloc.vec.Vec U8),
            v1 = v ++ [serialized] ∧
            serialized.length =
              2 * (iter.slice[iter.i]!).degree ∧
            ∀ k < (iter.slice[iter.i]!).degree,
                256 * serialized[2 * k]! + serialized[2 * k +1]! =
                  ((iter.slice[iter.i]!).coefficients[k]!).value.val ⦄ := by
  unfold body
  obtain ⟨opt, iter1', hnext, h_none, h_some⟩ := core.slice.iter.IteratorSliceIter.next_post iter
  rw [hnext]
  simp only [bind_tc_ok]
  by_cases h_lt : iter.i < iter.slice.length
  · obtain ⟨h_opt_eq, h_i1, h_slice1⟩ := h_some h_lt
    rw [h_opt_eq]
    have h_ser := h_ser_overflow iter.i h_lt
    have h_getelem : (iter.slice.val[iter.i]! : Poly) =
        iter.slice.val[iter.i]'h_lt := by
      rw [← List.Inhabited_getElem_eq_getElem! (hi := h_lt)]
    step*
  · obtain ⟨h_opt_eq, _⟩ := h_none (by omega)
    rw [h_opt_eq]
    exact ⟨rfl, h_lt⟩

end spqr.encoding.polynomial.PolyEncoder.into_pb_loop1

/-! # Spec theorem for `PolyEncoder::into_pb`: loop 2

Full polynomial-serialization loop (the `EncoderState::Polys` branch). Iterates over a slice of
`Poly` values, serializing each polynomial's coefficients into a byte vector. Postcondition:
`result.len = slice.len` with each entry encoding the corresponding polynomial's coefficients
in big-endian. Proof via `loop.spec_decr_nat`.

**Source**: spqr/src/encoding/polynomial.rs -/

namespace spqr.encoding.polynomial.PolyEncoder.into_pb_loop1

/-- **Spec theorem for `encoding.polynomial.PolyEncoder.into_pb_loop1`**:

Full polynomial-serialization loop. Drives the body to completion, producing a vector of byte
vectors with `result.len = slice.len`, one serialized entry per polynomial. -/
@[step]
theorem loop_spec
    (iter : core.slice.iter.Iter Poly)
    (v : alloc.vec.Vec (alloc.vec.Vec U8))
    (h_out_len : v.length = iter.i)
    (h_start_le : iter.i ≤ iter.slice.length)
    (h_overflow : iter.slice.length + 1 ≤ Usize.max)
    (h_ser_overflow : ∀ j < iter.slice.length,
        2 * (iter.slice[j]!).degree + 2 ≤ Usize.max)
    (h_pre : ∀ j < iter.i,
          (v[j]!).length = 2 * (iter.slice[j]!).degree ∧
          ∀ k < (iter.slice[j]!).degree,
              256 * (v[j]!)[2 * k]! + (v[j]!)[2 * k + 1]! =
                ((iter.slice[j]!).coefficients[k]!).value.val) :
    into_pb_loop1 iter v ⦃ (result : alloc.vec.Vec (alloc.vec.Vec U8)) =>
      result.length = iter.slice.length ∧
      ∀ j < iter.slice.length,
          (result[j]!).length = 2 * (iter.slice[j]!).degree ∧
          ∀ k < (iter.slice[j]!).degree,
              256 * (result[j]!)[2 * k]! + (result[j]!)[2 * k + 1]! =
                ((iter.slice[j]!).coefficients[k]!).value.val ⦄ := by
  unfold into_pb_loop1
  apply loop.spec_decr_nat
    (measure := fun (p : core.slice.iter.Iter Poly ×
                       alloc.vec.Vec (alloc.vec.Vec U8)) => p.1.slice.length - p.1.i)
    (inv := fun (p : core.slice.iter.Iter Poly × alloc.vec.Vec (alloc.vec.Vec U8)) =>
        p.1.slice = iter.slice ∧
        p.1.i ≤ p.1.slice.length ∧
        p.2.length = p.1.i ∧
        (∀ j < p.1.i, (p.2[j]!).length = 2 * (iter.slice[j]!).degree ∧
          ∀ k < (iter.slice[j]!).degree,
            256 * (p.2[j]!)[2 * k]! + (p.2[j]!)[2 * k + 1]! =
            ((iter.slice[j]!).coefficients[k]!).value.val))
  · rintro ⟨iter', out'⟩ ⟨h_slice', h_start_le', h_out_len', h_pre'⟩
    simp only [] at h_slice' h_start_le' h_out_len' h_pre' ⊢
    have h_slice_len : iter'.slice.val.length = iter.slice.val.length := by rw [h_slice']
    have h_body := body_spec iter' out' (by grind) (by rw [h_slice']; exact h_ser_overflow)
    apply WP.spec_mono h_body
    intro cf h_cf
    match cf with
    | ControlFlow.done out'' => grind
    | ControlFlow.cont (iter'', out'') =>
      simp only [] at h_cf ⊢
      obtain ⟨h_lt, h_i1, h_slice1, serialized, h_out_eq, h_ser_len, h_ser_encode⟩ := h_cf
      have h_slice1_len : iter''.slice.val.length = iter'.slice.val.length := by rw [h_slice1]
      rw [h_slice'] at h_ser_len h_ser_encode
      constructor
      · refine ⟨by rw [h_slice1]; exact h_slice',
               by grind,
               by grind,
               fun j hj => ?_⟩
        by_cases hj_lt : j < iter'.i
        · grind
        · grind
      · grind
  · exact ⟨rfl, h_start_le, h_out_len, h_pre⟩

end spqr.encoding.polynomial.PolyEncoder.into_pb_loop1

/-! # Spec theorem for `spqr::encoding::polynomial::{PolyEncoder}::into_pb`

Converts a `PolyEncoder` (chunk index `idx` + `EncoderState`) into its protobuf representation.
For `Points`: serializes each point's GF(2¹⁶) coefficients into `result.pts` (big-endian).
For `Polys`: serializes each polynomial's coefficients into `result.polys` via `Poly::serialize`.

**Source**: spqr/src/encoding/polynomial.rs -/

namespace spqr.encoding.polynomial.PolyEncoder

/-- **Spec theorem for `encoding.polynomial.PolyEncoder.into_pb`** (byte-level)

Byte-level postcondition for serializing a `PolyEncoder` into its protobuf representation. -/
theorem into_pb_spec_bytes
    (self : PolyEncoder)
    (h_overflow_points : ∀ points,
      self.s = .Points points →
        ∀ j < points.length, 2 * (points[j]!).value.length + 2 ≤ Usize.max)
    (h_overflow_polys : ∀ polys,
      self.s = .Polys polys →
        ∀ j < polys.length, 2 * (polys[j]!).degree + 2 ≤ Usize.max) :
    into_pb self ⦃ (result : proto.pq_ratchet.PolynomialEncoder) =>
      result.idx = self.idx ∧
      match self.s with
      | .Points points =>
        result.polys.val = [] ∧
        result.pts.length = points.length ∧
        ∀ j < points.length,
            (result.pts[j]!).length = 2 * (points[j]!).value.length ∧
            ∀ k < (points[j]!).value.length,
              256 * (result.pts[j]!)[2 * k]! + (result.pts[j]!)[2 * k + 1]!  =
                  ((points[j]!).value[k]!).value.val
      | .Polys polys =>
        result.pts.val = [] ∧
        result.polys.length = polys.length ∧
        ∀ j < polys.length,
          result.polys[j]!.length = 2 * (polys.val[j]!).degree ∧
          ∀ k < (polys.val[j]!).degree,
            256 * (result.polys[j]!)[2 * k ]! + (result.polys[j]!)[2 * k + 1]! =
              ((polys[j]!).coefficients[k]!).value.val ⦄ := by
  unfold into_pb
  simp only [alloc.vec.Vec.with_capacity]
  cases h : self.s with
  | Points points =>
    have h_overflow := h_overflow_points points h
    step*
    all_goals first
      | assumption
      | grind
  | Polys polys =>
    have h_overflow := h_overflow_polys polys h
    step*
    simp only [core.slice.Slice.iter, bind_tc_ok]
    step with into_pb_loop1.loop_spec by
      first
        | assumption
        | scalar_tac
        | omega
        | (simp only [s_post])
    · intros j hj
      simp_all
    · constructor
      · grind
      · simp_all
        grind

/-- **Spec theorem for `PolyEncoder.into_pb`**
(cascading: byte-level + algebraic)

Lifts the byte-level spec to include derived GF(2¹⁶) and polynomial identities. -/
@[step]
theorem into_pb_spec
    (self : PolyEncoder)
    (h_overflow_points : ∀ points,
      self.s = .Points points →
        ∀ j < points.length, 2 * (points[j]!).value.length + 2 ≤ Usize.max)
    (h_overflow_polys : ∀ polys, self.s = .Polys polys →
        ∀ j < polys.length, 2 * (polys[j]!).degree + 2 ≤ Usize.max) :
    into_pb self ⦃ (result : proto.pq_ratchet.PolynomialEncoder) =>
      result.idx = self.idx ∧
      match self.s with
      | .Points points =>
        result.polys.val = [] ∧
        result.pts.length = points.length ∧
        ∀ j < points.length,
            result.pts[j]!.length = 2 * (points[j]!).value.length ∧
            ∀ k < (points[j]!).value.length,
                256 * (result.pts[j]!)[2 * k]! + (result.pts[j]!)[2 * k + 1]! =
                  ((points[j]!).value[k]!).value.val ∧
                (256 * (result.pts[j]!)[2 * k]! + (result.pts[j]!)[2 * k + 1]! : ℕ).toGF216 =
                  ((points[j]!).value[k]!).value.val.toGF216 ∧
                natToBinaryPoly (256 * (result.pts[j]!)[2 * k]! + (result.pts[j]!)[2 * k + 1]!) =
                  natToBinaryPoly (((points[j]!).value[k]!).value.val)
      | .Polys polys =>
        result.pts.val = [] ∧
        result.polys.length = polys.length ∧
        ∀ j < polys.length,
            (result.polys[j]!).length =
              2 * (polys[j]!).degree ∧
            ∀ k < (polys[j]!).degree,
                 256 * (result.polys[j]!)[2 * k]! + (result.polys[j]!)[2 * k + 1]! =
                  ((polys[j]!).coefficients[k]! ).value.val ∧
                (256 * (result.polys[j]!)[2 * k]! + (result.polys[j]!)[2 * k + 1]! : ℕ).toGF216 =
                  ((polys[j]!).coefficients[k]!).value.val.toGF216 ∧
                natToBinaryPoly (
                  256 * (result.polys[j]!)[2 * k]! + (result.polys[j]!)[2 * k + 1]! ) =
                  natToBinaryPoly (((polys[j]!).coefficients[k]!).value.val) ⦄ := by
  have h_raw := into_pb_spec_bytes self h_overflow_points h_overflow_polys
  apply WP.spec_mono h_raw
  intro result h_post
  obtain ⟨h_idx, h_data⟩ := h_post
  refine ⟨h_idx, ?_⟩
  cases h : self.s with
  | Points points => grind
  | Polys polys => grind

end spqr.encoding.polynomial.PolyEncoder
