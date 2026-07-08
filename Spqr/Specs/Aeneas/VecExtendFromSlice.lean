/-
Copyright 2026 The Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE-APACHE.
Authors: Hoang Le Truong
-/
import SrcTranslated.Funs

/-!
# Spec theorems for `alloc::vec::Vec::extend_from_slice`

Specs for `extend_from_slice` when `Clone` is the identity (e.g. `U8`, `GF16`),
showing the result is `v ++ s`. Used in serialization proofs in `Spqr.Specs.Encoding.Polynomial`.-/

open Aeneas Aeneas.Std Result

namespace Aeneas.Std.alloc.vec.Vec

/-- **Spec theorem for `alloc.vec.Vec.extend_from_slice` specialised to `U8`**:

Since `CloneU8.clone x = ok x`, the result is `v.val ++ s.val`
given `v.val.length + s.val.length ≤ Usize.max`. -/
@[step]
theorem extend_from_slice_U8_spec
    (v : alloc.vec.Vec U8) (s : Slice U8)
    (h : v.length + s.length ≤ Usize.max) :
    alloc.vec.Vec.extend_from_slice core.clone.CloneU8 v s ⦃ (r : alloc.vec.Vec U8) =>
      r = v ++ s.val ⦄ := by
  have h_clone_x : ∀ x ∈ s.val, core.clone.CloneU8.clone x = ok x := by
    intros _ _; rfl
  have h_slclone : Slice.clone core.clone.CloneU8.clone s = ok s := by
    obtain ⟨s', h_eq, hs⟩ := WP.spec_imp_exists (Slice.clone_spec h_clone_x)
    rw [h_eq, ← hs]
  unfold alloc.vec.Vec.extend_from_slice
  have hlen : v.length + s.length ≤ Usize.max := h
  rw [dif_pos hlen]
  grind

/-- **Spec theorem for `alloc.vec.Vec.extend_from_slice` specialised to `GF16`**:

Since `GF16.Clone.clone x = ok x`, the result is `v.val ++ s.val`
given `v.val.length + s.val.length ≤ Usize.max`. -/
@[step]
theorem extend_from_slice_GF16_spec
    (v : alloc.vec.Vec spqr.encoding.gf.GF16)
    (s : Slice spqr.encoding.gf.GF16)
    (h : v.length + s.length ≤ Usize.max) :
    alloc.vec.Vec.extend_from_slice
      spqr.encoding.gf.GF16.Insts.CoreCloneClone v s ⦃ (r : alloc.vec.Vec spqr.encoding.gf.GF16) =>
      r = v ++ s.val ⦄ := by
  have h_clone_x : ∀ x ∈ s.val, spqr.encoding.gf.GF16.Insts.CoreCloneClone.clone x = ok x := by
    intros _ _
    simp [spqr.encoding.gf.GF16.Insts.CoreCloneClone.clone]
  have h_slclone :
      Slice.clone spqr.encoding.gf.GF16.Insts.CoreCloneClone.clone s = ok s := by
    obtain ⟨s', h_eq, hs⟩ := WP.spec_imp_exists (Slice.clone_spec h_clone_x)
    rw [h_eq, ← hs]
  unfold alloc.vec.Vec.extend_from_slice
  have hlen : v.length + s.length ≤ Usize.max := h
  rw [dif_pos hlen]
  grind

end Aeneas.Std.alloc.vec.Vec
