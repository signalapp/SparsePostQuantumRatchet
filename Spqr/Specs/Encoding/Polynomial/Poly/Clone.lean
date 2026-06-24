/-
Copyright 2026 The Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE-APACHE.
Authors: Hoang Le Truong
-/
import Spqr.Math.Poly.Identities.Basic

/-! # Spec theorem for `spqr::encoding::polynomial::{impl Clone for Poly}::clone`

Cloning preserves the polynomial interpretation: `result.toGF216Poly = self.toGF216Poly`.

**Source**: spqr/src/encoding/polynomial.rs (`#[derive(Clone, PartialEq)]`)-/

open Aeneas Aeneas.Std spqr.encoding.gf

namespace spqr.encoding.polynomial.Poly

@[step]
private lemma clone_GF16_id (x : GF16) :
    GF16.Insts.CoreCloneClone.clone x ⦃ (r : encoding.gf.GF16) =>
      r = x ⦄ := by
  simp [GF16.Insts.CoreCloneClone.clone]

@[step]
private lemma clone_vec_GF16_spec (v : alloc.vec.Vec GF16) :
    alloc.vec.CloneVec.clone GF16.Insts.CoreCloneClone v ⦃ (r : alloc.vec.Vec GF16) =>
      r = v ⦄ := by
  unfold alloc.vec.CloneVec.clone
  apply WP.spec_mono (Slice.clone_spec (fun x _ => by simp [GF16.Insts.CoreCloneClone.clone]))
  intro v' h
  exact h.symm

/-- **Spec theorem for `encoding.polynomial.Poly.Insts.CoreCloneClone.clone`**:

The derived `Clone` always succeeds and is the identity on `Poly`: `clone(self) = ok self`
(since `GF16` is `Copy`, so elementwise clone returns its argument unchanged). -/
@[step]
theorem clone_spec (self : Poly) :
    Insts.CoreCloneClone.clone self ⦃ (result : Poly) =>
      result = self ⦄ := by
  unfold Insts.CoreCloneClone.clone
  step*
  rw [v_post]

/-- **Corollary**: cloning a `Poly` preserves its polynomial interpretation in
`GF216[X] = (GaloisField 2 16)[X]`. Immediate from `clone_spec`. -/
theorem clone_spec_toGF216Poly (self : Poly) :
    Insts.CoreCloneClone.clone self ⦃ (result : Poly) =>
      result.toGF216Poly = self.toGF216Poly ⦄ := by
  apply WP.spec_mono (clone_spec self)
  intro result h
  rw [h]

end spqr.encoding.polynomial.Poly
