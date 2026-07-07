/-
Copyright 2026 The Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE-APACHE.
Authors: Hoang Le Truong
-/
import Spqr.Math.Poly.Basic.Defs
/-!
# Spec theorem for `spqr::encoding::polynomial::{spqr::encoding::polynomial::PolyConst<N>}::to_poly`

Converts `PolyConst<N>` (fixed-size array of `GF16` coefficients) into `Poly` (heap-allocated
`Vec<GF16>`) by copying coefficients verbatim. The `GF216[X]` polynomial interpretation is
preserved, enabling downstream proofs to transfer `PolyConst`-level results to `Poly`.

**Source**: spqr/src/encoding/polynomial.rs -/

open Aeneas Aeneas.Std

namespace spqr.encoding.polynomial.PolyConst

/-- **Spec theorem for `encoding.polynomial.PolyConst.to_poly`**:

• Always succeeds: both `Array.to_slice` and `Slice.to_vec` are total.
• **Coefficient preservation**: `result.coefficients.val = self.coefficients.val`.
• **Polynomial identity**: `result.toGF216Poly = listToGF216Poly self.coefficients.val`,
  enabling transfer of `PolyConst`-level results to `Poly`. -/
@[step]
theorem to_poly_spec
    {N : Usize} (self : PolyConst N) :
    to_poly self ⦃ (result : Poly) =>
      result.coefficients = self.coefficients.val ∧
      result.toGF216Poly = listToGF216Poly self.coefficients ⦄ := by
  unfold to_poly
  step*
  · intro x _
    simp [encoding.gf.GF16.Insts.CoreCloneClone.clone]
  · simp_all [Poly.toGF216Poly]

end spqr.encoding.polynomial.PolyConst
