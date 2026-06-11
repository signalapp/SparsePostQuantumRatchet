/-
Copyright 2026 The Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE-APACHE.
Authors: Hoang Le Truong
-/
import SrcTranslated.Funs
import Spqr.Math.Poly.Basic.Zero
/-! # Spec theorem for `spqr::encoding::polynomial::{spqr::encoding::polynomial::Poly}::zero`

A `Poly` holds coefficients `[a₀, …, aₙ]` of a GF(2¹⁶) polynomial `a₀ + a₁·x + … + aₙ·xⁿ`.
The zero polynomial has an empty coefficient list.

**Source**: spqr/src/encoding/polynomial.rs -/

open Aeneas Aeneas.Std

namespace spqr.encoding.polynomial.Poly

/-- **Spec theorem for `spqr.encoding.polynomial.Poly.zero`**:

`zero capacity` returns the zero polynomial with an empty coefficient vector. The `capacity`
argument is only an allocation hint; the result satisfies `result.toGF216Poly = 0`. -/
@[step]
theorem zero_spec (capacity : Usize) :
    zero capacity ⦃ (result : Poly) =>
      result.coefficients.val.length = 0 ∧ result.toGF216Poly = 0 ⦄ := by
  unfold zero
  simp [alloc.vec.Vec.with_capacity, toGF216Poly]

end spqr.encoding.polynomial.Poly
