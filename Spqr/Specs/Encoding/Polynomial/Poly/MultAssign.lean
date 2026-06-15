/-
Copyright 2026 The Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE-APACHE.
Authors: Hoang Le Truong
-/
import Spqr.Math.Poly.Coeff.ListOps
import Spqr.Math.Poly.CharTwo.ToGF216
import Spqr.Specs.Encoding.Gf.ParallelMult

/-! # Spec theorem for `spqr::encoding::polynomial::{spqr::encoding::polynomial::Poly}::mult_assign`

Scales every coefficient of `self` by the GF(2¹⁶) element `m`, which corresponds to polynomial
scalar multiplication by `C(m.toGF216)` in `GF216[X]`. Delegates directly to `parallel_mult`;
the postcondition follows from `parallel_mult_spec`.

**Source**: spqr/src/encoding/polynomial.rs -/

open Aeneas Aeneas.Std spqr.encoding.gf Polynomial

namespace spqr.encoding.polynomial.Poly

/-- **Spec theorem for `encoding.polynomial.Poly.mult_assign`**:

Succeeds when `self.degree + 2 ≤ Usize.max` (required by `parallel_mult`).
Postcondition: `result.toGF216Poly = C (m.toGF216) * self.toGF216Poly` with degree preserved. -/
@[step]
theorem mult_assign_spec
    (self : Poly) (m : GF16)
    (h_len : self.degree + 2 ≤ Usize.max) :
    mult_assign self m ⦃ (result : Poly) =>
      result.degree = self.degree ∧
      result.toGF216Poly = C (m.toGF216) * self.toGF216Poly ⦄ := by
  unfold mult_assign
  simp only [alloc.vec.Vec.deref_mut, lift, bind_tc_ok, degree]
  step*
  refine ⟨by simp_all [Slice.length], ?_⟩
  simp only [Poly.toGF216Poly]
  apply listToGF216Poly_eq_of_coeffs
  · intro j hj
    rw [coeff_C_mul, ← getElem!_toGF216_eq_coeff]
    grind
  · intro j hj
    rw [coeff_C_mul, listToGF216Poly_coeff_eq_zero _ _ (by simp_all [Slice.length])]
    ring

end spqr.encoding.polynomial.Poly
