/-
Copyright 2026 The Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE-APACHE.
Authors: Hoang Le Truong
-/
import Spqr.Math.Poly.Eval
import Spqr.Specs.Encoding.Gf.GF16.ZERO

/-!
# Spec theorem for `spqr::encoding::polynomial::{spqr::encoding::polynomial::PolyConst<N>}::ZEROS`

`ZEROS` is the zero polynomial in `PolyConst<N>`, with all `N` coefficients set to `GF16::ZERO`.

**Source**: spqr/src/encoding/polynomial.rs -/

open Aeneas Aeneas.Std Result spqr.encoding.gf

namespace spqr.encoding.polynomial.PolyConst

/-- **Spec theorem for `encoding.polynomial.PolyConst.ZEROS`**:
the coefficient array of `ZEROS N` is `N` copies of `GF16.ZERO`, and lifting it
to `GF216[X]` gives the zero polynomial. -/
theorem ZEROS_coefficients (N : Usize) :
    (ZEROS N).coefficients = Array.repeat N GF16.ZERO := by
  simp [ZEROS]

theorem ZEROS_coefficients_val (N : Usize) :
    (ZEROS N).coefficients.val = List.replicate N.val GF16.ZERO := by
  simp [ZEROS, Array.repeat_val]

@[simp]
theorem ZEROS_toGF216Poly (N : Usize) :
    listToGF216Poly (ZEROS N).coefficients.val = 0 := by
  rw [ZEROS_coefficients_val]
  induction N.val with
  | zero => simp
  | succ n ih =>
    rw [List.replicate_succ, listToGF216Poly_cons, GF16.ZERO_toGF216, ih]
    simp

end spqr.encoding.polynomial.PolyConst
