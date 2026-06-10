/-
Copyright 2026 The Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE-APACHE.
Authors: Hoang Le Truong
-/
import Spqr.Math.Poly.Basic.Defs

/-!
# Expected trailing sub-polynomial

## Main definitions

* `expectedTrailingPoly` — expected trailing sub-polynomial after `k` iterations.

## Main statements

* `expectedTrailingPoly_zero` — base case.
* `expectedTrailingPoly_succ` — recurrence.
-/

open Polynomial
open spqr.encoding.gf

namespace spqr.encoding.polynomial

/--
Expected trailing sub-polynomial after `k` iterations.

Defined by the recurrence:
  `S₀ = C(p_coeffs[offset]!.toGF216)`
  `S_{k+1} = C(p_coeffs[offset − (k + 1)]!.toGF216) +
             (X − C(pts[iter_start + k]!.x.toGF216)) · Sₖ`

This tracks the compound effect of `k` calls to `mult_xdiff_assign_trailing` on the trailing
sub-polynomial rooted at position `offset`.
-/
noncomputable def expectedTrailingPoly
    (p_coeffs : List GF16) (pts : List Pt)
    (offset iter_start : Nat) : Nat → GF216[X]
  | 0 => C (p_coeffs[offset]!.toGF216)
  | k + 1 =>
    C (p_coeffs[offset - (k + 1)]!.toGF216) +
    (X - C (pts[iter_start + k]!.x.toGF216)) *
      expectedTrailingPoly p_coeffs pts offset iter_start k

/-- Base case: the expected trailing polynomial after 0 iterations. -/
@[simp]
lemma expectedTrailingPoly_zero (p_coeffs : List GF16) (pts : List Pt)
    (offset iter_start : Nat) :
    expectedTrailingPoly p_coeffs pts offset iter_start 0 =
      C (p_coeffs[offset]!.toGF216) := rfl

/-- Step case: one-step unfolding of `expectedTrailingPoly`. -/
lemma expectedTrailingPoly_succ (p_coeffs : List GF16) (pts : List Pt)
    (offset iter_start k : Nat) :
    expectedTrailingPoly p_coeffs pts offset iter_start (k + 1) =
      C (p_coeffs[offset - (k + 1)]!.toGF216) +
      (X - C (pts[iter_start + k]!.x.toGF216)) *
        expectedTrailingPoly p_coeffs pts offset iter_start k := rfl

end spqr.encoding.polynomial
