/-
Copyright 2026 The Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE-APACHE.
Authors: Hoang Le Truong
-/
import Spqr.Math.Poly.Basic.Defs

/-!
# Characteristic-2 facts in `GF216` and `GF216Poly`

The lemmas below record that `GF216` has characteristic `2`, in the forms `x + x = 0`,
`-a = a`, and `a - b = a + b`. They live at the root namespace under the `GF216` /
`GF216Poly` prefix so that dot notation is available, exactly as `BinaryPoly.neg_eq` does
in `Spqr/Math/Gf2Poly/Basic.lean`.

## Main statements

* `GF216.two_eq_zero`, `GF216.add_self_eq_zero` — characteristic-2 in `GF216`.
* `GF216Poly.neg_eq`, `GF216Poly.sub_eq_add` — characteristic-2 in `GF216Poly`.
-/

open Polynomial

/-! ## Characteristic-2 facts in `GF216` and `GF216Poly` -/

/-- GF(2¹⁶) has characteristic 2: `(2 : GF216) = 0`. -/
lemma GF216.two_eq_zero : (2 : GF216) = 0 :=
  CharP.cast_eq_zero GF216 2

/--
In `GF216`, every element added to itself gives zero.

This is the fundamental `x + x = 0` identity in characteristic 2.
-/
lemma GF216.add_self_eq_zero (x : GF216) : x + x = 0 := by
  have h2 : (2 : GF216) = 0 := GF216.two_eq_zero
  have : x + x = 2 * x := by ring
  rw [this, h2, zero_mul]

/--
In `GF216Poly`, every element is its own negation.

This is a consequence of characteristic 2: `a + a = 0` implies `-a = a`.  This parallels
`BinaryPoly.neg_eq` from `Spqr.Math.Gf`, now lifted from `BinaryPoly` to `GF216Poly`.
-/
lemma GF216Poly.neg_eq (a : GF216[X]) : -a = a := by
  have h : a + a = 0 := by
    ext n; simp only [coeff_add, coeff_zero]
    calc (a.coeff n) + (a.coeff n) = 2 * (a.coeff n) := by ring
      _ = 0 * (a.coeff n) := by rw [GF216.two_eq_zero]
      _ = 0 := by ring
  exact neg_eq_of_add_eq_zero_left h

/--
In `GF216Poly`, subtraction equals addition.

Direct consequence of `GF216Poly.neg_eq`: `a - b = a + (-b) = a + b`. This mirrors
`BinaryPoly.sub_eq_add` from `Spqr.Math.Gf`, and is the algebraic reason that `GF16::sub` in
the Rust implementation is identical to `GF16::add` (both are XOR).
-/
lemma GF216Poly.sub_eq_add (a b : GF216[X]) : a - b = a + b := by
  rw [sub_eq_add_neg, GF216Poly.neg_eq]

/-! ## Characteristic-2 equality from cancellation -/

/-- In `GF(2¹⁶)`, `a + b = 0` implies `a = b`.
This follows from `a + b = 0  ⟹  a = a + 0 = a + (b + b) = (a + b) + b = 0 + b = b`,
using the characteristic-2 identity `b + b = 0`. -/
theorem GF216_eq_of_add_eq_zero {a b : GF216} (h : a + b = 0) : a = b := by
  have : b + b = 0 := GF216.add_self_eq_zero b
  have hab : a = a + 0 := by ring
  rw [hab, ← this, ← add_assoc, h, zero_add]
