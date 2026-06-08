/-
Copyright 2026 The Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE-APACHE.
Authors: Hoang Le Truong
-/
import Spqr.Code.Funs
/-! # Spec Theorem for `GF16::eq` (PartialEq / Eq)

Specification and proof for `encoding.gf.GF16.Insts.CoreCmpPartialEqGF16.eq`, which implements
`PartialEq<GF16> for GF16` via the derived `#[derive(Eq, PartialEq)]` attribute.

**Source**: spqr/src/encoding/gf.rs (line 9, `#[derive(Eq, PartialEq)]`)
-/

open Aeneas Aeneas.Std Result

namespace spqr.encoding.gf.GF16

/-
natural language description:

• Takes two `GF16` field elements `self` and `other`, each wrapping a `u16` value representing
  an element of GF(2¹⁶).
• Compares the underlying `u16` values for equality:
    `self.value == other.value`
• Returns `ok true` if the values are equal, `ok false` otherwise.

natural language specs:

• The function always succeeds (no panic / no error) for any pair of GF16 inputs.
• The result is `true` if and only if `self.value = other.value`:
    `eq(a, b) = ok (a.value = b.value)`
• The relation is reflexive, symmetric, and transitive — i.e. it is a total equivalence
  relation, consistent with the `Eq` trait.
-/

/-- **Spec and proof concerning `encoding.gf.GF16.Insts.CoreCmpPartialEqGF16.eq`**:

The derived `PartialEq<GF16> for GF16` succeeds for all inputs and returns `true` if and only if
the two underlying `u16` values are equal.

Since GF16 is a transparent newtype around `u16`, equality of the wrapper is equivalent to
equality of the representation:

  `eq(a, b) = ok (a.value = b.value)`

This is a total, decidable equality — consistent with `GF16` also deriving `Eq`.

**Source**: spqr/src/encoding/gf.rs (line 9, `#[derive(Eq, PartialEq)]`)
-/
@[step]
theorem eq_spec (self other : spqr.encoding.gf.GF16) :
    Insts.CoreCmpPartialEqGF16.eq self other ⦃ (result : Bool) =>
      result = true ↔ (self.value = other.value) ⦄ := by
  simp [Insts.CoreCmpPartialEqGF16.eq]

/-- Two `GF16` elements are equal (as structs) if and only if their `value` fields are equal.
This connects propositional equality of the wrapper to propositional equality of the
representation. -/
theorem gf16_eq_iff (a b : spqr.encoding.gf.GF16) :
    a = b ↔ a.value = b.value := by
  constructor
  · intro h; rw [h]
  · intro h
    cases a
    cases b
    simp only at h
    subst h
    rfl

end spqr.encoding.gf.GF16
