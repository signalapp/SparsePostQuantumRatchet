/-
Copyright 2026 The Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE-APACHE.
Authors: Hoang Le Truong
-/
import Spqr.Code.Funs
import Spqr.Math.Gf16.Field

/-!
# Spec theorem for `spqr::encoding::gf::GF16::const_sub`

In GF(2¹⁶) — the Galois field with 65 536 elements — subtraction coincides with addition: every
element is its own additive inverse (`a + a = 0`) since GF(2¹⁶) has characteristic 2.  Concretely,
both operations are bitwise XOR of the two 16-bit polynomial encodings:
  `a - b = a + b = a ⊕ b`

The function operates in a single stage:
  1. `self.value ^^^ other.value` — bitwise XOR of the two `u16`
     polynomial encodings, which corresponds to addition (=
     subtraction) of GF(2)-polynomial coefficients.

Unlike `unaccelerated::mul`, no reduction modulo the irreducible polynomial POLY = x¹⁶ + x¹² + x³ +
x + 1 is required: XOR of two `u16` values is itself representable in 16 bits, so the resulting
GF(2) polynomial already has degree `< 16` and is the canonical representative of its class in
`BinaryPoly / (polyGF2)`.

**Source**: spqr/src/encoding/gf.rs (lines 566:4-570:5)
-/

open Aeneas Aeneas.Std Result Polynomial spqr.encoding.gf.unaccelerated spqr.math.gf

namespace spqr.encoding.gf.GF16

/-- **Spec theorem for `encoding.gf.GF16.const_sub`**:

Bitwise XOR of two `u16` values in GF(2¹⁶), wrapped into a `GF16`.

At the GF(2)-polynomial level, XOR corresponds to polynomial addition: each bit of the inputs is a
coefficient in `ZMod 2`, and XOR is exactly coefficient-wise addition modulo 2.  Since `BinaryPoly`
has characteristic 2, polynomial subtraction coincides with polynomial addition, so XOR equally
encodes polynomial subtraction.

The result satisfies the polynomial-level specification:
  `natToBinaryPoly result.value = natToBinaryPoly self.value - natToBinaryPoly other.value.val`

This establishes that `const_sub` computes subtraction in the quotient ring
  GF(2¹⁶) ≅ GF(2)[X] / (polyGF2)
already at the polynomial level — no reduction modulo `polyGF2` is necessary, since XOR of two `u16`
values stays within 16 bits and therefore corresponds to a polynomial of degree `< 16`.

**Source**: spqr/src/encoding/gf.rs (lines 566:4-570:5)
-/
theorem const_sub_spec_poly (self other : GF16) :
    const_sub self other ⦃ (result : GF16) =>
      natToBinaryPoly result.value =
        natToBinaryPoly self.value - natToBinaryPoly other.value ⦄ := by
  unfold const_sub
  step*
  simp_all only [UScalar.val_xor, natToBinaryPoly_xor, BinaryPoly.sub_eq_add]

/-- **Spec theorem for `spqr.encoding.gf.GF16.const_sub`**:

For the chosen ring-homomorphism `BinaryPoly.toGF216 : BinaryPoly →+* GF216` (which vanishes on
`polyGF2`), the result of `const_sub self other` corresponds — via `BinaryPoly.toGF216 ∘
natToBinaryPoly = Nat.toGF216` — to the difference of `self.value.val` and `other.value.val` in
`GF216`.

Specializing `BinaryPoly.toGF216` to the canonical isomorphism (whose construction requires
irreducibility of `polyGF2` over `ZMod 2`, i.e. the finite-field development we omit here) recovers
the GF(2¹⁶) interpretation of the result.

Note that in GF(2¹⁶) addition and subtraction coincide, so this is equivalently
  `result.toGF216 = self.toGF216 + other.toGF216`.
-/
@[step]
theorem const_sub_spec
    (self other : GF16) :
    const_sub self other ⦃ (result : GF16) =>
      result.toGF216 = self.toGF216 - other.toGF216 ⦄ := by
  unfold const_sub
  step*
  simp_all only [UScalar.val_xor, GF16.toGF216, Nat.toGF216, natToBinaryPoly_xor,
    ← BinaryPoly.sub_eq_add, map_sub]

end spqr.encoding.gf.GF16
