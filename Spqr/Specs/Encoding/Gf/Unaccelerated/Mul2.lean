/-
Copyright 2026 The Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Hoang Le Truong
-/
import Spqr.Specs.Encoding.Gf.Unaccelerated.Mul

/-!
# Spec theorem for `spqr::encoding::gf::unaccelerated::mul2`

Specification and proof for `encoding.gf.unaccelerated.mul2`, which performs *two* GF(2¹⁶)
multiplications sharing a common left operand:

  `mul2(a, b1, b2) = (mul(a, b1), mul(a, b2))`

This is the software (unaccelerated) fallback for the "double-product" primitive used by
higher-level encoding routines; on x86/x86_64 and aarch64 the same operation may be dispatched to a
fused hardware carry-less multiplication kernel.  The semantics are nevertheless exactly that of
running `unaccelerated.mul` twice with the same `a`, once against each `bi`.

Each component of the result is therefore the canonical GF(2¹⁶) representative of the polynomial
product, obtained by composing
  1. `poly_mul`     — carry-less (XOR-based) long multiplication, then
  2. `poly_reduce`  — table-driven reduction modulo
                      POLY = x¹⁶ + x¹² + x³ + x + 1 (0x1100b).

**Source**: spqr/src/encoding/gf.rs (lines 436:4-438:5)
-/

open Aeneas Aeneas.Std spqr.math.gf

namespace spqr.encoding.gf.unaccelerated

/-- `mul2 a b1 b2` performs two independent GF(2¹⁶) multiplications that share the left operand `a`.
Each component of the returned pair satisfies the polynomial-level specification of `mul`:

  `natToBinaryPoly result.1.val =
     (natToBinaryPoly a.val * natToBinaryPoly b1.val) %ₘ polyGF2`
  `natToBinaryPoly result.2.val =
     (natToBinaryPoly a.val * natToBinaryPoly b2.val) %ₘ polyGF2`

This is an immediate consequence of `mul_spec'` applied componentwise along the `do`-block in the
extracted Lean source. -/
theorem mul2_spec_poly (a b1 b2 : Std.U16) :
    mul2 a b1 b2 ⦃ (result : U16 × U16) =>
      natToBinaryPoly result.1.val =
        (natToBinaryPoly a.val * natToBinaryPoly b1.val) %ₘ polyGF2 ∧
      natToBinaryPoly result.2.val =
        (natToBinaryPoly a.val * natToBinaryPoly b2.val) %ₘ polyGF2 ⦄ := by
  unfold mul2
  have h1 := mul_spec_nat a b1
  have h2 := mul_spec_nat a b2
  step*

/-- **Spec theorem for `encoding.gf.unaccelerated.mul2`**:

For any ring-homomorphism `BinaryPoly.toGF216 : BinaryPoly →+* GF216` that vanishes on `polyGF2`,
both components of `mul2 a b1 b2` correspond — via `BinaryPoly.toGF216 ∘ natToBinaryPoly` — to the
products `a · b1` and `a · b2` in `GF216`.

Specialising `BinaryPoly.toGF216` to the canonical isomorphism (whose construction requires
irreducibility of `polyGF2` over `ZMod 2`, i.e. a finite- field development we omit here) recovers
the GF(2¹⁶) interpretation of the result. -/
@[step]
theorem mul2_spec (a b1 b2 : U16) :
    mul2 a b1 b2 ⦃ (result : U16 × U16) =>
      result.1.val.toGF216 = a.val.toGF216 * b1.val.toGF216 ∧
      result.2.val.toGF216 = a.val.toGF216 * b2.val.toGF216 ⦄ := by
  unfold mul2
  have h1 := mul_spec a b1
  have h2 := mul_spec a b2
  step*

end spqr.encoding.gf.unaccelerated
