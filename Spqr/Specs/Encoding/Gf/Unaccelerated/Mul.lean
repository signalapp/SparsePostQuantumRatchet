/-
Copyright 2026 The Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE-APACHE.
Authors: Hoang Le Truong
-/
import Spqr.Code.Funs
import Spqr.Math.Gf16.Field
import Spqr.Math.Poly.ModByMonic
import Spqr.Specs.Encoding.Gf.Reduce.PolyReduce
import Spqr.Specs.Encoding.Gf.Unaccelerated.PolyMul

/-!
# Spec theorem for `spqr::encoding::gf::unaccelerated::mul`

In GF(2¹⁶) — the Galois field with 65 536 elements — multiplication is polynomial multiplication
modulo the irreducible polynomial POLY. Each field element is represented as a polynomial of degree
< 16 with coefficients in GF(2), stored as a 16-bit unsigned integer.

The function proceeds in two stages:
  1. `poly_mul(a, b)` — carry-less (XOR-based) long multiplication of the two 16-bit inputs,
     producing a 32-bit unreduced product.
  2. `poly_reduce(product)` — reduction of the 32-bit product modulo POLY using a precomputed
     table (`REDUCE_BYTES`), yielding a 16-bit result that is the canonical representative in
     GF(2¹⁶).

**Source**: spqr/src/encoding/gf.rs (lines 444:4-446:5)
-/

open Aeneas Aeneas.Std Result spqr.math.gf

namespace spqr.encoding.gf.unaccelerated

/-- **Spec theorem for `encoding.gf.unaccelerated.mul`**:

Carry-less polynomial multiplication of two `u16` values in GF(2¹⁶), followed by reduction modulo
the irreducible polynomial POLY = 0x1100b.

The function composes `poly_mul` (carry-less long multiplication producing a 32-bit intermediate)
with `poly_reduce` (table-based reduction modulo POLY).

The result satisfies the polynomial-level specification:
  `natToBinaryPoly result.val =
     (natToBinaryPoly a.val * natToBinaryPoly b.val) %ₘ polyGF2`

This follows from composing:
  1. `poly_mul_spec`:
       `natToBinaryPoly (poly_mul a b).val = natToBinaryPoly a.val * natToBinaryPoly b.val`
  2. `poly_reduce_spec`: `natToBinaryPoly (poly_reduce v).val = (natToBinaryPoly v.val) %ₘ polyGF2`

This establishes that `mul` computes multiplication in the quotient ring
  GF(2¹⁶) ≅ GF(2)[X] / (polyGF2)
at the polynomial level.

**Source**: spqr/src/encoding/gf.rs (lines 444:4-446:5)
-/
theorem mul_spec_nat (a b : U16) :
    mul a b ⦃ ( result : U16) =>
      natToBinaryPoly result.val =
        (natToBinaryPoly a.val * natToBinaryPoly b.val) %ₘ polyGF2 ⦄ := by
  unfold mul
  step*

/--
For any ring-homomorphism `BinaryPoly.toGF216 : BinaryPoly →+* GF216` that vanishes on `polyGF2`,
the result of `mul a b` corresponds — via `BinaryPoly.toGF216 ∘ natToBinaryPoly` — to the product of
`a` and `b` in `GF216`.

Specializing `BinaryPoly.toGF216` to the canonical isomorphism (whose construction requires
irreducibility of `polyGF2` over `ZMod 2`, i.e. a finite-field development we omit here) recovers
the GF(2¹⁶) interpretation of the result.
-/
@[step]
theorem mul_spec
    (a b : U16) :
    mul a b ⦃ (result : U16) =>
      result.val.toGF216 = a.val.toGF216 * b.val.toGF216 ⦄ := by
  unfold mul
  step*
  simp only [Nat.toGF216]
  have key :
      BinaryPoly.toGF216 (natToBinaryPoly result.val) =
        BinaryPoly.toGF216
          ((natToBinaryPoly a.val * natToBinaryPoly b.val) %ₘ polyGF2) := by
    grind
  rw [key, ringHom_modByMonic BinaryPoly.toGF216 polyGF2 BinaryPoly.toGF216_polyGF2, map_mul]

end spqr.encoding.gf.unaccelerated
