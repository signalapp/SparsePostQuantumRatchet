/-
Copyright 2026 The Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Hoang Le Truong
-/
import Spqr.Code.Funs
import Spqr.Specs.Encoding.Gf.Unaccelerated.Mul

/-!
# Spec theorem for `spqr::encoding::gf::GF16::const_mul`

In GF(2¹⁶) — the Galois field with 65 536 elements — multiplication is polynomial multiplication
modulo the irreducible polynomial POLY = x¹⁶ + x¹² + x³ + x + 1 (0x1100b).  Each `GF16` element is
represented as a `u16` polynomial of degree < 16 with coefficients in GF(2).

Concretely, `const_mul self other` simply computes
  `unaccelerated::mul(self.value, other.value)`
and stores the resulting `u16` in a fresh `GF16` wrapper.  The `const_mul` method introduces no
additional logic beyond this delegation, so its postcondition is inherited from the corresponding
`unaccelerated::mul` specification: lifting the underlying `u16` of the result into `GF216 =
GaloisField 2 16` via `Nat.toGF216` yields the GF(2¹⁶) product of the lifts of `self.value` and
`other.value`.

**Source**: spqr/src/encoding/gf.rs (lines 560:4-564:5)
-/

open Aeneas Aeneas.Std Result

namespace spqr.encoding.gf.GF16

/-- **Spec theorem for `spqr.encoding.gf.GF16.const_mul`**:

`const_mul` computes GF(2¹⁶) multiplication on the `GF16` wrapper by delegating to the underlying
`unaccelerated::mul` (carry-less polynomial multiplication followed by reduction modulo POLY =
0x1100b) and wrapping the resulting `u16` back into a `GF16`.

The result satisfies the GF(2¹⁶)-level postcondition:

  `result.toGF216 = self.toGF216 * other.toGF216`

where `Nat.toGF216 n = BinaryPoly.toGF216 (natToBinaryPoly n)` interprets a natural number as an
element of `GF216 = GaloisField 2 16` via the chosen ring homomorphism `BinaryPoly.toGF216 :
BinaryPoly →+* GF216` that vanishes on `polyGF2`. -/
@[step]
theorem const_mul_spec (self other : GF16) :
    const_mul self other ⦃ (result : GF16) =>
      result.toGF216 = self.toGF216 * other.toGF216 ⦄ := by
  unfold const_mul
  step*
  simp[GF16.toGF216]
  simp_all

end spqr.encoding.gf.GF16
