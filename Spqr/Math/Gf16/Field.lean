/-
Copyright 2026 The Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE-APACHE.
Authors: Hoang Le Truong
-/
import Spqr.Math.Gf16.Irreducible
import Spqr.Code.Types
import Mathlib.FieldTheory.Finite.GaloisField

/-!
# The construction of GF(2¹⁶)

`GF216 = GaloisField 2 16` as a quotient of `(ZMod 2)[X]` by `polyGF2`, together with the canonical
ring homomorphism `BinaryPoly.toGF216` and the interpretation function `Nat.toGF216`.

The identifier names are chosen to follow Mathlib's conventions for similar objects:

* `adjoinRootEquivGF216` for the `ZMod 2`-algebra isomorphism between `AdjoinRoot polyGF2` and
  `GF216`,
* `BinaryPoly.toGF216` for the canonical ring homomorphism `BinaryPoly →+* GF216` (matching the
  existing `Nat.toGF216`),
* `BinaryPoly.toGF216_polyGF2` for the lemma that this homomorphism sends `polyGF2` to `0`.

Note: this development is intended to be upstream-friendly so that it can be reused by other
projects working with the same Galois field.
-/

open Polynomial

/-- The Galois field GF(2^16), used as the coefficient field for SPQR polynomial encoding. -/
abbrev GF216 := GaloisField 2 16

namespace spqr.math.gf

/-- `ZMod 2`-algebra isomorphism between `AdjoinRoot polyGF2` and `GF216 = GaloisField 2 16`. -/
noncomputable opaque adjoinRootEquivGF216 : AdjoinRoot polyGF2 ≃ₐ[ZMod 2] GF216 := by
  let pb := AdjoinRoot.powerBasis polyGF2_monic.ne_zero
  have : Fintype (AdjoinRoot polyGF2) := Module.fintypeOfFintype pb.basis
  have hcard : Fintype.card (AdjoinRoot polyGF2) = 2 ^ 16 := by rw [Module.card_fintype pb.basis,
    ZMod.card, Fintype.card_fin, AdjoinRoot.powerBasis_dim, polyGF2_natDegree]
  have : Fact (Irreducible polyGF2) := ⟨polyGF2_irreducible⟩
  exact GaloisField.algEquivGaloisFieldOfFintype 2 16 hcard

/--
The canonical ring homomorphism `BinaryPoly →+* GF216`, obtained by composing the quotient map
`AdjoinRoot.mk polyGF2` with the algebra isomorphism `adjoinRootEquivGF216`.
-/
noncomputable def _root_.BinaryPoly.toGF216 : BinaryPoly →+* GF216 :=
  (adjoinRootEquivGF216 : AdjoinRoot polyGF2 →+* GF216).comp (AdjoinRoot.mk polyGF2)


/-- The canonical ring homomorphism `BinaryPoly.toGF216` sends `polyGF2` to `0`. -/
lemma _root_.BinaryPoly.toGF216_polyGF2 : BinaryPoly.toGF216 polyGF2 = 0 := by
  simp [BinaryPoly.toGF216, AdjoinRoot.mk_self]

/--
Interpret a natural number as an element of `GF216 = GF(2¹⁶)`, using the canonical chain `Nat →
BinaryPoly → GF216` where the first arrow is `natToBinaryPoly` (binary expansion as a
GF(2)-polynomial) and the second arrow is the canonical ring homomorphism `BinaryPoly.toGF216`
(which factors through `BinaryPoly / (polyGF2)`).
-/
noncomputable def _root_.Nat.toGF216 (n : Nat) : GF216 :=
  BinaryPoly.toGF216 (natToBinaryPoly n)

end spqr.math.gf

namespace spqr.encoding.gf.GF16
open spqr.encoding.gf in
/--
Interpret a `GF16` field element as an element of `GF216 = GF(2¹⁶)`, using the canonical chain
`GF16.value.val → BinaryPoly → GF216`.
-/
noncomputable def toGF216 (g : GF16) : GF216 := g.value.val.toGF216

end spqr.encoding.gf.GF16
