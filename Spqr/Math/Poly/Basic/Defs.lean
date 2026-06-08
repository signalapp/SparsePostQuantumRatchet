/-
Copyright 2026 The Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Hoang Le Truong
-/
import Spqr.Code.Funs
import Spqr.Math.Gf16.Field
import Mathlib.RingTheory.Polynomial.Basic

/-! # Bridge frox the Aeneas-extracted `Poly` to `GF(2¹⁶)[X]`

This file defines the type abbreviation `GF216Poly := GF216[X]` and the canonical bridge
functions `listToGF216Poly` and `Poly.toGF216Poly`.

The bridge from the implementation to the mathematics is:

  Implementation Layer          Mathematical Layer
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  GF16 (value : U16)    ──────► GF216 = GF(2¹⁶)
          │    GF16.toGF216         │
          │                        │
  Vec<GF16>             ──────► GF216[X]
          │    listToGF216Poly     │
          │                        │
  Poly                  ──────► GF216[X]
               Poly.toGF216Poly -/

open Polynomial

namespace spqr.encoding.polynomial

instance : Inhabited spqr.encoding.polynomial.Pt where default := ⟨⟨0#u16⟩, ⟨0#u16⟩⟩

/-- Interpret a list of `GF16` coefficients (in ascending degree order) as a polynomial in
`GF(2¹⁶)[X]`. Given `cs = [a₀, a₁, …, aₙ]`, this produces:

  `C(a₀.toGF216) + C(a₁.toGF216)·X + … + C(aₙ.toGF216)·Xⁿ`

where `C : GF216 →+* GF216[X]` is the constant-polynomial embedding. The sum is indexed by `Fin
cs.length`, ensuring well-typed access to each coefficient. -/
noncomputable def listToGF216Poly (cs : List spqr.encoding.gf.GF16) : GF216[X] :=
  ∑ i : Fin cs.length, C ((cs.get i).toGF216) * X ^ i.val

/-- Interpret a `Poly` as a mathematical polynomial in `GF(2¹⁶)[X]`. It reads
the coefficient vector from the `Poly` and  maps each `GF16` coefficient through `GF16.toGF216`. -/
noncomputable def Poly.toGF216Poly (p : Poly) : GF216[X] :=
  listToGF216Poly p.coefficients.val

end spqr.encoding.polynomial
