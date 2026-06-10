/-
Copyright 2026 The Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE-APACHE.
Authors: Hoang Le Truong
-/
import Spqr.Math.Poly.Coeff.Basic
import Mathlib.RingTheory.DedekindDomain.Basic
/-!
# `GF16.toGF216` at distinguished values, and the `getElem!`/`coeff` bridge

## Main statements

* `GF16.toGF216_eq_zero` — `g.value.val = 0 → g.toGF216 = 0`.
* `GF16.toGF216_eq_one` — `g.value.val = 1 → g.toGF216 = 1`.
* `getElem!_toGF216_eq_coeff` — bridge between `cs[j]!.toGF216` and the polynomial
  coefficient.
-/

open Polynomial
open spqr.math.gf spqr.encoding.gf

namespace spqr.encoding.gf

/-! ## `GF16.toGF216` at 0 and 1 -/

/-- `GF16.toGF216` maps the zero GF16 element to `0 : GF216`. -/
lemma GF16.toGF216_eq_zero (g : spqr.encoding.gf.GF16) (h : g.value.val = 0) :
    g.toGF216 = 0 := by
  unfold GF16.toGF216 Nat.toGF216
  rw [h]
  simp [natToBinaryPoly_zero, map_zero]

/-- `GF16.toGF216` preserves the one element. -/
lemma GF16.toGF216_eq_one (g : spqr.encoding.gf.GF16) (h : g.value.val = 1) :
    g.toGF216 = 1 := by
  unfold GF16.toGF216 Nat.toGF216
  rw [h]
  simp [natToBinaryPoly_one, map_one]

end spqr.encoding.gf

namespace spqr.encoding.polynomial

/-! ## Bridge between `getElem!` and coefficients -/

/--
Bridge: `getElem!` with `toGF216` equals `listToGF216Poly` coefficient.

Connects the Lean list indexing `cs[j]!.toGF216` to the mathematical coefficient
`(listToGF216Poly cs).coeff j`, handling the out-of-bounds case.
-/
lemma getElem!_toGF216_eq_coeff
    (cs : List GF16) (j : Nat) :
    (cs[j]!).toGF216 = (listToGF216Poly cs).coeff j := by
  rw [listToGF216Poly_coeff]
  by_cases hj : j < cs.length
  · rw [dif_pos hj, List.get_eq_getElem]
    grind
  · rw [dif_neg hj]
    have : (cs[j]! : spqr.encoding.gf.GF16) = default := by
      grind
    rw [this]; exact GF16.toGF216_eq_zero _ (by rfl)


/-! ## Injectivity of `toGF216` at zero -/

/-- If `n.toGF216 = 0` and `n < 2^16`, then `n = 0`.
Uses the kernel characterization of the ring homomorphism
`BinaryPoly.toGF216`: since `polyGF2` is irreducible in the PID
`BinaryPoly`, the ideal `(polyGF2)` is maximal, and
`ker BinaryPoly.toGF216 = (polyGF2)`.  Any element of
`ker BinaryPoly.toGF216` with degree `< 16` must therefore be
zero. -/
theorem Nat_toGF216_eq_zero
    {n : Nat} (hn : n < 2 ^ 16) (h : n.toGF216 = 0) : n = 0 := by
  open spqr.encoding.gf.unaccelerated in
  unfold Nat.toGF216 at h
  by_contra hn0
  have hne : natToBinaryPoly n ≠ 0 := fun h0 =>
    hn0 (natToBinaryPoly_inj
      (by rw [h0, natToBinaryPoly_zero] : natToBinaryPoly n = natToBinaryPoly 0))
  have hcoeff_zero : ∀ m, 16 ≤ m → (natToBinaryPoly n).coeff m = 0 := by
    intro m hm
    rw [natToBinaryPoly_coeff]
    simp [Nat.testBit_eq_false_of_lt
      (lt_of_lt_of_le hn (Nat.pow_le_pow_right (by norm_num : 0 < 2) hm))]
  have hnd : (natToBinaryPoly n).natDegree < 16 := by
    by_contra h_not
    push Not at h_not
    have h_lc : (natToBinaryPoly n).coeff (natToBinaryPoly n).natDegree ≠ 0 := by
      intro h0; exact hne (Polynomial.leadingCoeff_eq_zero.mp h0)
    exact h_lc (hcoeff_zero _ h_not)
  have hprime : Prime polyGF2 :=
    (UniqueFactorizationMonoid.irreducible_iff_prime).mp polyGF2_irreducible
  have hprime_ideal : (Ideal.span {polyGF2}).IsPrime :=
    (Ideal.span_singleton_prime polyGF2_monic.ne_zero).mpr hprime
  have hne_bot : Ideal.span ({polyGF2} : Set BinaryPoly) ≠ ⊥ := by
    rw [Ne, Ideal.span_singleton_eq_bot]; exact polyGF2_monic.ne_zero
  have hmax : (Ideal.span {polyGF2}).IsMaximal :=
    Ideal.IsPrime.isMaximal hprime_ideal hne_bot
  have hle : Ideal.span {polyGF2} ≤ RingHom.ker BinaryPoly.toGF216 :=
    Ideal.span_le.mpr (Set.singleton_subset_iff.mpr
      (RingHom.mem_ker.mpr BinaryPoly.toGF216_polyGF2))
  have hker_eq : RingHom.ker BinaryPoly.toGF216 = Ideal.span {polyGF2} := by
    rcases eq_or_lt_of_le hle with heq | hlt
    · exact heq.symm
    · exact absurd (hmax.out.2 _ hlt) (RingHom.ker_ne_top BinaryPoly.toGF216)
  have hmem : polyGF2 ∣ natToBinaryPoly n := by
    rwa [← Ideal.mem_span_singleton, ← hker_eq, RingHom.mem_ker]
  have := Polynomial.natDegree_le_of_dvd hmem hne
  rw [polyGF2_natDegree] at this
  omega

/-- If `g.toGF216 = 0`, then `g.value.val = 0`.
This is the reverse direction of `GF16.toGF216_eq_zero`. -/
theorem GF16_toGF216_eq_zero_imp
    (g : GF16) (h : g.toGF216 = 0) :
    g.value.val = 0 := by
  unfold GF16.toGF216 at h
  exact Nat_toGF216_eq_zero (by have := g.value.hBounds; scalar_tac) h

end spqr.encoding.polynomial
