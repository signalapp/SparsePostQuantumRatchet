/-
Copyright 2026 The Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Hoang Le Truong
-/
import Mathlib.Algebra.Field.ZMod
import Mathlib.RingTheory.Polynomial.Basic
import Mathlib.Data.Nat.BitIndices
import Mathlib.Data.Nat.Bits
import Mathlib.Algebra.CharP.Two

/-!
# The binary polynomial ring `(ZMod 2)[X]`

This file develops a small API around the bridge

  `natToBinaryPoly : ℕ → (ZMod 2)[X]`

which interprets the binary representation of a natural number as the coefficient vector of a
polynomial over the binary field `ZMod 2`. It also collects a couple of elementary characteristic-2
facts about `BinaryPoly := (ZMod 2)[X]` that are convenient throughout the rest of the library.

The identifier names follow Mathlib's conventions for similar objects: `BinaryPoly` for the type
abbreviation `(ZMod 2)[X]`, `natToBinaryPoly` for the canonical map from `ℕ`, and
`BinaryPoly.neg_eq` / `BinaryPoly.sub_eq_add` for the basic algebraic facts in characteristic 2.

Note: this development is intended to be upstream-friendly so that it can be reused by other
projects working with the same Galois field.

## Main definitions

* `BinaryPoly`: the polynomial ring `(ZMod 2)[X]`.
* `natToBinaryPoly n`: the polynomial whose coefficient at position `m` equals the `m`-th bit of
  `n`.

## Main statements

* `natToBinaryPoly_coeff`: coefficient characterization in terms of `Nat.testBit`.
* `natToBinaryPoly_xor`, `natToBinaryPoly_shiftLeft`, `natToBinaryPoly_split`: bit-level operations
  translate to the expected polynomial operations.
* `natToBinaryPoly_inj`: `natToBinaryPoly` is injective on `ℕ`.
* `BinaryPoly.neg_eq`, `BinaryPoly.sub_eq_add`: characteristic-2 identities in `BinaryPoly`.

## Conventions

* XOR (`^^^`) on `Nat` corresponds to polynomial addition (`+`).
* Shift-left (`<<< n`) corresponds to multiplication by `X ^ n`.
* `Nat.testBit n` corresponds to checking whether the `n`-th coefficient is non-zero.
-/

open Polynomial

/-- Polynomials over the binary field `ZMod 2`. -/
abbrev BinaryPoly := (ZMod 2)[X]

namespace spqr.math.gf

/-! ## Core definition -/

/--
Interpret a natural number as a `BinaryPoly` by taking its binary expansion as the sequence of
coefficients.

For example, `natToBinaryPoly 0b1011 = X ^ 3 + X + 1`, since bits `0`, `1`, and `3` of `11` are set.
-/
noncomputable def natToBinaryPoly (n : ℕ) : BinaryPoly :=
  (n.bitIndices.map (X ^ ·)).sum

/-! ## Helper lemma relating `Nat.bitIndices` and `Nat.testBit` -/

/-- Membership in `n.bitIndices` is equivalent to `n.testBit m = true`. -/
private lemma mem_bitIndices_iff_testBit {n m : ℕ} :
    m ∈ n.bitIndices ↔ n.testBit m := by
  induction n using Nat.binaryRec generalizing m with
  | zero => simp
  | bit b n ih =>
    cases m with
    | zero => rw [Nat.testBit_bit_zero]; cases b <;> simp
    | succ m => rw [Nat.testBit_bit_succ]; cases b <;> simp [ih]

/-! ## Coefficient characterization and basic lemmas of `natToBinaryPoly` -/

/--
The coefficient of `natToBinaryPoly n` at position `m` is `1` when bit `m` of `n` is set, and `0`
otherwise.
-/
lemma natToBinaryPoly_coeff (n m : ℕ) :
    (natToBinaryPoly n).coeff m = if n.testBit m then (1 : ZMod 2) else 0 := by
  unfold natToBinaryPoly
  have hdist : (n.bitIndices.map (X ^ ·)).sum.coeff m =
      ((n.bitIndices.map (X ^ ·)).map (fun p => p.coeff m)).sum :=
    map_list_sum (Polynomial.lcoeff (ZMod 2) m) _
  rw [hdist, List.map_map]
  simp only [Function.comp_def, coeff_X_pow]
  by_cases hm : n.testBit m = true
  · simp only [hm]
    rw [List.sum_map_eq_nsmul_single _ _ fun _ ha _ => if_neg ha.symm]
    simp [mem_bitIndices_iff_testBit.mpr hm]
  · push_neg at hm
    simp only [hm, Bool.false_eq_true]
    exact List.sum_eq_zero (fun x hx => by
      simp only [List.mem_map] at hx
      obtain ⟨i, hi, rfl⟩ := hx
      have hmi : m ≠ i := fun h => by
        subst h; exact absurd (mem_bitIndices_iff_testBit.mp hi) (by simp [hm])
      simp [hmi])

/-- `natToBinaryPoly 0 = 0`. -/
@[simp]
lemma natToBinaryPoly_zero : natToBinaryPoly 0 = 0 := by
  ext m
  simp [natToBinaryPoly_coeff]

/-- XOR of natural numbers corresponds to addition in `BinaryPoly`. -/
lemma natToBinaryPoly_xor (a b : ℕ) :
    natToBinaryPoly (a ^^^ b) = natToBinaryPoly a + natToBinaryPoly b := by
  ext m
  simp only [natToBinaryPoly_coeff, coeff_add, Nat.testBit_xor]
  cases a.testBit m <;> cases b.testBit m <;> decide

/-- Left-shift on naturals corresponds to multiplication by `X ^ k` in `BinaryPoly`. -/
lemma natToBinaryPoly_shiftLeft (a k : ℕ) :
    natToBinaryPoly (a <<< k) = natToBinaryPoly a * X ^ k := by
  ext m
  simp only [natToBinaryPoly_coeff, coeff_mul_X_pow', Nat.testBit_shiftLeft,
    Bool.and_eq_true, decide_eq_true_eq]
  by_cases hkm : k ≤ m <;> simp [hkm]

/--
**Natural-number polynomial decomposition at an arbitrary bit boundary.**

For any natural number `v` and bit position `n`,

  `natToBinaryPoly v = natToBinaryPoly (v % 2 ^ n) + natToBinaryPoly (v >>> n) * X ^ n`.

This decomposes a binary polynomial into its lower `n` coefficients and its upper coefficients
shifted down.
-/
theorem natToBinaryPoly_split (v n : ℕ) :
    natToBinaryPoly v =
      natToBinaryPoly (v % 2 ^ n) + natToBinaryPoly (v >>> n) * X ^ n := by
  ext m
  simp only [natToBinaryPoly_coeff, coeff_add, coeff_mul_X_pow',
             Nat.testBit_mod_two_pow, Nat.testBit_shiftRight]
  by_cases hm : n ≤ m
  · simp only [hm, show ¬ m < n from by omega]
    grind
  · push_neg at hm
    simp only [show ¬ n ≤ m from by omega, hm, ↓reduceIte, add_zero]
    congr 1

/--
**Injectivity of `natToBinaryPoly` on naturals.**

If two natural numbers map to the same binary polynomial, they are equal: the coefficient of
`natToBinaryPoly n` at position `m` is `1` iff bit `m` of `n` is set, so equal polynomials force
equal bit patterns.
-/
lemma natToBinaryPoly_inj : Function.Injective natToBinaryPoly := by
  intro a b h
  apply Nat.eq_of_testBit_eq
  intro m
  have hcoeff : (natToBinaryPoly a).coeff m = (natToBinaryPoly b).coeff m :=
    congrArg (fun p => p.coeff m) h
  simp only [natToBinaryPoly_coeff] at hcoeff
  by_cases ha : a.testBit m
  · by_cases hb : b.testBit m
    · exact ha.trans hb.symm
    · simp [ha, hb] at hcoeff
  · by_cases hb : b.testBit m
    · simp [ha, hb] at hcoeff
    · exact (Bool.eq_false_iff.mpr ha).trans (Bool.eq_false_iff.mpr hb).symm

/-- `natToBinaryPoly 1 = 1`. -/
lemma natToBinaryPoly_one : natToBinaryPoly 1 = 1 := by
  ext m; simp only [natToBinaryPoly_coeff, coeff_one]
  cases m with
  | zero => decide
  | succ n =>
    have htb : Nat.testBit 1 (n + 1) = false :=
      Nat.testBit_eq_false_of_lt (Nat.one_lt_pow (by omega) (by norm_num))
    simp [htb]

end spqr.math.gf

/-!
## Characteristic-2 facts in `BinaryPoly`

The two lemmas below record that `BinaryPoly` has characteristic `2`, in the form `-a = a` and `a -
b = a + b`. They live in the root namespace under the `BinaryPoly` prefix so that dot notation is
available on elements of `BinaryPoly`.
-/

/-- In characteristic `2`, negation is the identity on `BinaryPoly`. -/
lemma BinaryPoly.neg_eq (a : BinaryPoly) : -a = a := CharTwo.neg_eq a

/-- In characteristic `2`, subtraction in `BinaryPoly` agrees with addition. -/
lemma BinaryPoly.sub_eq_add (a b : BinaryPoly) : a - b = a + b := CharTwo.sub_eq_add a b
