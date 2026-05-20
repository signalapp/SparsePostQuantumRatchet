/-
Copyright 2026 The Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Hoang Le Truong
-/
import Mathlib.Data.Nat.Bitwise
import Mathlib.Tactic.IntervalCases
import Spqr.Math.Gf2Poly.Basic

/-!
# Computable Nat-level representation of `BinaryPoly`

Bit-pattern arithmetic on `Nat` (`natBinaryPolyModAux`, `natBinaryPolyMod`,
`natBinaryPolyNoDivisorOfDeg`) together with round-trip lemmas tying the `Nat` representation to
`natToBinaryPoly`.

This module provides the computational backbone for verifying irreducibility of specific binary
polynomials: the `decide`-friendly functions operate on natural numbers, and the bridge lemmas
connect their results back to the abstract polynomial ring `BinaryPoly = (ZMod 2)[X]`.
-/

open Polynomial

namespace spqr.math.gf

/-! ### Computable binary polynomial arithmetic on `Nat` -/

/--
One step of binary polynomial long-division: if the leading term of `a` can be cancelled by a shift
of `b`, XOR to cancel it.
-/
private def natBinaryPolyModAux (b : Nat) : Nat → Nat → Nat
  | a, 0       => a
  | a, fuel + 1 =>
    if b ≤ 1 then (if b = 1 then 0 else a)
    else if a.log2 < b.log2 then a
    else natBinaryPolyModAux b (a ^^^ (b <<< (a.log2 - b.log2))) fuel

/--
Binary polynomial remainder: `natBinaryPolyMod a b` computes `a mod b` where `a` and `b` are
natural-number encodings of binary polynomials.
-/
def natBinaryPolyMod (a b : Nat) : Nat := natBinaryPolyModAux b a (a + 1)

private def natBinaryPolyNoDivisorOfDeg (n d : Nat) : Bool :=
  (List.range (2 ^ d)).all fun lower => natBinaryPolyMod n (2 ^ d + lower) != 0

/-! ### Bridge lemmas between `Nat` arithmetic and `natToBinaryPoly` -/

private lemma natBinaryPolyModAux_preserves_dvd (b a fuel : Nat) (hb : b ≥ 2) :
    natToBinaryPoly b ∣
      natToBinaryPoly a - natToBinaryPoly (natBinaryPolyModAux b a fuel) := by
  induction fuel generalizing a with
  | zero => simp [natBinaryPolyModAux, sub_self]
  | succ n ih =>
    simp only [natBinaryPolyModAux, show ¬(b ≤ 1) from by omega, ↓reduceIte]
    split
    · simp [sub_self]
    · rename_i hlog
      push Not at hlog
      set shift := a.log2 - b.log2
      set a' := a ^^^ (b <<< shift)
      have hstep : natToBinaryPoly a - natToBinaryPoly a' =
          natToBinaryPoly b * X ^ shift := by
        have h1 : natToBinaryPoly a' = natToBinaryPoly a + natToBinaryPoly b * X ^ shift := by
          change natToBinaryPoly (a ^^^ (b <<< shift)) = _
          rw [natToBinaryPoly_xor, natToBinaryPoly_shiftLeft]
        have haa : ∀ (p : BinaryPoly), p + p = 0 := fun p =>
          (BinaryPoly.sub_eq_add p p).symm.trans (sub_self p)
        calc natToBinaryPoly a - natToBinaryPoly a'
            = natToBinaryPoly a + natToBinaryPoly a' := BinaryPoly.sub_eq_add ..
          _ = natToBinaryPoly a + (natToBinaryPoly a + natToBinaryPoly b * X ^ shift) := by rw [h1]
          _ = (natToBinaryPoly a + natToBinaryPoly a) + natToBinaryPoly b * X ^ shift := by ring
          _ = 0 + natToBinaryPoly b * X ^ shift := by rw [haa]
          _ = natToBinaryPoly b * X ^ shift := by ring
      have ih' := ih a'
      have htelescope : natToBinaryPoly a -
            natToBinaryPoly (natBinaryPolyModAux b a' n) =
          (natToBinaryPoly a - natToBinaryPoly a') +
          (natToBinaryPoly a' -
            natToBinaryPoly (natBinaryPolyModAux b a' n)) := by ring
      rw [htelescope, hstep]
      exact dvd_add (dvd_mul_right _ _) ih'

private lemma natBinaryPolyModAux_log2_lt (b a fuel : Nat) (hb : b ≥ 2)
    (hfuel : a.log2 + 1 ≤ b.log2 + fuel) :
    natBinaryPolyModAux b a fuel = 0 ∨
      (natBinaryPolyModAux b a fuel).log2 < b.log2 := by
  induction fuel generalizing a with
  | zero =>
    simp [natBinaryPolyModAux]
    omega
  | succ n ih =>
    simp only [natBinaryPolyModAux, show ¬(b ≤ 1) from by omega, ↓reduceIte]
    split
    · rename_i hlt
      rcases Nat.eq_zero_or_pos a with rfl | ha
      · left
        rfl
      · right
        exact hlt
    · rename_i hlog
      push Not at hlog
      set shift := a.log2 - b.log2
      set a' := a ^^^ (b <<< shift)
      have ha_pos : a ≥ 2 := by
        have hb_log2 : 1 ≤ b.log2 := (Nat.le_log2 (by omega)).mpr (by omega)
        have h1 : 1 ≤ a.log2 := le_trans hb_log2 hlog
        have ha_ne : a ≠ 0 := by
          intro heq
          subst heq
          simp [Nat.log2_zero] at h1
        exact (Nat.le_log2 ha_ne).mp h1
      have hlog2_lt : a'.log2 < a.log2 := by
        by_cases ha'_zero : a' = 0
        · simp [ha'_zero, Nat.log2_zero]
          have : 1 ≤ a.log2 := (Nat.le_log2 (by omega)).mpr (by omega)
          omega
        · rw [Nat.log2_lt ha'_zero]
          apply Nat.lt_of_testBit a.log2
          · change (a ^^^ (b <<< shift)).testBit a.log2 = false
            rw [Nat.testBit_xor, Nat.testBit_shiftLeft]
            have h1 : a.testBit a.log2 = true := Nat.testBit_log2 (by omega)
            have h2 : decide (shift ≤ a.log2) = true := decide_eq_true_eq.mpr (by omega)
            have h3 : a.log2 - shift = b.log2 := by omega
            have h4 : b.testBit b.log2 = true := Nat.testBit_log2 (by omega)
            simp [h1, h2, h3, h4]
          · rw [← Nat.one_shiftLeft, Nat.testBit_shiftLeft]
            simp
          · intro j hj
            change (a ^^^ (b <<< shift)).testBit j = (2 ^ a.log2).testBit j
            rw [Nat.testBit_xor, Nat.testBit_shiftLeft,
                ← Nat.one_shiftLeft, Nat.testBit_shiftLeft]
            have haj : a.testBit j = false :=
              Nat.testBit_eq_false_of_lt ((Nat.log2_lt (show a ≠ 0 by omega)).mp (by omega))
            have hbsj : b.testBit (j - shift) = false :=
              Nat.testBit_eq_false_of_lt ((Nat.log2_lt (show b ≠ 0 by omega)).mp (by omega))
            have h1j : (1 : Nat).testBit (j - a.log2) = false :=
              Nat.testBit_eq_false_of_lt (Nat.one_lt_pow (by omega) (by norm_num))
            simp [haj, show shift ≤ j from by omega, hbsj,
                  show a.log2 ≤ j from by omega, h1j]
      apply ih
      omega

/-! ### Degree and monicity of `natToBinaryPoly` -/

lemma natToBinaryPoly_natDegree_eq_log2 (b : Nat) (hb : b ≥ 2) :
    (natToBinaryPoly b).natDegree = b.log2 := by
  have hb_ne : b ≠ 0 := by omega
  apply le_antisymm
  · apply Polynomial.natDegree_le_of_degree_le
    rw [Polynomial.degree_le_iff_coeff_zero]
    intro m hm
    rw [natToBinaryPoly_coeff]
    have hm' : b.log2 < m := by exact_mod_cast hm
    simp [Nat.testBit_eq_false_of_lt ((Nat.log2_lt hb_ne).mp hm')]
  · apply Polynomial.le_natDegree_of_ne_zero
    rw [natToBinaryPoly_coeff]
    simp [Nat.testBit_log2 hb_ne]

private lemma natToBinaryPoly_monic_of_ge_two (b : Nat) (hb : b ≥ 2) :
    (natToBinaryPoly b).Monic := by
  unfold Polynomial.Monic Polynomial.leadingCoeff
  rw [natToBinaryPoly_natDegree_eq_log2 b hb, natToBinaryPoly_coeff]
  simp [Nat.testBit_log2 (show b ≠ 0 by omega)]

/-! ### Non-divisibility from `natBinaryPolyMod` -/

lemma natBinaryPolyMod_ne_zero_of_not_dvd (a b : Nat) (hb : b ≥ 2)
    (hmod : natBinaryPolyMod a b ≠ 0) :
    ¬ (natToBinaryPoly b ∣ natToBinaryPoly a) := by
  intro ⟨q, hq⟩
  set r := natBinaryPolyMod a b with hr_def
  have hdvd_diff := natBinaryPolyModAux_preserves_dvd b a (a + 1) hb
  have hdvd_r : natToBinaryPoly b ∣ natToBinaryPoly r := by
    have : natToBinaryPoly b ∣ natToBinaryPoly a := ⟨q, hq⟩
    have : natToBinaryPoly b ∣ natToBinaryPoly a - natToBinaryPoly r := hdvd_diff
    exact (dvd_add_right this).mp ⟨q, by rw [hq]; ring⟩
  obtain ⟨s, hs⟩ := hdvd_r
  have hr_ne : natToBinaryPoly r ≠ 0 := by
    intro h
    have heq : natToBinaryPoly r = natToBinaryPoly 0 := by
      rw [h, natToBinaryPoly_zero]
    exact hmod (natToBinaryPoly_inj heq)
  have hs_ne : s ≠ 0 := by
    rintro rfl
    simp only [mul_zero] at hs
    exact hr_ne hs
  have hmonic_b : (natToBinaryPoly b).Monic := natToBinaryPoly_monic_of_ge_two b hb
  have hdeg : (natToBinaryPoly b * s).natDegree = (natToBinaryPoly b).natDegree + s.natDegree :=
    hmonic_b.natDegree_mul' hs_ne
  have hdeg_b : (natToBinaryPoly b).natDegree = b.log2 :=
    natToBinaryPoly_natDegree_eq_log2 b hb
  have hlower : b.log2 ≤ (natToBinaryPoly r).natDegree := by
    rw [hs, hdeg, hdeg_b]
    omega
  have hupper : (natToBinaryPoly r).natDegree ≤ r.log2 := by
    apply Polynomial.natDegree_le_of_degree_le
    rw [Polynomial.degree_le_iff_coeff_zero]
    intro m hm
    rw [natToBinaryPoly_coeff]
    have hm' : r.log2 < m := by exact_mod_cast hm
    simp [Nat.testBit_eq_false_of_lt ((Nat.log2_lt hmod).mp hm')]
  have hlog2_lt : r.log2 < b.log2 := by
    have hfuel : a.log2 + 1 ≤ b.log2 + (a + 1) := by
      have hb_log2 : 1 ≤ b.log2 := (Nat.le_log2 (by omega)).mpr (by omega)
      suffices a.log2 ≤ a by omega
      rcases Nat.eq_zero_or_pos a with rfl | ha_pos
      · simp
      · suffices a < 2 ^ (a + 1) by
          have := (Nat.log2_lt (by omega)).mpr this
          omega
        suffices ∀ n : Nat, n < 2 ^ (n + 1) from this a
        intro n
        induction n with
        | zero => norm_num
        | succ k ih =>
          calc k + 1 ≤ 2 ^ (k + 1) := ih
            _ < 2 ^ (k + 1) + 2 ^ (k + 1) :=
              lt_add_of_pos_right _ (pos_of_gt ih)
            _ = 2 ^ (k + 2) := by ring
    have hbound := natBinaryPolyModAux_log2_lt b a (a + 1) hb hfuel
    change r = 0 ∨ r.log2 < b.log2 at hbound
    rcases hbound with h | h
    · exact absurd h hmod
    · exact h
  omega

/-! ### Surjectivity and monic representation -/

private lemma natToBinaryPoly_two_pow (k : Nat) : natToBinaryPoly (2 ^ k) = X ^ k := by
  rw [show (2 : Nat) ^ k = 1 <<< k from (Nat.one_shiftLeft k).symm,
      natToBinaryPoly_shiftLeft, natToBinaryPoly_one, one_mul]

lemma natToBinaryPoly_surjective (q : BinaryPoly) : ∃ n, natToBinaryPoly n = q := by
  induction q using Polynomial.induction_on' with
  | add p r ih_p ih_r =>
    obtain ⟨np, rfl⟩ := ih_p
    obtain ⟨nr, rfl⟩ := ih_r
    exact ⟨np ^^^ nr, natToBinaryPoly_xor np nr⟩
  | monomial n a =>
    fin_cases a
    · refine ⟨0, ?_⟩
      simp only [natToBinaryPoly_zero]
      exact (monomial_zero_right n).symm
    · refine ⟨2 ^ n, ?_⟩
      rw [natToBinaryPoly_two_pow]
      simp [X_pow_eq_monomial]
      rfl

lemma exists_natToBinaryPoly_eq_of_one_le_natDegree (q : BinaryPoly)
    (hd : 1 ≤ q.natDegree) : ∃ b, b ≥ 2 ∧ natToBinaryPoly b = q := by
  obtain ⟨n, hn⟩ := natToBinaryPoly_surjective q
  refine ⟨n, ?_, hn⟩
  by_contra h
  push Not at h
  interval_cases n
  · simp only [natToBinaryPoly_zero] at hn
    rw [← hn] at hd
    simp at hd
  · rw [← hn] at hd; simp [natToBinaryPoly_one] at hd

/-! ### No small divisors of `0x1100b` -/

private lemma natBinaryPolyNoDivisorOfDeg_POLY (d : Nat) (hd : 1 ≤ d) (hd8 : d ≤ 8) :
    natBinaryPolyNoDivisorOfDeg 0x1100b d = true := by
  interval_cases d <;> decide

lemma natBinaryPolyMod_POLY_ne_zero (d : Nat) (hd : 1 ≤ d) (hd8 : d ≤ 8)
    (lower : Nat) (hlower : lower < 2 ^ d) :
    natBinaryPolyMod 0x1100b (2 ^ d + lower) ≠ 0 := by
  have hstep := natBinaryPolyNoDivisorOfDeg_POLY d hd hd8
  simp only [natBinaryPolyNoDivisorOfDeg, List.all_eq_true, List.mem_range,
    bne_iff_ne, ne_eq] at hstep
  exact hstep lower hlower

end spqr.math.gf
