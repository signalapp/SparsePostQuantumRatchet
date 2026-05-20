/-
Copyright 2026 The Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Hoang Le Truong
-/
import Spqr.Code.Funs
import Spqr.Specs.Encoding.Gf.Reduce.ReduceFromByte

open Aeneas Aeneas.Std Result Polynomial spqr.math.gf

namespace spqr.encoding.gf.reduce

@[step]
theorem reduce_bytes_loop_spec
    (out : Array U16 256#usize) (i : Usize)
    (hi : i.val ≤ 256)
    (h_inv : ∀ (j : Usize) (_ : j < i), out[j]! = reduceByteTable j) :
    reduce_bytes_loop out i ⦃ (result : Array U16 256#usize) =>
      ∀ (j : Usize) (_ : j.val < 256), result[j]! = reduceByteTable j ⦄ := by
  unfold reduce_bytes_loop
  apply loop.spec_decr_nat
    (measure := fun (p : (Array U16 256#usize) × Usize) => 256 - p.2.val)
    (inv := fun (p : (Array U16 256#usize) × Usize) =>
      p.2.val ≤ 256 ∧ ∀ (j : Usize) (_ : j < p.2), p.1[j]! = reduceByteTable j)
  · intro ⟨out', i'⟩ ⟨hi'_bound, h_inv'⟩
    unfold reduce_bytes_loop.body
    by_cases hLt : i' < 256#usize
    · step*
      refine ⟨by scalar_tac, fun j hj => ?_, by scalar_tac⟩
      by_cases hjne : j = i'
      · simp_all [UScalar.cast_val_eq]
      · simp_lists; grind
    · grind
  · exact ⟨hi, h_inv⟩

/--
**Spec theorem for `spqr::encoding::gf::reduce::reduce_bytes`**

Builds the 256-entry reduction lookup table: for every index `j < 256`, `result[j].val =
reduceByteTable j`.
-/
@[step]
theorem reduce_bytes_spec_nat :
    reduce_bytes ⦃ (result : Array U16 256#usize) =>
      ∀ (j : Usize) (_ :j.val < 256), result[j]! = reduceByteTable j ⦄ := by
  unfold reduce_bytes
  step*

/-! ## Full-range polynomial correctness of the reduction table -/

private def reduceByteLoopFull (a out : Nat) : (n : Nat) → Nat × Nat
  | 0     => (a, out)
  | n + 1 =>
    if a.testBit n then
      let ps := 0x1100b <<< n
      reduceByteLoopFull ((a ^^^ (ps >>> 16)) % 256) (out ^^^ ps) n
    else
      reduceByteLoopFull a out n

private lemma reduceByteLoopFull_snd_eq (a out n : Nat) :
    (reduceByteLoopFull a out n).2 = reduceFromByteLoopSpec a out n := by
  induction n generalizing a out with
  | zero => rfl
  | succ n ih =>
    simp only [reduceByteLoopFull, reduceFromByteLoopSpec]
    split <;> exact ih _ _

private lemma xor_lt_256 (a b : Nat) (ha : a < 256) (hb : b < 256) : a ^^^ b < 256 := by
  have tb : ∀ x, x < 256 → ∀ j, 8 ≤ j → x.testBit j = false := fun x hx j hj =>
    Nat.testBit_eq_false_of_lt (calc x < 256 := hx
      _ = 2 ^ 8 := by norm_num
      _ ≤ 2 ^ j := Nat.pow_le_pow_right (by norm_num) hj)
  apply Nat.lt_of_testBit 8
  · grind
  · decide
  · intro j hj
    simp [Nat.testBit_xor, tb a ha j (by omega), tb b hb j (by omega),
      Nat.testBit_eq_false_of_lt (show 256 < 2 ^ j from
        calc (256 : Nat) = 2 ^ 8 := by norm_num
          _ < 2 ^ j := Nat.pow_lt_pow_right (by norm_num) (by omega))]

private lemma reduceByteLoopFull_inv (a out n : Nat) (ha : a < 256) :
    (natToBinaryPoly ((reduceByteLoopFull a out n).2 % 2 ^ 16) +
     natToBinaryPoly (reduceByteLoopFull a out n).1 * X ^ 16) %ₘ polyGF2 =
    (natToBinaryPoly (out % 2 ^ 16) + natToBinaryPoly a * X ^ 16) %ₘ polyGF2 := by
  induction n generalizing a out with
  | zero => simp [reduceByteLoopFull]
  | succ n ih =>
    simp only [reduceByteLoopFull]
    split_ifs with htb
    · have hn_le : n ≤ 7 := by
        by_contra hlt; push Not at hlt
        have := Nat.testBit_eq_false_of_lt (calc a < 256 := ha
          _ = 2 ^ 8 := by norm_num
          _ ≤ 2 ^ n := Nat.pow_le_pow_right (by norm_num) (by omega))
        simp_all
      set ps := 0x1100b <<< n with hps_def
      have hps_hi_lt : ps >>> 16 < 256 := by unfold ps; interval_cases n <;> decide
      have ha'_lt : a ^^^ (ps >>> 16) < 256 := xor_lt_256 a (ps >>> 16) ha hps_hi_lt
      have ha'_eq : (a ^^^ (ps >>> 16)) % 256 = a ^^^ (ps >>> 16) := Nat.mod_eq_of_lt ha'_lt
      have hpoly_ps : natToBinaryPoly ps = polyGF2 * X ^ n := by
        unfold ps; simp [natToBinaryPoly_shiftLeft, natToBinaryPoly_polyGF2]
      have hxor_mod : ∀ p q : Nat, (p ^^^ q) % 2 ^ 16 = p % 2 ^ 16 ^^^ q % 2 ^ 16 :=
        fun p q => Nat.eq_of_testBit_eq fun i => by
          simp only [Nat.testBit_xor, Nat.testBit_mod_two_pow]; by_cases hi : i < 16 <;> simp [hi]
      have hrw : natToBinaryPoly ((out ^^^ ps) % 2 ^ 16) +
                 natToBinaryPoly (a ^^^ ps >>> 16) * X ^ 16 =
                 (natToBinaryPoly (out % 2 ^ 16) + natToBinaryPoly a * X ^ 16) +
                 polyGF2 * X ^ n := by
        rw [hxor_mod, natToBinaryPoly_xor, natToBinaryPoly_xor, add_mul,
            ← hpoly_ps, natToBinaryPoly_split ps 16]
        ring
      simp only [ha'_eq]
      rw [ih _ _ ha'_lt, hrw, Polynomial.add_modByMonic,
          (Polynomial.modByMonic_eq_zero_iff_dvd polyGF2_monic).mpr
          (dvd_mul_right polyGF2 _), add_zero]
    · exact ih a out ha

private lemma reduceByteLoopFull_carry_zero (k : Nat) (hk : k < 256) :
    (reduceByteLoopFull k 0 8).1 = 0 := by
  have h : ∀ k' : Fin 256, (reduceByteLoopFull k'.val 0 8).1 = 0 := by decide
  exact h ⟨k, hk⟩

theorem reduceByteTable_eq_poly_full (k : Nat) (hk : k < 256) :
    natToBinaryPoly (reduceByteTable k) =
      (natToBinaryPoly k * X ^ 16) %ₘ polyGF2 := by
  unfold reduceByteTable
  rw [← reduceByteLoopFull_snd_eq]
  have hinv := reduceByteLoopFull_inv k 0 8 hk
  simp only [Nat.zero_mod, natToBinaryPoly_zero, zero_add] at hinv
  simp only [reduceByteLoopFull_carry_zero k hk, natToBinaryPoly_zero, zero_mul, add_zero] at hinv
  set A := natToBinaryPoly ((reduceByteLoopFull k 0 8).2 % 2 ^ 16)
  have hA_deg : A.natDegree < 16 := by
    rcases eq_or_ne A 0 with heq | hne
    · simp [heq]
    rw [Polynomial.natDegree_lt_iff_degree_lt hne, Polynomial.degree_lt_iff_coeff_zero]
    intro m hm
    simp only [A, natToBinaryPoly_coeff]
    exact if_neg (Bool.not_eq_true _ ▸ Nat.testBit_eq_false_of_lt
      (Nat.lt_of_lt_of_le (Nat.mod_lt _ (by norm_num)) (Nat.pow_le_pow_right (by norm_num) hm)))
  have hA_self : A %ₘ polyGF2 = A := by
    have : A /ₘ polyGF2 = 0 := (Polynomial.divByMonic_eq_zero_iff polyGF2_monic).mpr
      (lt_of_le_of_lt Polynomial.degree_le_natDegree (by
        rw [Polynomial.degree_eq_natDegree polyGF2_monic.ne_zero, polyGF2_natDegree]
        exact_mod_cast hA_deg))
    grind [Polynomial.modByMonic_add_div]
  rwa [hA_self] at hinv

/--
**Spec theorem for `spqr::encoding::gf::reduce::reduce_bytes`**

GF(2)[X] polynomial correctness: for every index `j < 256`, the table entry satisfies
`natToBinaryPoly result[j].val = (natToBinaryPoly j * X^16) %ₘ polyGF2`.
-/
@[step]
theorem reduce_bytes_spec :
    reduce_bytes ⦃ (result : Array U16 256#usize) =>
      ∀ (j : Usize) (_: j.val < 256),
        natToBinaryPoly result[j]! = (natToBinaryPoly j * X ^ 16) %ₘ polyGF2 ⦄ := by
  apply WP.spec_mono reduce_bytes_spec_nat
  intro result hres j hj
  have := reduceByteTable_eq_poly_full j hj
  rw[← this]
  have := hres j hj
  rw[this]

end spqr.encoding.gf.reduce
