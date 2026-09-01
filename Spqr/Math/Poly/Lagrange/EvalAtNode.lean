/-
Copyright (c) 2026 The Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE-APACHE.
Authors: Alessandro D'Angelo
-/
import Spqr.Math.Gf16.Equiv
import Spqr.Math.Poly.Lagrange.CompletePoints

open Aeneas Aeneas.Std Polynomial
open spqr.encoding.gf
open spqr.encoding.polynomial.PolyConst.lagrange_interpolate_pt_loop
open spqr.math.gf

namespace spqr.encoding.polynomial

private lemma GF16.toGF216_ne_of_value_ne {a b : GF16} (h : a.value ≠ b.value) :
    a.toGF216 ≠ b.toGF216 := by
  intro hab
  apply h
  apply UScalar.eq_of_val_eq
  unfold GF16.toGF216 at hab
  exact Nat.toGF216_injOn a.value.hBounds b.value.hBounds hab

private theorem eval_condProdLinearFactors_eq_lagrangeDenomProd
    (pi : GF16) (pts : List Pt) (start : Nat) :
    (condProdLinearFactors pi pts start).eval pi.toGF216 =
      lagrangeDenomProd pi pts start := by
  by_cases hstart : start < pts.length
  · have hdec : pts.length - (start + 1) < pts.length - start := by omega
    by_cases heq : pi.value = (pts[start]).x.value
    · rw [condProdLinearFactors_skip pi pts start hstart heq,
          lagrangeDenomProd_skip pi pts start hstart heq]
      exact eval_condProdLinearFactors_eq_lagrangeDenomProd pi pts (start + 1)
    · rw [condProdLinearFactors_accum pi pts start hstart heq,
          lagrangeDenomProd_accum pi pts start hstart heq,
          eval_mul, eval_sub, eval_X, eval_C,
          eval_condProdLinearFactors_eq_lagrangeDenomProd]
      simp only [List.get_eq_getElem]
  · rw [condProdLinearFactors_ge pi pts start (by omega),
        lagrangeDenomProd_eq_one_of_le pi pts start (by omega), eval_one]
termination_by pts.length - start
decreasing_by all_goals exact hdec

private theorem lagrangeDenomProd_ne_zero
    (pi : GF16) (pts : List Pt) (start : Nat) :
    lagrangeDenomProd pi pts start ≠ 0 := by
  by_cases hstart : start < pts.length
  · have hdec : pts.length - (start + 1) < pts.length - start := by omega
    by_cases heq : pi.value = (pts[start]).x.value
    · rw [lagrangeDenomProd_skip pi pts start hstart heq]
      exact lagrangeDenomProd_ne_zero pi pts (start + 1)
    · rw [lagrangeDenomProd_accum pi pts start hstart heq]
      exact mul_ne_zero (sub_ne_zero.mpr (GF16.toGF216_ne_of_value_ne heq))
        (lagrangeDenomProd_ne_zero pi pts (start + 1))
  · rw [lagrangeDenomProd_eq_one_of_le pi pts start (by omega)]
    exact one_ne_zero
termination_by pts.length - start
decreasing_by all_goals exact hdec

private theorem eval_condProdLinearFactors_eq_zero_of_value_ne
    (pi : GF16) (pts : List Pt) (start m : Nat)
    (hstart : start ≤ m) (hm : m < pts.length)
    (hne : pi.value ≠ (pts[m]).x.value) :
    (condProdLinearFactors pi pts start).eval (pts[m]).x.toGF216 = 0 := by
  have hstart_lt : start < pts.length := by omega
  have hdec : pts.length - (start + 1) < pts.length - start := by omega
  by_cases hsm : start = m
  · subst m
    rw [condProdLinearFactors_accum pi pts start hm hne]
    simp [eval_mul, eval_sub, eval_X, eval_C]
  · by_cases heq : pi.value = (pts[start]).x.value
    · rw [condProdLinearFactors_skip pi pts start hstart_lt heq]
      exact eval_condProdLinearFactors_eq_zero_of_value_ne pi pts (start + 1) m
        (by omega) hm hne
    · rw [condProdLinearFactors_accum pi pts start hstart_lt heq, eval_mul,
          eval_condProdLinearFactors_eq_zero_of_value_ne pi pts (start + 1) m
            (by omega) hm hne, mul_zero]
termination_by pts.length - start
decreasing_by all_goals exact hdec

private theorem natDegree_condProdLinearFactors_le
    (pi : GF16) (pts : List Pt) (start : Nat) :
    (condProdLinearFactors pi pts start).natDegree ≤ pts.length - start := by
  by_cases hstart : start < pts.length
  · have hdec : pts.length - (start + 1) < pts.length - start := by omega
    by_cases heq : pi.value = (pts[start]).x.value
    · rw [condProdLinearFactors_skip pi pts start hstart heq]
      have := natDegree_condProdLinearFactors_le pi pts (start + 1)
      omega
    · rw [condProdLinearFactors_accum pi pts start hstart heq]
      calc
        ((X - C ((pts[start]).x.toGF216)) *
            condProdLinearFactors pi pts (start + 1)).natDegree
            ≤ (X - C ((pts[start]).x.toGF216) : GF216[X]).natDegree +
                (condProdLinearFactors pi pts (start + 1)).natDegree :=
              Polynomial.natDegree_mul_le
        _ ≤ 1 + (pts.length - (start + 1)) := by
              gcongr
              · exact Polynomial.natDegree_X_sub_C _ |>.le
              · exact natDegree_condProdLinearFactors_le pi pts (start + 1)
        _ ≤ pts.length - start := by omega
  · rw [condProdLinearFactors_ge pi pts start (by omega)]
    simp
termination_by pts.length - start
decreasing_by all_goals exact hdec

private theorem natDegree_condProdLinearFactors_lt_of_eq
    (pi : GF16) (pts : List Pt) (start j : Nat)
    (hstart : start ≤ j) (hj : j < pts.length)
    (heqj : pi.value = (pts[j]).x.value) :
    (condProdLinearFactors pi pts start).natDegree < pts.length - start := by
  have hstart_lt : start < pts.length := by omega
  have hdec : pts.length - (start + 1) < pts.length - start := by omega
  by_cases hsj : start = j
  · subst j
    rw [condProdLinearFactors_skip pi pts start hj heqj]
    have := natDegree_condProdLinearFactors_le pi pts (start + 1)
    omega
  · by_cases heq : pi.value = (pts[start]).x.value
    · rw [condProdLinearFactors_skip pi pts start hstart_lt heq]
      have := natDegree_condProdLinearFactors_lt_of_eq pi pts (start + 1) j
        (by omega) hj heqj
      omega
    · rw [condProdLinearFactors_accum pi pts start hstart_lt heq]
      have hrec := natDegree_condProdLinearFactors_lt_of_eq pi pts (start + 1) j
        (by omega) hj heqj
      calc
        ((X - C ((pts[start]).x.toGF216)) *
            condProdLinearFactors pi pts (start + 1)).natDegree
            ≤ (X - C ((pts[start]).x.toGF216) : GF216[X]).natDegree +
                (condProdLinearFactors pi pts (start + 1)).natDegree :=
              Polynomial.natDegree_mul_le
        _ ≤ 1 + (condProdLinearFactors pi pts (start + 1)).natDegree := by
              gcongr
              exact Polynomial.natDegree_X_sub_C _ |>.le
        _ < pts.length - start := by omega
termination_by pts.length - start
decreasing_by all_goals exact hdec

private lemma eval_condProdLinearFactors_eq_zero_of_value_ne_bang
    (pi : GF16) (pts : List Pt) (start m : Nat)
    (hstart : start ≤ m) (hm : m < pts.length)
    (hne : pi.value ≠ (pts[m]!).x.value) :
    (condProdLinearFactors pi pts start).eval (pts[m]!).x.toGF216 = 0 := by
  rw [← List.Inhabited_getElem_eq_getElem! pts m hm] at hne ⊢
  exact eval_condProdLinearFactors_eq_zero_of_value_ne pi pts start m hstart hm hne

private lemma completePoints_take (N : Usize) :
    (completePoints N).val.take N.val = (completePoints N).val := by
  apply List.take_of_length_le
  exact (completePoints N).property.le

private lemma completePoints_x_value {N : Usize} (hN : N.val ≤ 2 ^ 16)
    {i : Nat} (hi : i < N.val) :
    ((completePoints N).val[i]!).x.value.val = i := by
  simp only [global_simps]
  rw [← List.Inhabited_getElem_eq_getElem! _ i (by simp [hi])]
  simp only [List.getElem_map, List.getElem_finRange]
  change (BitVec.ofNat 16 i).toNat = i
  rw [BitVec.toNat_ofNat, Nat.mod_eq_of_lt (lt_of_lt_of_le hi hN)]

private lemma completePoints_x_toGF216 {N : Usize} (hN : N.val ≤ 2 ^ 16)
    {i : Nat} (hi : i < N.val) :
    ((completePoints N).val[i]!).x.toGF216 = Nat.toGF216 i := by
  unfold GF16.toGF216
  rw [completePoints_x_value hN hi]

private lemma completePoints_y_toGF216 {N : Usize} {i : Nat} (hi : i < N.val) :
    ((completePoints N).val[i]!).y.toGF216 = 1 := by
  simp only [global_simps]
  simp [hi, GF16.toGF216, Nat.toGF216, natToBinaryPoly_one]

theorem scaledLagrangeBasis_eval_node {N : Std.Usize} (hN : N.val ≤ 2 ^ 16)
    {j m : ℕ} (hj : j < N.val) (hm : m < N.val) :
    (scaledLagrangeBasis N j).eval (Nat.toGF216 m) = if j = m then 1 else 0 := by
  classical
  by_cases hjm : j = m
  · subst m
    rw [if_pos rfl]
    unfold scaledLagrangeBasis
    simp only [Array.getElem!_Nat_eq, completePoints_take, eval_mul, eval_C]
    rw [← completePoints_x_toGF216 hN hj,
        eval_condProdLinearFactors_eq_lagrangeDenomProd,
        completePoints_y_toGF216 hj, one_mul]
    let d := lagrangeDenomProd ((completePoints N).val[j]!).x
      (completePoints N).val 0
    have hd : d ≠ 0 := lagrangeDenomProd_ne_zero _ _ _
    calc
      d ^ (2 ^ 16 - 2) * d = d ^ (2 ^ 16 - 2 + 1) := (pow_succ d _).symm
      _ = d ^ (2 ^ 16 - 1) :=
        congrArg (fun n : Nat => d ^ n) (by norm_num)
      _ = 1 := by
        simpa only [GF216.card_eq] using FiniteField.pow_card_sub_one_eq_one d hd
  · rw [if_neg hjm]
    unfold scaledLagrangeBasis
    simp only [Array.getElem!_Nat_eq, completePoints_take, eval_mul, eval_C]
    rw [← completePoints_x_toGF216 hN hm]
    have hvalue : ((completePoints N).val[j]!).x.value ≠
        ((completePoints N).val[m]!).x.value := by
      intro h
      have := congrArg UScalar.val h
      rw [completePoints_x_value hN hj, completePoints_x_value hN hm] at this
      exact hjm this
    have hm_pts : m < (completePoints N).val.length := by
      simpa only [(completePoints N).property] using hm
    rw [eval_condProdLinearFactors_eq_zero_of_value_ne_bang _ _ 0 m (by omega)
      hm_pts hvalue, mul_zero]

theorem scaledLagrangeBasis_degree_lt {N : Std.Usize} {j : ℕ} (hj : j < N.val) :
    (scaledLagrangeBasis N j).degree < (N.val : WithBot ℕ) := by
  unfold scaledLagrangeBasis
  simp only [Array.getElem!_Nat_eq, completePoints_take]
  have hj_pts : j < (completePoints N).val.length := by
    simpa only [(completePoints N).property] using hj
  have hget := List.Inhabited_getElem_eq_getElem! (completePoints N).val j hj_pts
  have heqj : ((completePoints N).val[j]!).x.value =
      ((completePoints N).val[j]).x.value := congrArg (fun p => p.x.value) hget.symm
  have hbasis := natDegree_condProdLinearFactors_lt_of_eq
    ((completePoints N).val[j]!).x (completePoints N).val 0 j
    (by omega) hj_pts heqj
  have hdeg :
      (C (((completePoints N).val[j]!).y.toGF216 *
          lagrangeDenomProd ((completePoints N).val[j]!).x
            (completePoints N).val 0 ^ (2 ^ 16 - 2)) *
        condProdLinearFactors ((completePoints N).val[j]!).x
          (completePoints N).val 0).natDegree < N.val :=
    (Polynomial.natDegree_C_mul_le _ _).trans_lt (by
      simpa only [(completePoints N).property, Nat.sub_zero] using hbasis)
  exact Polynomial.degree_le_natDegree.trans_lt (WithBot.coe_lt_coe.mpr hdeg)

end spqr.encoding.polynomial
