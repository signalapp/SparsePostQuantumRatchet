/-
Copyright (c) 2026 The Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE-APACHE.
Authors: Alessandro D'Angelo
-/
import Spqr.Math.Poly.Lagrange.EvalAtNode
import Mathlib.LinearAlgebra.Lagrange

open Aeneas Polynomial

namespace spqr.encoding.polynomial

theorem sum_scaledLagrangeBasis_eq_interpolate {N : Std.Usize} (hN : N.val ≤ 2 ^ 16)
    (y : Fin N.val → GF216) :
    (∑ k : Fin N.val,
        Polynomial.C (y k) * scaledLagrangeBasis N k.val)
      = Lagrange.interpolate Finset.univ
          (fun m : Fin N.val => Nat.toGF216 m.val) y := by
  classical
  have hinj : Function.Injective (fun m : Fin N.val => Nat.toGF216 m.val) := by
    intro a b hab
    exact Fin.ext (Nat.toGF216_injOn
      (lt_of_lt_of_le a.isLt hN) (lt_of_lt_of_le b.isLt hN) hab)
  refine Lagrange.eq_interpolate_of_eval_eq y hinj.injOn ?_ ?_
  · refine (Polynomial.degree_sum_le Finset.univ _).trans_lt ?_
    rw [Finset.card_univ, Fintype.card_fin, Nat.cast_withBot,
      Finset.sup_lt_iff (WithBot.bot_lt_coe N.val)]
    intro k hk
    by_cases hy : y k = 0
    · simp [hy, WithBot.bot_lt_coe]
    · rw [Polynomial.degree_C_mul hy]
      exact scaledLagrangeBasis_degree_lt k.isLt
  · intro m _
    simp only [Polynomial.eval_finsetSum, Polynomial.eval_mul, Polynomial.eval_C]
    rw [Finset.sum_eq_single m]
    · rw [scaledLagrangeBasis_eval_node hN m.isLt m.isLt, if_pos rfl, mul_one]
    · intro k hk hkm
      rw [scaledLagrangeBasis_eval_node hN k.isLt m.isLt,
        if_neg (fun h => hkm (Fin.ext h)), mul_zero]
    · simp

end spqr.encoding.polynomial
