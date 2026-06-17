/-
Copyright 2026 The Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE-APACHE.
Authors: Hoang Le Truong
-/
import Spqr.Math.Poly.CharTwo.ToGF216

/-! # Power-vector invariant

Lemmas for maintaining `xs[j].toGF216 = x.toGF216 ^ j` during power-vector construction. -/

open spqr.math.gf spqr.encoding.gf

namespace spqr.encoding.polynomial

theorem div2_add_sum_eq (n : Nat) : n / 2 + (n / 2 + n % 2) = n := by
  have := Nat.div_add_mod n 2
  omega

theorem power_invariant_step
    (x : GF16) (xs : List GF16) (g : GF16)
    (h_ge2 : 2 ≤ xs.length)
    (h_pow : ∀ j < xs.length, (xs[j]!).toGF216 = x.toGF216 ^ j)
    (h_g : g.toGF216 = (xs[xs.length / 2]!).toGF216 *
      (xs[xs.length / 2 + xs.length % 2]!).toGF216) :
    ∀ j < (xs ++ [g]).length, ((xs ++ [g])[j]!).toGF216 = x.toGF216 ^ j := by
  intro j hj
  simp only [List.length_append, List.length_singleton] at hj
  have h_div2_lt : xs.length / 2 < xs.length := Nat.div_lt_self (by omega) (by omega)
  have h_sum_lt : xs.length / 2 + xs.length % 2 < xs.length := by
    have := Nat.div_add_mod xs.length 2; omega
  by_cases hlt : j < xs.length
  · grind
  · have hj_eq : j = xs.length := by omega
    subst hj_eq
    have hlt' : xs.length < (xs ++ [g]).length := by grind
    simp only [List.length_append, List.length_cons, List.length_nil, zero_add,
      lt_add_iff_pos_right, Order.lt_one_iff, getElem!_pos, le_refl, List.getElem_append_right,
      tsub_self, List.getElem_cons_zero]
    rw [h_g, h_pow _ h_div2_lt, h_pow _ h_sum_lt, ← pow_add, div2_add_sum_eq]

theorem initial_power_invariant (x : GF16) :
    ∀ j, j < [GF16.ONE, x].length →
      ([GF16.ONE, x][j]!).toGF216 = x.toGF216 ^ j := by
  intro j hj
  simp only [List.length_cons, List.length_nil] at hj
  interval_cases j
  · simp [GF16.ONE, GF16.toGF216, Nat.toGF216, natToBinaryPoly_one, map_one]
  · simp [pow_one]

end spqr.encoding.polynomial
