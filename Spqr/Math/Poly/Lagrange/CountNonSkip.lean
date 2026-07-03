/-
Copyright 2026 The Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE-APACHE.
Authors: Hoang Le Truong
-/
import Spqr.Math.Poly.Basic.Defs

/-!
# Counting non-skip iterations in the Lagrange basis loop

`countNonSkip pi_x pts start` counts the number of indices `k ∈ [start, pts.length)`
with `pi_x.value ≠ pts[k].x.value`.  This is the number of *update* iterations
(as opposed to *skip* iterations) that the inner loop of
`PolyConst::lagrange_interpolate_pt` will execute starting from index `start`.

The count is used to establish the degree bound
`p.degree + countNonSkip pi.x (pts.take N) j < N`,
which is the key loop invariant ensuring the polynomial fits in the `PolyConst N` array.

## Main definitions

* `countNonSkip` — the recursive count.

## Main statements

* `countNonSkip_ge` — out-of-range index gives `0`.
* `countNonSkip_skip` — one-step skip unfolding (count unchanged).
* `countNonSkip_accum` — one-step accumulate unfolding (count drops by `1`).
* `countNonSkip_le_length_sub` — trivial bound `countNonSkip ≤ pts.length − start`.
* `countNonSkip_add_one_le_of_skip` — strict bound when a skip index exists.
* `countNonSkip_le_of_skip_exists` — bound when at least one skip exists in `[0, m)`.
-/
open spqr.encoding.gf

namespace spqr.encoding.polynomial.PolyConst.lagrange_interpolate_pt_loop

/-! ## Definition and basic unfolding lemmas -/

/-- **Count of non-skip indices**: number of `k ∈ [start, pts.length)` with
`pi_x.value ≠ pts[k].x.value`. -/
def countNonSkip (pi_x : GF16) (pts : List Pt) (start : Nat) : Nat :=
  if h : start < pts.length then
    (if pi_x.value = pts[start].x.value then 0 else 1) +
      countNonSkip pi_x pts (start + 1)
  else 0
termination_by pts.length - start

/-- When `start ≥ pts.length`, the count is `0`. -/
@[simp]
lemma countNonSkip_ge (pi_x : GF16) (pts : List Pt) (start : Nat)
    (h : pts.length ≤ start) :
    countNonSkip pi_x pts start = 0 := by
  unfold countNonSkip
  simp [show ¬(start < pts.length) from by omega]

lemma countNonSkip_skip (pi_x : GF16) (pts : List Pt) (start : Nat)
    (h : start < pts.length)
    (heq : pi_x.value = pts[start].x.value) :
    countNonSkip pi_x pts start = countNonSkip pi_x pts (start + 1) := by
  conv_lhs => unfold countNonSkip
  rw [dif_pos h, if_pos heq]
  simp

lemma countNonSkip_accum (pi_x : GF16) (pts : List Pt) (start : Nat)
    (h : start < pts.length)
    (hne : pi_x.value ≠ pts[start].x.value) :
    countNonSkip pi_x pts start = 1 + countNonSkip pi_x pts (start + 1) := by
  conv_lhs => unfold countNonSkip
  rw [dif_pos h, if_neg hne]

lemma countNonSkip_le_length_sub (pi_x : GF16) (pts : List Pt) (start : Nat) :
    countNonSkip pi_x pts start ≤ pts.length - start := by
  by_cases h_lt : start < pts.length
  · have ih := countNonSkip_le_length_sub pi_x pts (start + 1)
    by_cases h_eq : pi_x.value = (pts[start]).x.value
    · rw [countNonSkip_skip pi_x pts start h_lt h_eq]; omega
    · rw [countNonSkip_accum pi_x pts start h_lt h_eq]; omega
  · rw [countNonSkip_ge pi_x pts start (by omega)]; omega
termination_by pts.length - start

lemma countNonSkip_add_one_le_of_skip (pi_x : GF16) (pts : List Pt) (start i : Nat)
    (h_start_le : start ≤ i) (h_i_lt : i < pts.length)
    (h_skip : pi_x.value = pts[i].x.value) :
    countNonSkip pi_x pts start + 1 ≤ pts.length - start := by
  by_cases h_eq_si : start = i
  · subst h_eq_si
    rw [countNonSkip_skip pi_x pts start h_i_lt h_skip]
    have := countNonSkip_le_length_sub pi_x pts (start + 1)
    omega
  · have h_start_lt_i : start < i := by omega
    have h_start_lt : start < pts.length := by omega
    have ih := countNonSkip_add_one_le_of_skip pi_x pts (start + 1) i
      (by omega) h_i_lt h_skip
    by_cases h_eq : pi_x.value = (pts.get ⟨start, h_start_lt⟩).x.value
    · rw [countNonSkip_skip pi_x pts start h_start_lt h_eq]; omega
    · rw [countNonSkip_accum pi_x pts start h_start_lt h_eq]; omega
termination_by i - start

theorem countNonSkip_le_of_skip_exists (pi_x : GF16) (pts : List Pt) (m : Nat)
    (h_m_le : pts.length ≤ m)
    (i : Nat) (hi : i < m)
    (h_skip : ∀ (h : i < pts.length),
      pi_x.value = pts[i].x.value) :
    countNonSkip pi_x pts 0 ≤ m - 1 := by
  by_cases h_i : i < pts.length
  · have h := countNonSkip_add_one_le_of_skip pi_x pts 0 i (Nat.zero_le _) h_i (h_skip h_i)
    omega
  · have h := countNonSkip_le_length_sub pi_x pts 0
    omega

end spqr.encoding.polynomial.PolyConst.lagrange_interpolate_pt_loop
