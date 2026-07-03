/-
Copyright 2026 The Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE-APACHE.
Authors: Hoang Le Truong
-/
import Spqr.Specs.Encoding.Gf.GF16.ConstDiv
import Spqr.Specs.Encoding.Polynomial.PolyConst.Mult
import Spqr.Specs.Encoding.Gf.GF16.ONE
import Spqr.Specs.Encoding.Polynomial.PolyConst.MultXdiff
import Spqr.Math.Poly.Lagrange.CondProdLinearFactors
import Spqr.Math.Poly.Lagrange.CountNonSkip

/-! # Spec theorem for `PolyConst::lagrange_interpolate_pt`: loop body 0

Specifies one iteration of the `while j < N` loop (lines 380–391) inside
`PolyConst::lagrange_interpolate_pt` (`src/encoding/polynomial.rs`, lines 370–395).

The loop builds `p = ∏_{j ≠ i} (X − pts[j].x)` and `denominator = ∏_{j ≠ i} (pts[i].x − pts[j].x)`.
Each iteration either **skips** (`pi.x.value = pj.x.value`) or **updates** by calling
`mult_xdiff` and `const_mul`.

In GF(2¹⁶), subtraction equals addition (`a − b = a ⊕ b`).

The mathematical definitions `condProdLinearFactors` and `countNonSkip` (with their
unfolding and bound lemmas) live in `Spqr.Math.Poly.Lagrange.CondProdLinearFactors`
and `Spqr.Math.Poly.Lagrange.CountNonSkip` respectively.

**Source**: spqr/src/encoding/polynomial.rs -/

open Aeneas Aeneas.Std Result spqr.encoding.polynomial spqr.encoding.gf Polynomial
open spqr.encoding.polynomial.PolyConst.lagrange_interpolate_pt_loop

namespace spqr.encoding.polynomial.PolyConst.lagrange_interpolate_pt_loop

/-- **Spec theorem for `encoding.polynomial.PolyConst.lagrange_interpolate_pt_loop.body`**:

One iteration of the Lagrange basis loop. Given `pts`, interpolation point `pi`, running
polynomial `p`, running `denominator`, and counter `j`:

• Always succeeds when preconditions hold.
• **Done** (`j ≥ N`): outputs unchanged.
• **Cont** (`j < N`): advances `j`, then either skips (same `pi.x`) or updates `p` via
  `mult_xdiff` and `denominator` via `const_mul`. -/
@[step]
theorem body_spec
    {N : Usize} (pts : Slice Pt) (pi : Pt) (p : PolyConst N) (denominator : GF16) (j : Usize)
    (h_N_pos : 0 < N.val)
    (h_N_le_pts : N ≤ pts.val.length)
    (h_leading : (_ : j < N.val) → pi.x.value ≠ (pts[j]).x.value → p.degree + 1 < N) :
    body pts pi p denominator j ⦃ cf =>
      match cf with
      | ControlFlow.done (pi', p', denominator') =>
          pi' = pi ∧ p' = p ∧ denominator' = denominator ∧ ¬ (j < N)
      | ControlFlow.cont (p1, denominator1, j1) =>
          j < N ∧
          j1 = j.val + 1 ∧
          ∀ (hj : j < pts.length),
            (pi.x.value = pts[j].x.value → p1 = p ∧ denominator1 = denominator) ∧
            (pi.x.value ≠ pts[j].x.value →
            listToGF216Poly p1.coefficients =
              (X - C (pts[j].x.toGF216)) * listToGF216Poly p.coefficients ∧
            denominator1.toGF216 = denominator.toGF216 * (pi.x.toGF216 - pts[j].x.toGF216)) ⦄ := by
  unfold body
  step*

/-! # Spec theorem for `PolyConst::lagrange_interpolate_pt`: loop 0

The `loop` fixed-point wrapper around the body, iterating `j = 0, …, N−1` to build the
unnormalised Lagrange basis polynomial and denominator.

The key precondition is `p.degree + countNonSkip pi.x (pts.take N) j < N`, which is preserved
by each iteration (skip preserves it; update raises degree by 1 and decreases `countNonSkip`
by 1).

**Postconditions** (after all iterations from `j` to `N−1`):
- `p = condProdLinearFactors pi.x (pts.take N) j * p₀`
- `denominator = denominator₀ * lagrangeDenomProd pi.x (pts.take N) j`
- `pi` unchanged.

**Source**: spqr/src/encoding/polynomial.rs -/
@[step]
theorem loop_spec
    {N : Usize} (pts : Slice Pt) (pi : Pt) (p : PolyConst N) (denominator : GF16) (j : Usize)
    (h_N_pos : 0 < N.val)
    (h_N_le_pts : N ≤ pts.val.length)
    (h_j_le_N : j ≤ N)
    (h_degree_bound : p.degree + countNonSkip pi.x (pts.val.take N) j < N) :
    lagrange_interpolate_pt_loop pts pi p denominator j ⦃ result =>
      result.1 = pi ∧
      listToGF216Poly result.2.1.coefficients.val =
          condProdLinearFactors pi.x (pts.val.take N) j * listToGF216Poly p.coefficients ∧
      result.2.2.toGF216 = denominator.toGF216 * lagrangeDenomProd pi.x (pts.val.take N) j ⦄ := by
  unfold lagrange_interpolate_pt_loop
  apply loop.spec_decr_nat
    (measure := fun (state : (PolyConst N) × GF16 × Usize) => N - state.2.2)
    (inv := fun (state : (PolyConst N) × GF16 × Usize) =>
      j ≤ state.2.2 ∧
      state.2.2 ≤ N ∧
      listToGF216Poly state.1.coefficients * condProdLinearFactors pi.x (pts.val.take N) state.2.2 =
          listToGF216Poly p.coefficients * condProdLinearFactors pi.x (pts.val.take N) j ∧
        state.2.1.toGF216 * lagrangeDenomProd pi.x (pts.val.take N) state.2.2 =
          denominator.toGF216 * lagrangeDenomProd pi.x (pts.val.take N) j ∧
        state.1.degree + countNonSkip pi.x (pts.val.take N) state.2.2 < N)
  · rintro ⟨p', d', j'⟩ ⟨hj_ge, hj_le, hpoly_inv, hdenom_inv, hdeg_inv⟩
    have h_leading_for_body :
      (h_jN : j'.val < N) → pi.x.value ≠ (pts[j']).x.value → p'.degree + 1 < N := by
        grind[countNonSkip_accum]
    have h_body := body_spec pts pi p' d' j' h_N_pos h_N_le_pts h_leading_for_body
    apply Aeneas.Std.WP.spec_mono h_body
    intro cf hcf
    cases cf with
    | done result =>  grind [lagrangeDenomProd_eq_one_of_le,  condProdLinearFactors_ge]
    | cont state =>
      obtain ⟨p1, d1, j1⟩ := state
      simp only at hcf
      obtain ⟨h_lt, h_j1_eq, h_cases⟩ := hcf
      have hj_pts : j'.val < pts.val.length := by grind
      obtain ⟨h_skip, h_update⟩ := h_cases hj_pts
      have h_take_get :
          (pts.val.take N.val).get ⟨j'.val, (by grind)⟩ =
            pts.val.get ⟨j'.val, hj_pts⟩ := by
        simp [List.get_eq_getElem, List.getElem_take]
      refine ⟨⟨by grind, by grind, ?_, ?_, ?_⟩, ?_⟩
      · by_cases h_eq : pi.x.value = (pts.val.get ⟨j'.val, hj_pts⟩).x.value
        · grind [condProdLinearFactors_skip]
        · grind [condProdLinearFactors_accum]
      · by_cases h_eq : pi.x.value = (pts.val.get ⟨j'.val, hj_pts⟩).x.value
        · grind[lagrangeDenomProd_skip]
        · grind [lagrangeDenomProd_accum]
      · by_cases h_eq : pi.x.value = (pts.val.get ⟨j'.val, hj_pts⟩).x.value
        · grind [countNonSkip_skip ]
        · obtain ⟨hp_id, _⟩ := h_update h_eq
          have h_cs_acc :
              countNonSkip pi.x (pts.val.take N) j' =
              1 + countNonSkip pi.x (pts.val.take N) (j' + 1) := by
            rw [countNonSkip_accum pi.x (pts.val.take N) j' (by grind)]
            grind
          have h_nd_p1 : p1.degree ≤ 1 + p'.degree := by
            unfold PolyConst.degree
            rw [hp_id]
            calc ((X - C ((pts[j']).x.toGF216)) * listToGF216Poly p'.coefficients.val).natDegree
                ≤ (X - C ((pts[j']).x.toGF216)).natDegree +
                  (listToGF216Poly p'.coefficients).natDegree := Polynomial.natDegree_mul_le
              _ = 1 + (listToGF216Poly p'.coefficients.val).natDegree := by
                  rw [Polynomial.natDegree_X_sub_C]
          grind
      · grind
  · grind

end spqr.encoding.polynomial.PolyConst.lagrange_interpolate_pt_loop

/-! # Spec theorem for
`spqr::encoding::polynomial::{spqr::encoding::polynomial::PolyConst<N>}::lagrange_interpolate_pt`

Computes the i-th scaled Lagrange basis polynomial over GF(2¹⁶) in a fixed-size `PolyConst N`.

Steps: (1) read `pi = pts[i]`, (2) initialise unit polynomial `[ONE, ZERO, …]`, (3) loop to
build `∏_{j≠i}(X − pts[j].x)` and the denominator, (4) Fermat-style division
`pi.y / denominator`, (5) scale via `p.mult(g)`.

Result satisfies:
  `listToGF216Poly result.coefficients =
      C (lagrangeScaleGF216 pi (pts.take N)) * condProdLinearFactors pi.x (pts.take N) 0`

In GF(2¹⁶), subtraction equals addition (`a − b = a ⊕ b`).

**Source**: spqr/src/encoding/polynomial.rs -/


namespace spqr.encoding.polynomial.PolyConst

private lemma listToGF216Poly_replicate_zero_set_one
    (N : Nat) (h_N_pos : 0 < N) :
    listToGF216Poly ((List.replicate N GF16.ZERO).set 0 GF16.ONE) = 1 := by
  ext m
  rw [listToGF216Poly_coeff, Polynomial.coeff_one]
  simp only [List.length_set, List.length_replicate, List.get_eq_getElem]
  cases m
  · simp [h_N_pos, GF16.ONE_toGF216]
  · rename_i n
    rw [if_neg (show n + 1 ≠ 0 from by omega)]
    by_cases hlt : n + 1 < N
    · rw [dif_pos hlt]
      simp only [ne_eq, Nat.right_eq_add, Nat.add_eq_zero_iff, one_ne_zero,
        and_false, not_false_eq_true, List.getElem_set_ne, List.getElem_replicate,
        GF16.ZERO_toGF216]
    · rw [dif_neg hlt]

/-- **Spec theorem for `spqr.encoding.polynomial.PolyConst.lagrange_interpolate_pt`**:

Given `pts` with `N ≤ pts.length` and `i < N`, returns `result : PolyConst N` with:

  `listToGF216Poly result.coefficients =
    C (pts[i].y.toGF216 * (lagrangeDenomProd pts[i].x (pts.take N) 0) ^ (2¹⁶ − 2)) *
        condProdLinearFactors pts[i].x (pts.take N) 0`

Composes: loop spec (with degree bound from `countNonSkip_le_of_skip_exists`),
`GF16.const_div_spec`, and `PolyConst.mult_spec`. -/
@[step]
theorem lagrange_interpolate_pt_spec
    (N : Usize) (pts : Slice Pt) (i : Usize)
    (h_N_pos : 0 < N.val)
    (h_i_lt_N : i < N.val)
    (h_N_le_pts : N ≤ pts.val.length) :
    lagrange_interpolate_pt N pts i ⦃ (result : PolyConst N) =>
      ∀ (hi : i < pts.length),
        listToGF216Poly result.coefficients =
          C (pts[i].y.toGF216 * (lagrangeDenomProd (pts[i]).x (pts.val.take N) 0) ^ (2 ^ 16 - 2)) *
                condProdLinearFactors (pts[i]).x (pts.val.take N) 0 ⦄ := by
  unfold lagrange_interpolate_pt
  step*
  · unfold PolyConst.degree
    simp only [a1_post, Array.set_val_eq, Array.repeat_val, UScalar.ofNatCore_val_eq]
    rw [listToGF216Poly_replicate_zero_set_one N h_N_pos, Polynomial.natDegree_one, Nat.zero_add]
    have h_count : countNonSkip pi.x (List.take (↑N) (↑pts)) 0 ≤ ↑N - 1 := by
      apply countNonSkip_le_of_skip_exists pi.x _ (↑N)
        (by simp only [List.length_take, inf_le_left]) (↑i) h_i_lt_N
      grind
    omega
  · subst pi1_post1
    have h_init : listToGF216Poly a1 = 1 := by
      simp only [a1_post, Array.set_val_eq, Array.repeat_val, UScalar.ofNatCore_val_eq]
      exact listToGF216Poly_replicate_zero_set_one N.val h_N_pos
    simp only [result_post1, pi1_post2, g_post, pi1_post3, GF16.ONE_toGF216, one_mul, h_init,
      mul_one, pi_post]
    grind

end spqr.encoding.polynomial.PolyConst
