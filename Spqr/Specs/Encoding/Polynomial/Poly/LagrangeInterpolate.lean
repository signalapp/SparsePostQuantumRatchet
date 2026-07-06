/-
Copyright 2026 The Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE-APACHE.
Authors: Hoang Le Truong
-/
import Spqr.Specs.Encoding.Polynomial.Poly.Clone
import Spqr.Specs.Encoding.Polynomial.Poly.LagrangeInterpolatePrepare
import Spqr.Specs.Encoding.Polynomial.Poly.LagrangeInterpolateComplete

/-! # Spec theorem for `lagrange_interpolate`: loop body 1

One step of the inner loop `out.coefficients[j] += working.coefficients[j + 1]`.
The body retrieves the next index `j`; if exhausted returns `done (v, working)` unchanged,
otherwise performs the GF(2¹⁶) addition and returns `cont (iter1, v1)`.

**Source**: spqr/src/encoding/polynomial.rs -/

open Aeneas Aeneas.Std Result  spqr.encoding.gf Polynomial

namespace spqr.encoding.polynomial.Poly.lagrange_interpolate_loop0_loop0
/-- **Spec theorem for `encoding.polynomial.Poly.lagrange_interpolate_loop0_loop0.body`**:

One step of the inner accumulation `v[j] += working.coefficients[j+1]`.

• `done`: `v` and `working` unchanged, `¬ (iter.start < iter.end)`.
• `cont`: iterator advances by 1, `v` length preserved, position `j` updated with
  `v1[j].toGF216 = v[j].toGF216 + working.coefficients[j+1].toGF216`,
  all other positions unchanged.

Preconditions: `iter.end ≤ v.length` and `iter.end < working.coefficients.length`. -/
@[step]
theorem body_spec
    (working : Poly)
    (iter : core.ops.range.Range Usize)
    (v : alloc.vec.Vec GF16)
    (h_end_le_v : iter.end ≤ v.length)
    (h_end_lt_working : iter.end < working.degree) :
    body working iter v ⦃ cf =>
      match cf with
      | ControlFlow.done (v', working') => v' = v ∧ working' = working ∧ ¬ (iter.start < iter.end)
      | ControlFlow.cont (iter1, v1) =>
          iter.start < iter.end ∧
          iter1.start = iter.start.val + 1 ∧
          iter1.end = iter.end ∧
          v1.val.length = v.length ∧
          v1[iter.start]!.toGF216 = v[iter.start]!.toGF216 +
            (working.coefficients[iter.start.val + 1]!).toGF216 ∧
          (∀ (k : Nat), k ≠ iter.start → v1[k]! = v[k]!) ⦄ := by
  unfold body
  obtain ⟨⟨opt, iter1'⟩, hnext, h_none, h_some⟩ :=
    WP.spec_imp_exists (core.iter.range.IteratorRange.next_Usize_spec' iter)
  rw [hnext]
  simp only [bind_tc_ok]
  by_cases h_lt : iter.start.val < iter.end.val
  · obtain ⟨h_opt_eq, h_start1, h_end1⟩ := h_some h_lt
    rw [h_opt_eq]
    have h_j_lt_v : iter.start < v.length := by grind
    have h_jp1_lt_w : iter.start + 1 < working.coefficients.length := by grind [degree]
    step*
    refine ⟨h_lt, h_start1, h_end1, by simp_all, by simp_all, by simp_all⟩
  · grind

/-! # Spec theorem for `lagrange_interpolate`: loop 1

Full inner loop executing `out.coefficients[j] += working.coefficients[j+1]` for all
`j ∈ 0..out.coefficients.len()`. Provides a closed-form postcondition over all iterations.
Per-step spec is in `LagrangeInterpolateLoop1`.

**Source**: spqr/src/encoding/polynomial.rs -/
@[step]
theorem loop_spec
    (working : Poly) (iter : core.ops.range.Range Usize) (v : alloc.vec.Vec GF16)
    (h_end_le_v : iter.end ≤ v.length)
    (h_end_lt_working : iter.end < working.degree)
    (h_le : iter.start ≤ iter.end) :
    Poly.lagrange_interpolate_loop0_loop0 iter v working ⦃ (result : (alloc.vec.Vec GF16) × Poly) =>
      result.2 = working ∧
      result.1.length = v.length ∧
      (∀ (j : Nat), iter.start ≤ j → j < iter.end →
          result.1[j]!.toGF216 = v[j]!.toGF216 + (working.coefficients[j + 1]!).toGF216) ∧
      (∀ (j : Nat), ¬(iter.start ≤ j ∧ j < iter.end) → result.1[j]! = v[j]!) ⦄ := by
  unfold Poly.lagrange_interpolate_loop0_loop0
  apply loop.spec_decr_nat
    (measure := fun (p : core.ops.range.Range Usize × alloc.vec.Vec GF16) => p.1.end - p.1.start)
    (inv := fun (p : core.ops.range.Range Usize × alloc.vec.Vec GF16) =>
        p.1.end = iter.end ∧
        iter.start ≤ p.1.start ∧
        p.1.start ≤ iter.end ∧
        p.2.length = v.length ∧
        (∀ (j : Nat), iter.start ≤ j → j < p.1.start →
            p.2[j]!.toGF216 = v[j]!.toGF216 + working.coefficients[j + 1]!.toGF216) ∧
        (∀ (j : Nat), ¬(iter.start ≤ j ∧ j < p.1.start) → p.2[j]! = v[j]!))
  · rintro ⟨iter', v'⟩ ⟨h_end', h_ge', h_le', h_len', h_processed, h_unchanged⟩
    step*
    grind
  · grind

end spqr.encoding.polynomial.Poly.lagrange_interpolate_loop0_loop0

/-! # Spec theorem for `lagrange_interpolate`: loop body 0

One step of the outer loop: resets `working` from `template`, calls
`lagrange_interpolate_complete` for the `i`-th point, then XOR-adds
`working.coefficients[j+1]` into `out.coefficients[j]` via the inner loop.

**Source**: spqr/src/encoding/polynomial.rs -/

namespace spqr.encoding.polynomial.Poly.lagrange_interpolate_loop0

/-- **Spec theorem for `encoding.polynomial.Poly.lagrange_interpolate_loop0.body`**:

One step of the outer loop processing point index `i = iter.start.val`.

• `done`: `v` unchanged, `¬ (iter.start < iter.end)`.
• `cont`: iterator advances by 1, `v₂.length = v.length`,
  `working₂.coefficients.length = template.coefficients.length`,
  `working₂` satisfies `working₂.toGF216Poly · (X − C(pts[i].x)) =
    X · C(lagrangeScaleGF216 pts[i] pts) · template.toGF216Poly`,
  and `v₂[j].toGF216 = v[j].toGF216 + working₂.coefficients[j+1].toGF216` for all `j`.

Preconditions: `iter.end ≤ pts.length`, `0 < template.coefficients.length`,
`v.length < template.coefficients.length`, matching template/working lengths,
and `template.evalAt pts[i].x = 0` when the iterator is active. -/
@[step]
theorem body_spec
    (pts : Slice Pt) (template : Poly) (iter : core.ops.range.Range Usize)
    (v : alloc.vec.Vec GF16) (working : Poly)
    (h_end_le_pts : iter.end ≤ pts.length)
    (h_template_pos : 0 < template.degree)
    (h_v_lt : v.val.length < template.degree)
    (h_wt : template.degree = working.degree)
    (h_eval : iter.start < iter.end →
        ∀ (_ : iter.start < pts.length),
          template.evalAt (pts[iter.start]!).x = 0) :
    body pts template iter v working ⦃ cf =>
      match cf with
      | ControlFlow.done v' => v' = v ∧ ¬ (iter.start < iter.end)
      | ControlFlow.cont (iter1, v₂, working₂) =>
          iter.start < iter.end ∧
          iter1.start = iter.start.val + 1 ∧
          iter1.end = iter.end ∧
          v₂.length = v.length ∧
          working₂.degree = template.degree ∧
          (∀ (hi : iter.start < pts.length),
            working₂.toGF216Poly * (X - C (GF16.toGF216 (pts[iter.start]).x)) =
              X * C (lagrangeScaleGF216 (pts[iter.start]) pts) * template.toGF216Poly) ∧
          (∀ j < v₂.length,
            (v₂[j]!).toGF216 = (v[j]!).toGF216 + (working₂.coefficients[j + 1]!).toGF216) ⦄ := by
  unfold body
  obtain ⟨⟨opt, iter1'⟩, hnext, h_none, h_some⟩ :=
    WP.spec_imp_exists (core.iter.range.IteratorRange.next_Usize_spec' iter)
  rw [hnext]
  simp only [bind_tc_ok]
  by_cases h_lt : iter.start < iter.end
  · obtain ⟨h_opt_eq, h_start1, h_end1⟩ := h_some h_lt
    rw [h_opt_eq]
    have h_match_len :
        (alloc.vec.Vec.deref_mut working.coefficients).1.length =
        (alloc.vec.Vec.deref template.coefficients).length := by
      simp only [alloc.vec.Vec.deref_mut, alloc.vec.Vec.deref, Slice.length]
      exact h_wt.symm
    have hv1_val :
        ((alloc.vec.Vec.deref_mut working.coefficients).2
          (alloc.vec.Vec.deref template.coefficients)).val = template.coefficients.val := by
      simp only [alloc.vec.Vec.deref_mut, alloc.vec.Vec.deref]
    have h_toGF_eq :
      ({coefficients := (alloc.vec.Vec.deref_mut working.coefficients).2
                          (alloc.vec.Vec.deref template.coefficients)}
        : encoding.polynomial.Poly).toGF216Poly = template.toGF216Poly := by
      unfold Poly.toGF216Poly
      rw [hv1_val]
    have h_poly_eval :
      ({coefficients := (alloc.vec.Vec.deref_mut working.coefficients).2
                          (alloc.vec.Vec.deref template.coefficients)}: Poly).evalAt
                          (pts[iter.start]!).x = 0 := by
      unfold Poly.evalAt
      rw [h_toGF_eq]
      exact h_eval h_lt (by grind)
    have h_v1_len :
        0 < ({coefficients := (alloc.vec.Vec.deref_mut working.coefficients).2
                                (alloc.vec.Vec.deref template.coefficients)}
              : Poly).coefficients.val.length := by
      change 0 < ((alloc.vec.Vec.deref_mut working.coefficients).2
                  (alloc.vec.Vec.deref template.coefficients)).val.length
      rw [hv1_val]
      exact h_template_pos
    simp only [lift, bind_tc_ok]
    have h_copy :=
      core.slice.Slice.copy_from_slice.step_spec GF16.Insts.CoreMarkerCopy
        (alloc.vec.Vec.deref_mut working.coefficients).1
        (alloc.vec.Vec.deref template.coefficients) h_match_len
    have h_complete :=
      lagrange_interpolate_complete_spec
        { coefficients := (alloc.vec.Vec.deref_mut working.coefficients).2
                            (alloc.vec.Vec.deref template.coefficients) }
        pts iter.start (by grind) h_v1_len h_poly_eval
    apply WP.spec_bind h_copy
    intro s2 hs2
    rw [hs2]
    apply WP.spec_bind h_complete
    intro working1 ⟨h_w1_len, h_w1_poly⟩
    apply WP.spec_bind (lagrange_interpolate_loop0_loop0.loop_spec working1
      { start := 0#usize, «end» := alloc.vec.Vec.len v } v
      (by simp [alloc.vec.Vec.len])
      (by simp [alloc.vec.Vec.len]; grind [degree])
      (by grind))
    grind [degree]
  · grind

/-! # Spec theorem for `lagrange_interpolate`: loop 0

Full outer loop over `iter.start..iter.end`. At each iteration: resets `working` from `template`,
calls `lagrange_interpolate_complete`, and XOR-adds contributions into `out`.

Postcondition: length preserved, and there exist witness polynomials `ws` (one per iteration)
satisfying the Lagrange polynomial identity and cumulative XOR-accumulation of coefficients
at positions `j+1` (the "divide by X" trick).

**Source**: spqr/src/encoding/polynomial.rs -/
@[step]
theorem loop_spec
    (pts : Slice Pt) (template : Poly) (iter : core.ops.range.Range Usize)
    (v : alloc.vec.Vec GF16) (working : Poly)
    (h_end_le_pts : iter.end ≤ pts.length)
    (h_template_pos : 0 < template.degree)
    (h_v_lt : v.length < template.degree)
    (h_wt : template.degree = working.degree)
    (h_le : iter.start ≤ iter.end)
    (h_eval_all : ∀ (i : Nat), iter.start ≤ i → i < iter.end → template.evalAt (pts[i]!).x = 0) :
    Poly.lagrange_interpolate_loop0 iter pts v template working ⦃ (result : alloc.vec.Vec GF16) =>
      result.length = v.length ∧
      ∃ ws : List Poly,
        ws.length = iter.end - iter.start ∧
        (∀ (k : Nat) (hk : k < ws.length) (hi : iter.start + k < pts.length),
          (ws[k]).toGF216Poly * (X - C (GF16.toGF216 (pts[iter.start + k]).x)) =
            X * C (lagrangeScaleGF216 (pts[iter.start + k]) pts.val) * template.toGF216Poly) ∧
        (∀ (j : Nat) (_ : j < result.length),
          (result.val[j]!).toGF216 =
            (v[j]!).toGF216 + (ws.map (fun w => (w.coefficients[j + 1]!).toGF216)).sum) ⦄ := by
  unfold Poly.lagrange_interpolate_loop0
  apply loop.spec_decr_nat
    (measure := fun (p : core.ops.range.Range Usize × alloc.vec.Vec GF16 × Poly) =>
                  p.1.end - p.1.start)
    (inv := fun (p : core.ops.range.Range Usize × alloc.vec.Vec GF16 × Poly) =>
        p.1.end = iter.end ∧
        iter.start ≤ p.1.start ∧
        p.1.start ≤ iter.end ∧
        p.2.1.length = v.length ∧
        p.2.2.degree = template.degree ∧
        ∃ ws : List Poly,
          ws.length = p.1.start - iter.start ∧
          (∀ (k : Nat) (hk : k < ws.length) (hi : iter.start + k < pts.length),
            (ws[k]!).toGF216Poly * (X - C (GF16.toGF216 (pts[iter.start + k]!).x)) =
              X * C (lagrangeScaleGF216 (pts[iter.start + k]!) pts) * template.toGF216Poly) ∧
          (∀ (j : Nat) (hj : j < p.2.1.length),
            (p.2.1[j]!).toGF216 = (v[j]!).toGF216 +
            (ws.map (fun w => (w.coefficients[j + 1]!).toGF216)).sum))
  · rintro ⟨iter', v', working'⟩
      ⟨h_end', h_ge', h_le', h_len', h_wt', ws, h_ws_len, h_ws_id, h_ws_sum⟩
    simp only at h_end' h_ge' h_le' h_len' h_wt' h_ws_len h_ws_id h_ws_sum ⊢
    step*
    split
    · rename_i r_post
      simp only [] at r_post
      obtain ⟨h_v_eq, h_nlt⟩ := r_post
      subst h_v_eq
      refine ⟨h_len', ws, by grind, by grind, by grind⟩
    · rename_i r_post
      simp only at r_post
      obtain ⟨h_lt, h_start1, h_end1, h_v2len, h_w2len, h_poly_id, h_coord⟩ := r_post
      refine ⟨by grind, by grind, by grind, by grind, by exact h_w2len, ?_, by grind⟩
      refine ⟨ws ++ [r_post.2.2], by grind, by grind, by grind⟩
  · refine ⟨rfl, le_refl _, h_le, rfl, h_wt.symm, [], by simp, by grind, by grind⟩

end spqr.encoding.polynomial.Poly.lagrange_interpolate_loop0

/-! # Spec theorem for
`spqr::encoding::polynomial::{spqr::encoding::polynomial::Poly}::lagrange_interpolate`

Computes the unique polynomial of degree `< pts.len()` over GF(2¹⁶) interpolating `pts`.
Prepares `template = ∏_j (X − pts[j].x)`, then for each point index `i`, calls
`lagrange_interpolate_complete` and XOR-accumulates `working.coefficients[j+1]` into
`out.coefficients[j]` (the "divide by X" trick). The result is the classical Lagrange interpolant.

**Source**: spqr/src/encoding/polynomial.rs -/

namespace spqr.encoding.polynomial.Poly

private lemma slice_is_empty_spec {T : Type} (s : Slice T) :
    core.slice.Slice.is_empty s ⦃ (b : Bool) =>
      b = (s.val.length = 0) ⦄ := by
  unfold core.slice.Slice.is_empty
  simp only [WP.spec_ok]
  rcases h : s.val.length with _ | n
  all_goals simp [h]

private lemma extend_from_slice_GF16_spec
    (v : alloc.vec.Vec GF16)
    (s : Slice GF16)
    (h : v.length + s.length ≤ Usize.max) :
    alloc.vec.Vec.extend_from_slice GF16.Insts.CoreCloneClone v s ⦃ (r : alloc.vec.Vec GF16) =>
        r = v ++ s.val ⦄ := by
  have h_clone_x : ∀ x ∈ s.val, GF16.Insts.CoreCloneClone.clone x = ok x := by
    intros _ _
    simp [GF16.Insts.CoreCloneClone.clone]
  have h_slclone : Slice.clone GF16.Insts.CoreCloneClone.clone s = ok s := by
    obtain ⟨s', h_eq, hs⟩ := WP.spec_imp_exists (Slice.clone_spec h_clone_x)
    rw [h_eq, ← hs]
  unfold alloc.vec.Vec.extend_from_slice
  have hlen : v.length + s.length ≤ Usize.max := h
  rw [dif_pos hlen]
  grind

theorem lagrange_interpolate_formula
    (pts : Slice Pt)
    (h_len : pts.length + 1 ≤ Usize.max) :
    lagrange_interpolate pts ⦃ (result : Poly) =>
      result.degree = pts.length ∧
      (pts.length = 0 → result.toGF216Poly = 0) ∧
      (0 < pts.length →
        ∃ ws : List Poly,
          ws.length = pts.length ∧
          (∀ (i : Nat) (hi : i < ws.length) (hpi : i < pts.length),
            (ws[i]).toGF216Poly * (X - C (GF16.toGF216 (pts[i]).x)) =
              X * C (lagrangeScaleGF216 (pts[i]) pts) * (prodLinearFactors pts 0 pts.length)) ∧
          (∀ (j : Nat) (_ : j < result.degree),
            (result.coefficients.val[j]!).toGF216 =
            (ws.map (fun w => (w.coefficients.val[j + 1]!).toGF216)).sum)) ⦄ := by
  unfold lagrange_interpolate
  step with zero_spec pts.len as ⟨out, h_out_len, h_out_zero⟩
  step with slice_is_empty_spec pts as ⟨b, hb_eq⟩
  split
  · grind [degree]
  · rename_i hb_false
    have h_nonempty : 0 < pts.val.length := by grind
    step with lagrange_interpolate_prepare_spec pts h_len as
      ⟨template, h_template_len, _, _,  h_template_eq⟩
    step with clone_spec template as ⟨working, h_working_eq⟩
    rw [h_working_eq]
    have h_root_template : template.evalAt (pts[0]!).x = 0 := by
      unfold Poly.evalAt
      grind [prodLinearFactors_eval_root]
    step with lagrange_interpolate_complete_spec template pts 0#usize
      h_nonempty (by grind) h_root_template as ⟨working1, h_w1_len, h_w1_id⟩
    have h_one_le_w1 : (1 : Nat) ≤ working1.degree := by grind
    step with alloc.vec.Vec.index_RangeFrom_spec working1.coefficients ⟨1#usize⟩ h_one_le_w1
      as ⟨s, h_s_val, h_s_len⟩
    have h_s_len_pts : s.length = pts.length := by grind [degree]
    step with extend_from_slice_GF16_spec out.coefficients s (by grind [degree]) as ⟨v, h_v_val⟩
    have h_v_val' : v = s.val := by rw [h_v_val, List.length_eq_zero_iff.mp h_out_len,
      List.nil_append]
    have h_v_len : v.length = pts.length := by grind
    have h_v_coeff : ∀ (j : Nat), j < v.val.length →
        v[j]! = working1.coefficients.val[j + 1]! := by grind
    have h_one_le_end : (1 : Nat) ≤ (Slice.len pts).val := by
      simp only [Slice.len, Usize.ofNatCore_val_eq]
      exact h_nonempty
    have h_v_lt_template : v.length < template.degree := by
      rw [h_v_len]
      omega
    have h_eval_all_template :
        ∀ (i : Nat), 1 ≤ i → i < (Slice.len pts).val → template.evalAt (pts[i]!).x = 0 := by
      unfold Poly.evalAt
      grind [prodLinearFactors_eval_root]
    step with lagrange_interpolate_loop0.loop_spec pts template
      ({ start := 1#usize, «end» := Slice.len pts } : core.ops.range.Range Usize)
      v working1 (by simp [Slice.len]) (by grind) h_v_lt_template (h_w1_len.symm)
      h_one_le_end h_eval_all_template as
      ⟨v1, h_v1_len, ws', h_ws'_len, h_ws'_id, h_v1_coeff⟩
    have h_v1_pts_len : v1.length = pts.length := by rw [h_v1_len, h_v_len]
    refine ⟨h_v1_pts_len, by grind , ?_⟩
    intro _
    refine ⟨working1 :: ws', by grind, ?_, ?_⟩
    · intro i hi hpi
      cases i with
      | zero => grind
      | succ k => grind
    · intro j hj
      have hj' : j < v1.length := hj
      have hj_v : j < v.length := by rw [h_v_len]; rw [h_v1_pts_len] at hj'; exact hj'
      rw [h_v1_coeff j hj']
      have := h_v_coeff j hj_v
      rw [h_v_coeff j hj_v]
      simp [List.map_cons, List.sum_cons]

/-- **Spec theorem for `spqr.encoding.polynomial.Poly.lagrange_interpolate`**:

Returns `result` with `result.coefficients.length = pts.length`. When empty, `result = 0`.
Otherwise, witness polynomials `ws` exist (one per point) satisfying the Lagrange polynomial
identity and `result.coefficients[j] = ∑_i ws[i].coefficients[j+1]` in GF(2¹⁶),
recovering the classical Lagrange interpolation formula.

**Source**: spqr/src/encoding/polynomial.rs -/
@[step]
theorem lagrange_interpolate_spec
    (pts : Slice Pt)
    (h_len : pts.length + 1 ≤ Usize.max) :
    lagrange_interpolate pts ⦃ (result : Poly) =>
      result.degree = pts.length ∧
      (pts.length = 0 → result.toGF216Poly = 0) ∧
      result.toGF216Poly = lagrangeInterpolantSum pts pts.length ⦄ := by
  apply WP.spec_mono (lagrange_interpolate_formula pts h_len)
  intro result ⟨h_rlen, h_empty, h_nonempty⟩
  set n := pts.length with hn_def
  by_cases h0 : n = 0
  · grind [lagrangeInterpolantSum]
  · have hpos : 0 < n := Nat.pos_of_ne_zero h0
    obtain ⟨ws, hws_len, hws_id, hws_coeff⟩ := h_nonempty hpos
    have hws_poly : ∀ (i : Nat) (hi : i < ws.length) (hpi : i < n),
        (ws[i]!).toGF216Poly =
          X * C (lagrangeScaleGF216 (pts[i]!) pts) * lagrangeBasisPoly pts i := by
      intro i hi hpi
      have h_id := hws_id i hi hpi
      rw [prodLinearFactors_eq_X_sub_C_mul pts.val i hpi,
          show prodLinearFactors pts.val 0 i *
              prodLinearFactors pts.val (i + 1) pts.val.length =
              lagrangeBasisPoly pts.val i from by
            unfold lagrangeBasisPoly; rw [if_pos hpi]] at h_id
      have hne : (X : GF216[X]) - C (GF16.toGF216 (pts.val.get ⟨i, hpi⟩).x) ≠ 0 :=
        (Polynomial.monic_X_sub_C _).ne_zero
      have h_rhs_rw :
          X * C (lagrangeScaleGF216 (pts[i]) pts.val) *
            ((X - C (GF16.toGF216 (pts.val.get ⟨i, hpi⟩).x)) *
              lagrangeBasisPoly pts.val i) =
          (X * C (lagrangeScaleGF216 (pts.val.get ⟨i, hpi⟩) pts.val) *
            lagrangeBasisPoly pts.val i) *
          (X - C (GF16.toGF216 (pts.val.get ⟨i, hpi⟩).x)) := by grind
      rw [h_rhs_rw] at h_id
      apply  mul_right_cancel₀ hne
      grind
    have h_term_eq : ∀ (m : ℕ) (i : Fin ws.length),
        ((ws.get i).coefficients.val[m + 1]!).toGF216 =
          (C (lagrangeScaleGF216 (pts[i]!) pts.val) * lagrangeBasisPoly pts i).coeff m := by
      intro m ⟨i, hi⟩
      rw [getElem!_toGF216_eq_coeff]
      change (ws.get ⟨i, hi⟩ ).toGF216Poly.coeff (m + 1) = _
      grind [mul_assoc, Polynomial.coeff_X_mul]
    unfold Poly.toGF216Poly
    constructor
    · grind [lagrangeInterpolantSum, Polynomial.finset_sum_coeff, List.map_sum_eq_Finset_sum]
    · constructor
      · grind [lagrangeInterpolantSum, Polynomial.finset_sum_coeff, List.map_sum_eq_Finset_sum]
      · ext m
        rw [listToGF216Poly_coeff]
        by_cases hm : m < result.degree
        · rw [degree] at hm
          have :(result.coefficients.val ).get ⟨m, hm⟩ = (result.coefficients.val)[m]! := by grind
          rw [dif_pos hm, this, hws_coeff m hm, List.map_sum_eq_Finset_sum]
          rw [Finset.sum_congr rfl (fun i _ => h_term_eq m i)]
          rw [lagrangeInterpolantSum_eq_finset_sum pts.val n (le_refl _)]
          rw [Polynomial.finset_sum_coeff]
          apply Finset.sum_bij (fun (a : Fin ws.length) _ => a.val)
            (fun a _ => by rw [Finset.mem_range]; grind)
            (fun a₁ _ a₂ _ h => Fin.val_injective h)
            (fun b hb => by
              rw [Finset.mem_range] at hb
              exact ⟨⟨b, by grind⟩, Finset.mem_univ _, rfl⟩)
            (fun a _ => by grind)
        · rw[degree] at hm
          rw [dif_neg hm]
          exact (lagrangeInterpolantSum_coeff_high pts n m (le_refl _)
            (by rw[degree] at h_rlen; rw [h_rlen] at hm; push Not at hm; omega)).symm

end spqr.encoding.polynomial.Poly
