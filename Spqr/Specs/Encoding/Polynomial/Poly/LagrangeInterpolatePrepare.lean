/-
Copyright 2026 The Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE-APACHE.
Authors: Hoang Le Truong
-/
import Spqr.Specs.Encoding.Polynomial.Poly.Zero
import Spqr.Specs.Encoding.Gf.GF16.Eq
import Spqr.Specs.Encoding.Gf.GF16.ONE
import Spqr.Specs.Encoding.Gf.GF16.ZERO
import Spqr.Specs.Encoding.Polynomial.Poly.MultXdiffAssignTrailing

/-! # Spec theorem for `lagrange_interpolate_prepare`: loop body 0

Builds `∏_{j<offset} (x − pts[j].x)` by iteratively calling
`mult_xdiff_assign_trailing(offset − i, pts[i].x)` for `i` in `0..offset`.

In char 2: `(x − a) = (x ⊕ a)`. The recurrence is `v[j−1] −= v[j] * diff`.

Invariant: vector length = `offset + 1`; after `i` steps
`p[offset−i..]` = `∏_{j<i} (x − pts[j].x)`.

**Source**: spqr/src/encoding/polynomial.rs -/

open Aeneas Aeneas.Std  spqr.encoding.gf Polynomial

namespace spqr.encoding.polynomial.Poly.lagrange_interpolate_prepare_loop

/-- **Spec theorem for `encoding.polynomial.Poly.lagrange_interpolate_prepare_loop.body`**

One iteration of the `∏(x − pts[j].x)` construction. Always succeeds.
- `done`: iterator exhausted, polynomial unchanged.
- `cont`: iterator advanced by one, vector length preserved. Modified positions satisfy
  `p'[j] = p[j] − p[j+1] * pts[i].x` (in GF(2¹⁶)); all other positions unchanged.

Propagates the `mult_xdiff_assign_trailing` spec with `start = offset − i`,
`diff = pts[i].x`.

**Source**: spqr/src/encoding/polynomial.rs -/
@[step]
theorem body_spec
    (pts : Slice Pt)
    (offset : Usize)
    (iter : core.ops.range.Range Usize)
    (p : Poly)
    (h_end_le_pts : iter.end ≤ pts.length)
    (h_end_le_offset : iter.end ≤ offset)
    (h_offset_lt_len : offset < p.coefficients.length) :
    body pts offset iter p ⦃ cf =>
      match cf with
      | ControlFlow.done r =>
          r = p ∧ ¬ (iter.start < iter.end)
      | ControlFlow.cont (iter1, p1) =>
          iter.start < iter.end ∧
          iter1.start = iter.start.val + 1 ∧
          iter1.end = iter.end ∧
          p1.coefficients.length = p.coefficients.length ∧
          (∀ (j : Nat),
            offset - iter.start ≤ j + 1 →
            j + 1 < p.coefficients.length →
            ∀ (hj : j < p1.coefficients.length),
              (p1.coefficients[j]'hj).toGF216 =
                (p.coefficients[j]!).toGF216 -
                (p.coefficients[j + 1]!).toGF216 *
                  (pts[iter.start.val]!).x.toGF216) ∧
          (∀ (j : Nat),
            ¬(offset - iter.start ≤ j + 1 ∧
              j + 1 < p.coefficients.length) →
            p1.coefficients[j]? = p.coefficients[j]?) ⦄ := by
  unfold body
  obtain ⟨⟨opt, iter1'⟩, hnext, h_none, h_some⟩ :=
    WP.spec_imp_exists (core.iter.range.IteratorRange.next_Usize_spec' iter)
  rw [hnext]
  simp only [bind_tc_ok]
  by_cases h_lt : iter.start.val < iter.end.val
  · obtain ⟨h_opt_eq, h_start1, h_end1⟩ := h_some h_lt
    rw [h_opt_eq]
    simp only [uncurry_apply_pair, not_lt, tsub_le_iff_right, not_and]
    have h_i_lt_pts : iter.start < pts.length := by grind
    have h_i_lt_offset : iter.start < offset := by grind
    step*
    simp_all
    grind[degree]
  · obtain ⟨h_opt_eq, h_range_eq⟩ := h_none (by omega)
    rw [h_opt_eq]
    grind

/-! # Spec theorem for `lagrange_interpolate_prepare`: loop 0

Full loop building `∏_{j<offset} (x − pts[j].x)` via repeated `mult_xdiff_assign_trailing`.

Invariants: vector length = `offset + 1`, leading coeff = `ONE`, trailing sub-polynomial
`p[offset−i..]` = `∏_{j<i} (x − pts[j].x)`.

**Source**: spqr/src/encoding/polynomial.rs -/

@[step]
theorem loop_spec
    (pts : Slice Pt)
    (offset : Usize)
    (iter : core.ops.range.Range Usize)
    (p : Poly)
    (h_end_le_pts : iter.end ≤ pts.length)
    (h_end_le_offset : iter.end ≤ offset)
    (h_len_eq : p.degree = offset + 1)
    (h_le : iter.start ≤ iter.end)
    (h_start_zero : iter.start.val = 0) :
    lagrange_interpolate_prepare_loop
      iter pts p offset ⦃ (result : Poly) =>
      result.degree = p.degree ∧
      result.coefficients[offset.val]! =
        p.coefficients[offset.val]! ∧
      (∀ (hoff : offset.val < result.degree),
        (result.coefficients[offset.val]'hoff).toGF216 =
          (p.coefficients[offset.val]!).toGF216) ∧
      (∀ (j : Nat), ¬(offset.val - iter.end ≤ j ∧ j < offset) →
        result.coefficients[j]? = p.coefficients[j]?) ∧
      (∀ (m : Nat),
        m ≤ iter.end - iter.start →
        ∀ (hpos : offset - (iter.end - iter.start) + m <
                    result.degree),
          GF16.toGF216
            (result.coefficients[offset - (iter.end - iter.start) + m]) =
            (expectedTrailingPoly p.coefficients pts offset
              iter.start (iter.end - iter.start)).coeff m) ⦄ := by
  unfold spqr.encoding.polynomial.Poly.lagrange_interpolate_prepare_loop
  simp only [degree, alloc.vec.Vec.length] at h_len_eq
  apply loop.spec_decr_nat
    (measure := fun (st : core.ops.range.Range Usize × Poly) =>
                  st.1.end.val - st.1.start.val)
    (inv := fun (st : core.ops.range.Range Usize × Poly) =>
        st.1.end = iter.end ∧
        iter.start ≤ st.1.start.val ∧
        st.1.start.val ≤ iter.end.val ∧
        st.2.degree = p.degree ∧
        st.2.coefficients[offset.val]? =
          p.coefficients[offset.val]? ∧
        (∀ (hoff : offset.val < st.2.coefficients.length),
          (st.2.coefficients.val.get ⟨offset, hoff⟩).toGF216 =
            (p.coefficients[offset]!).toGF216) ∧
        (∀ (j : Nat),
          ¬(offset - st.1.start ≤ j ∧ j < offset.val) →
          st.2.coefficients[j]? = p.coefficients[j]?) ∧
        (∀ (m : Nat), m ≤ st.1.start.val - iter.start.val →
          ∀ (hpos : offset.val - (st.1.start - iter.start) + m < st.2.degree),
            GF16.toGF216
              (st.2.coefficients.val.get
                ⟨offset - (st.1.start - iter.start) + m, hpos⟩) =
              (expectedTrailingPoly p.coefficients pts offset
                iter.start (st.1.start - iter.start)).coeff m))
  · rintro ⟨iter', p'⟩ ⟨h_end', h_ge', h_le', h_len', h_off', h_gf16_off', h_frame', h_trail'⟩
    simp only [] at h_end' h_ge' h_le' h_len' h_off' h_gf16_off' h_frame' h_trail' ⊢
    have h_end_le_pts' : iter'.end.val ≤ pts.length := by grind
    have h_end_le_offset' : iter'.end.val ≤ offset.val := by grind
    have h_offset_lt_len' : offset.val < p'.coefficients.length := by grind
    step*
    split
    · rename_i r_post
      simp only [] at r_post
      obtain ⟨h_eq, h_nlt⟩ := r_post
      subst h_eq
      have h_end_val : iter'.end.val = iter.end.val := by rw [h_end']
      refine ⟨h_len', (by grind), h_gf16_off', fun j hj => ?_, fun m hm hpos => ?_⟩
      · apply h_frame'
        intro ⟨h1, h2⟩
        exact hj ⟨by omega, h2⟩
      · have h_iters_eq : iter'.start.val - iter.start.val =
            iter.end.val - iter.start.val := by grind
        rw [h_iters_eq] at h_trail'
        exact h_trail' m hm hpos
    · rename_i r_post
      simp only [] at r_post
      obtain ⟨h_lt, h_start1, h_end1, h_v1len, h_modified, h_frame⟩ := r_post
      refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
      · rw [h_end1]; exact h_end'
      · omega
      · grind
      · grind [degree]
      · grind
      · grind
      · grind
      · intro m hm hpos
        set k := iter'.start.val - iter.start.val with hk_def
        have hk1 : (Prod.fst r_post).start.val - iter.start.val = k + 1 := by omega
        have hpos' : offset.val - (k + 1) + m <
            (Prod.snd r_post).degree := by grind
        have hget_eq : (Prod.snd r_post).coefficients.val.get
            ⟨offset.val - ((Prod.fst r_post).start.val - iter.start.val) + m, hpos⟩ =
            (Prod.snd r_post).coefficients.val.get
            ⟨offset.val - (k + 1) + m, hpos'⟩ := by grind
        rw [hget_eq, hk1]
        rw [expectedTrailingPoly_succ]
        set pos := offset - (k + 1) + m with hpos_def
        by_cases hm0 : m = 0
        · subst hm0
          rw [coeff_zero_C_add_X_sub_C_mul]
          have htr := h_trail' 0 (by omega)
            (show offset - k + 0 < p'.coefficients.length by omega)
          grind
        · obtain ⟨m', rfl⟩ : ∃ m', m = m' + 1 := ⟨m - 1, by omega⟩
          rw [coeff_succ_C_add_X_sub_C_mul]
          have hpos_simp : pos = offset - k + m' := by grind
          by_cases hm'k : m' + 1 ≤ k
          · have hget_conv : (Prod.snd r_post).coefficients.val.get ⟨pos, hpos'⟩ =
                (Prod.snd r_post).coefficients.val.get
                  ⟨offset - k + m', (by grind)⟩ := by
              congr 1
              exact Fin.ext (by omega)
            have hlen_m' : offset.val - k + m' < p'.coefficients.length := by omega
            have htr_m' := h_trail' m' (by omega) hlen_m'
            have hlen_m1 : offset.val - k + (m' + 1) < p'.coefficients.length := by omega
            have htr_m1 := h_trail' (m' + 1) (by omega) hlen_m1
            have hiter : iter'.start.val = iter.start.val + k := by omega
            grind
          · have hm'_eq : m' = k := by omega
            subst hm'_eq
            have hpos_off : pos = offset.val := by omega
            have htr_k := h_trail' k (by omega)
              (show offset.val - k + k < p'.coefficients.length by omega)
            rw [expectedTrailingPoly_coeff_eq_zero_of_lt _ _ _ _ _ _ (by omega : k < k + 1)]
            grind
      · grind
  · refine ⟨rfl, le_refl _, h_le, rfl, rfl, ?_, ?_, ?_⟩
    · grind
    · intro _ _; rfl
    · intro m hm hpos
      have hm0 : m = 0 := by grind
      subst hm0
      simp only [Nat.sub_self, expectedTrailingPoly_zero, coeff_C_zero]
      congr 1
      exact (getElem!_pos p.coefficients.val offset.val (by omega)).symm

end spqr.encoding.polynomial.Poly.lagrange_interpolate_prepare_loop

/-! # Spec theorem for `lagrange_interpolate_prepare`

Constructs `∏_{j<pts.len()} (x − pts[j].x)` as a `Poly` of degree `pts.len()`.

**Source**: spqr/src/encoding/polynomial.rs (lines 144:4-163:5) -/

namespace spqr.encoding.polynomial.Poly

open encoding.gf.GF16

/-- **Spec theorem for `encoding.polynomial.Poly.lagrange_interpolate_prepare`**

Always succeeds when `pts.length + 1 ≤ Usize.max`. Guarantees:
- `result.coefficients.length = pts.length + 1`
- Leading coeff is `ONE` (matches Rust `debug_assert_eq!` at line 161), mapping to `1` in GF(2¹⁶).
- Each coefficient matches `prodLinearFactors` coefficient-wise under `toGF216`.
- `result.toGF216Poly = prodLinearFactors pts 0 pts.length` -/
@[step]
theorem lagrange_interpolate_prepare_spec
    (pts : Slice Pt)
    (h_len : pts.length + 1 ≤ Usize.max) :
    lagrange_interpolate_prepare pts ⦃ (result : Poly) =>
      result.degree = pts.length + 1 ∧
      result.coefficients[pts.length]! = ONE ∧
      (∀ m ≤ pts.length,
        (result.coefficients[m]!).toGF216 = (prodLinearFactors pts 0 pts.length).coeff m) ∧
      result.toGF216Poly = prodLinearFactors pts 0 pts.length ⦄ := by
  unfold lagrange_interpolate_prepare degree
  step*
  · simp_all [GF16.Insts.CoreCloneClone.clone]
  · simp_all [degree]
  · simp_all [degree]
  · have p1_len : p1.coefficients.val.length = (index_mut_back ONE).length := p1_post1
    simp_all
  · have p1_len : p1.coefficients.length =
        (index_mut_back ONE).val.length := p1_post1
    simp_all only [Slice.length, Order.add_one_le_iff, Usize.ofNatCore_val_eq,
      alloc.vec.Vec.getElem!_Nat_eq, alloc.vec.Vec.set_val_eq, List.length_set, List.resize_length,
      lt_add_iff_pos_right, Order.lt_one_iff, getElem!_pos, List.getElem_set_self,
      alloc.vec.Vec.getElem_Nat_eq, ONE_toGF216, implies_true, tsub_self, zero_le, true_and, not_lt,
      alloc.vec.Vec.getElem?_Nat_eq, tsub_zero, zero_add, ONE_value, alloc.vec.Vec.length,
      Order.lt_add_one_iff]
    have h_bridge : expectedTrailingPoly
        ((p.coefficients.val.resize (pts.length + 1) ZERO).set pts.length ONE)
        pts pts.length 0 pts.length =
      prodLinearFactors pts 0 pts.length := by
      apply expectedTrailingPoly_eq_prodLinearFactors
      · have hlen : pts.length < (p.coefficients.val.resize (pts.length + 1) ZERO).length := by
          grind
        grind [list_getElem_bang_set_self _ _ _ hlen, ONE_toGF216]
      · intro j hj
        have hj_lt : j < (p.coefficients.val.resize (pts.length + 1) ZERO).length := by grind
        unfold List.resize at hj_lt ⊢
        by_cases hk : j < p.coefficients.length
        · grind
        · simp_all
      · exact le_refl _
      · exact le_refl _
    constructor
    · intro m hm
      have hm_bound : m < (v.set pts.len ONE).length := by grind
      have h5 := p1_post5 m (by omega) hm_bound
      rw [h_bridge] at h5
      exact h5
    · change listToGF216Poly p1.coefficients = prodLinearFactors pts 0 pts.length
      apply listToGF216Poly_eq_of_coeffs
      · intro m hm
        have hm_le : m ≤ pts.length := by grind
        have hm_bound : m < (v.set pts.len ONE).length := by grind
        have h5 := p1_post5 m hm_le hm_bound
        grind
      · intro m hm
        exact prodLinearFactors_coeff_eq_zero_high _ _ _ _ (by grind)

end spqr.encoding.polynomial.Poly
