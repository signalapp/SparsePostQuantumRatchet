/-
Copyright 2026 The Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE-APACHE.
Authors: Hoang Le Truong
-/
import Spqr.Math.List
import Spqr.Math.Poly.Aeneas.PolyIdentity
import Spqr.Specs.Encoding.Gf.GF16.Sub
import Spqr.Specs.Encoding.Gf.GF16.Div
import Spqr.Specs.Encoding.Gf.GF16.Eq
import Spqr.Specs.Encoding.Gf.GF16.ZERO
import Spqr.Specs.Encoding.Gf.GF16.ONE
import Spqr.Specs.Encoding.Gf.GF16.AddAssign
import Spqr.Specs.Aeneas.RangeIteratorNext
import Spqr.Specs.Aeneas.SliceIteratorNext
import Spqr.Specs.Aeneas.FmtArgumentsFromStr
import Mathlib.RingTheory.DedekindDomain.Basic
/-!
# Spec Theorem for `lagrange_interpolate_complete`: loop body 0

One iteration of the denominator accumulation loop. Retrieves the next point `pj`:
- exhausted → `done` with current `(pi, denominator)`;
- `pi.x = pj.x` → `cont`, denominator unchanged (skip self);
- `pi.x ≠ pj.x` → `cont`, `denominator ← denominator * (pi.x - pj.x)`.

In GF(2¹⁶), subtraction = addition = XOR.

**Source**: spqr/src/encoding/polynomial.rs (lines 202:8-207:9)
-/

open Aeneas Aeneas.Std Result spqr.encoding.polynomial spqr.encoding.gf  Polynomial

namespace spqr.encoding.polynomial.Poly.lagrange_interpolate_complete_loop0

/--
**Spec theorem for `encoding.polynomial.Poly.lagrange_interpolate_complete_loop0.body`**:

Postcondition: `done` ⇒ denominator unchanged and `pi' = pi`;
`cont` ⇒ denominator unchanged (skip) or multiplied by `(pi.x - pj.x)` (accumulate). -/
@[step]
theorem body_spec (pi : Pt)
    (iter : core.slice.iter.Iter Pt)
    (denominator : GF16) :
    body pi iter denominator ⦃ result =>
      match result with
      | ControlFlow.done (pi', denom') =>
          denom'.toGF216 = denominator.toGF216 ∧ pi' = pi
      | ControlFlow.cont (_, denom') =>
          denom'.toGF216 = denominator.toGF216 ∨
          ∃ (pj_x : GF216),
            denom'.toGF216 =
              denominator.toGF216 *
                (pi.x.toGF216 - pj_x)
      ⦄ := by
  unfold body
  step*

end spqr.encoding.polynomial.Poly.lagrange_interpolate_complete_loop0

/-! # Spec Theorem for `lagrange_interpolate_complete`: loop 0

Iterates `loop0.body` over all remaining points to compute
`denominator_final = denominator_init * ∏_{j, pj.x ≠ pi.x} (pi.x - pj.x)`.
The Lagrange scaling factor is then `scale = pi.y / denominator_final`.

**Source**: spqr/src/encoding/polynomial.rs (lines 202:8-207:9)
-/

namespace spqr.encoding.polynomial.Poly.lagrange_interpolate_complete_loop0
/-- **Spec theorem for `encoding.polynomial.Poly.lagrange_interpolate_complete_loop0`**:

Always succeeds. Returns `pi' = pi` and
`denominator'.toGF216 = denominator.toGF216 * lagrangeDenomProd pi.x iter.slice.val iter.i`.
With `iter.i = 0` and `denominator = ONE`, this yields the full Lagrange denominator product. -/
@[step]
theorem loop0_spec
    (iter : core.slice.iter.Iter Pt)
    (pi : Pt)
    (denominator : GF16) :
    lagrange_interpolate_complete_loop0 iter pi denominator ⦃ (result : Pt × GF16) =>
      result.1 = pi ∧
      result.2.toGF216 = denominator.toGF216 *
        lagrangeDenomProd pi.x iter.slice.val iter.i ⦄ := by
  unfold lagrange_interpolate_complete_loop0
  apply loop.spec_decr_nat
    (measure := fun (p : core.slice.iter.Iter Pt × GF16) =>
      p.1.slice.len - p.1.i)
    (inv := fun (p : core.slice.iter.Iter Pt × GF16) =>
      p.1.slice = iter.slice ∧
      iter.i ≤ p.1.i ∧
      p.2.toGF216 * lagrangeDenomProd pi.x
          iter.slice.val p.1.i =
        denominator.toGF216 *
          lagrangeDenomProd pi.x
            iter.slice.val iter.i)
  · rintro ⟨iter', denom'⟩ ⟨hslice, hge, hinv⟩
    simp only at hslice hge hinv
    unfold body
    simp only [core.slice.iter.IteratorSliceIter.next]
    split
    · step*
      · refine ⟨hslice, by omega, ?_, by (simp only [Slice.len_val]; grind)⟩
        rw [← lagrangeDenomProd_skip pi.x iter.slice.val iter'.i (by grind) (by grind)]
        grind
      · refine ⟨hslice, by omega, ?_, by (simp only [Slice.len_val]; grind)⟩
        rw [lagrangeDenomProd_accum pi.x iter.slice.val iter'.i (by grind) (by grind)] at hinv
        grind
    · simp_all [lagrangeDenomProd_eq_one_of_le pi.x iter.slice.val iter'.i (by grind), mul_one]
  · grind

end spqr.encoding.polynomial.Poly.lagrange_interpolate_complete_loop0

namespace spqr.encoding.polynomial.Poly.lagrange_interpolate_complete_loop1

@[step]
theorem body_spec
    (g scale : GF16)
    (iter' : core.ops.range.Range Usize)
    (v' : alloc.vec.Vec GF16)
    (h_start_ge : 1 ≤ iter'.start.val)
    (h_end_eq : iter'.«end».val = v'.val.length) :
    body g scale iter' v' ⦃ cf =>
      match cf with
      | ControlFlow.done r =>
          r = v' ∧ ¬ (iter'.start.val < iter'.«end».val)
      | ControlFlow.cont (iter1, v2) =>
          iter'.start.val < iter'.«end».val ∧
          iter1.start.val = iter'.start.val + 1 ∧
          iter1.«end» = iter'.«end» ∧
          v2.val.length = v'.val.length ∧
          (∀ (h_idx : v'.val.length - iter'.start.val < v2.val.length),
            (v2.val.get ⟨v'.val.length - iter'.start.val, h_idx⟩).toGF216 =
              (v'.val[v'.val.length - iter'.start.val]!).toGF216 *
                scale.toGF216) ∧
          (∀ (h_idx : v'.val.length - iter'.start.val - 1 < v2.val.length),
            (v2.val.get ⟨v'.val.length - iter'.start.val - 1, h_idx⟩).toGF216 =
              (v'.val[v'.val.length - iter'.start.val - 1]!).toGF216 +
              (v'.val[v'.val.length - iter'.start.val]!).toGF216 *
                g.toGF216) ∧
          (∀ (j : Nat),
            j ≠ v'.val.length - iter'.start.val ∧
            j ≠ v'.val.length - iter'.start.val - 1 →
            v2.val[j]? = v'.val[j]?) ⦄ := by
  unfold body
  step*
  all_goals (simp_all; grind)

@[step]
theorem loop1_spec
    (iter : core.ops.range.Range Usize)
    (v : alloc.vec.Vec GF16)
    (g : GF16)
    (scale : spqr.encoding.gf.GF16)
    (h_start : iter.start.val = 1)
    (h_end : iter.«end».val = v.val.length) :
    lagrange_interpolate_complete_loop1 iter v g scale ⦃ (result : alloc.vec.Vec GF16) =>
      result.val.length = v.val.length ∧
      (∀ k (hk : k < result.val.length),
        0 < k →
          (result.val.get ⟨k, hk⟩).toGF216 =
            scale.toGF216 * hornerAccum g v.val k) ∧
      (∀ (h0 : 0 < result.val.length),
      (result.val.get ⟨0, h0⟩).toGF216 = hornerAccum g v.val 0) ⦄ := by
  unfold lagrange_interpolate_complete_loop1
  apply loop.spec_decr_nat
    (measure := fun (p : core.ops.range.Range Std.Usize ×
                        alloc.vec.Vec spqr.encoding.gf.GF16) =>
      p.1.«end».val - p.1.start.val)
    (inv := fun (p : core.ops.range.Range Std.Usize ×
                      alloc.vec.Vec spqr.encoding.gf.GF16) =>
      p.2.val.length = v.val.length ∧
      p.1.«end».val = v.val.length ∧
      1 ≤ p.1.start.val ∧
      (∀ k (hk : k < p.2.val.length),
        v.val.length - p.1.start.val < k →
          (p.2.val.get ⟨k, hk⟩).toGF216 =
            scale.toGF216 * hornerAccum g v.val k) ∧
      (∀ (hcur : v.val.length - p.1.start.val < p.2.val.length),
          (p.2.val.get ⟨v.val.length - p.1.start.val,
            hcur⟩).toGF216 =
            hornerAccum g v.val (v.val.length - p.1.start.val)) ∧
      (∀ k, k < v.val.length - p.1.start.val →
        p.2.val[k]? = v.val[k]?))
  · rintro ⟨iter', v'⟩ ⟨hlen, hend, hstart_ge, hscaled, hcursor, hunchanged⟩
    simp only at hlen hend hstart_ge hscaled hcursor hunchanged
    step*
    split
    · simp_all
      grind
    · rename_i r_post
      obtain ⟨h_lt, h_start1, h_end1, h_v2len, h_scaled_pos, h_carry_pos, h_frame⟩ := r_post
      set cursor := v.val.length - iter'.start.val with hcursor_def
      refine ⟨by omega, by grind, by omega, ?_, ?_, by grind, by grind⟩
      · intro k hk hk_gt
        by_cases hk_eq : k = cursor
        · grind
        · grind [h_frame k (by omega)]
      · intro hcur
        suffices hsuff :
            ((Prod.snd r_post).val.get ⟨cursor - 1, (by omega)⟩).toGF216 =
              hornerAccum g v.val (cursor - 1) by
          exact hornerAccum_eq_of_idx_eq (by grind) hsuff
        rw [hornerAccum_unfold g v.val (cursor - 1) (by omega)]
        grind
  · dsimp only [Prod.fst, Prod.snd]
    simp only [h_start]
    refine ⟨trivial, h_end, le_refl 1, ?_, ?_, ?_⟩
    · intro k hk hgt; omega
    · intro hcur
      rw [hornerAccum_unfold g v.val (v.val.length - 1) hcur]
      have hlen_eq : v.val.length - 1 + 1 = v.val.length := by omega
      rw [hlen_eq, hornerAccum_eq_zero_of_le g v.val v.val.length (le_refl _)]
      simp [mul_zero, add_zero]
    · intro _ _; trivial

end spqr.encoding.polynomial.Poly.lagrange_interpolate_complete_loop1


namespace spqr.encoding.polynomial.Poly

/-! ## Spec theorem for `spqr.encoding.polynomial.Poly.lagrange_interpolate_complete`

Top-level correctness spec for `Poly::lagrange_interpolate_complete`
(`src/encoding/polynomial.rs`, lines 197–223).

The function takes a polynomial `self` (typically `∏ⱼ (X − pⱼ.x)`), a point slice `pts`, and an
index `i`, then:
1. Computes `denominator = ∏_{j≠i} (pᵢ.x − pⱼ.x)` (loop 0).
2. Computes `scale = pᵢ.y / denominator` via Fermat inversion in GF(2¹⁶).
3. Divides out `(X − pᵢ.x)` by Horner-style synthetic division, scaling each coefficient by
   `scale` (loop 1). The result is shifted up by one degree (multiplied by `X`).
4. Asserts `coefficients[0] == ZERO` (exact division check). -/

@[step]
theorem lagrange_interpolate_complete_spec
    (self : Poly) (pts : Slice Pt) (i : Usize)
    (hi : i.val < pts.val.length)
    (hlen : 0 < self.coefficients.val.length)
    (heval : self.evalAt (pts.val.get ⟨i.val, hi⟩).x = 0) :
    lagrange_interpolate_complete self pts i ⦃ (result : Poly) =>
      result.coefficients.val.length = self.coefficients.val.length ∧
      result.toGF216Poly * (X - C (GF16.toGF216 (pts.val.get ⟨i.val, hi⟩).x)) =
        X * C (lagrangeScaleGF216 (pts.val.get ⟨i.val, hi⟩) pts.val) * self.toGF216Poly ⦄ := by
  unfold lagrange_interpolate_complete
  step*
  · -- success path (b = true)
    rename_i _ _ _ _ _ _ hb
    have hpi_eq : pi = pts.val.get ⟨i.val, hi⟩ := by grind
    have hlv_zero := b_post.mp hb
    have hH0 : hornerAccum pi1.x self.coefficients.val 0 = 0 := by
      rw [← v_post3 (by omega)]
      have hlv_get : left_val = v.val.get ⟨0, by omega⟩ := by grind
      rw [← hlv_get]
      have hval_zero : left_val.value.val = 0 := by
        have := congr_arg UScalar.val hlv_zero
        simp only [gf.GF16.ZERO, UScalar.ofNatCore_val_eq] at this
        exact this
      exact spqr.encoding.gf.GF16.toGF216_eq_zero left_val hval_zero
    have hscale_eq : scale.toGF216 =
        lagrangeScaleGF216 (pts.val.get ⟨i.val, hi⟩)
          pts.val := by
      unfold lagrangeScaleGF216
      rw [pi1_post1] at scale_post
      rw [scale_post]
      rw [iter_post1, iter_post2] at pi1_post2
      simp only [spqr.encoding.gf.GF16.ONE_toGF216,
        one_mul] at pi1_post2
      rw [pi1_post2, hpi_eq]
    rw [pi1_post1] at v_post2 v_post3 hH0
    rw [hpi_eq] at v_post2 v_post3 hH0
    constructor
    · exact v_post1
    · unfold Poly.toGF216Poly
      apply poly_identity_from
        self.coefficients.val v.val
        (pts.val.get ⟨i.val, hi⟩).x
        (lagrangeScaleGF216
          (pts.val.get ⟨i.val, hi⟩) pts.val)
      · exact v_post1
      · exact hlen
      · intro h0; rw [v_post3 h0, hH0]
      · exact hH0
      · intro k hk hk_pos
        rw [v_post2 k hk hk_pos, hscale_eq]
  · -- panic path (¬b = true): derive contradiction
    simp only [WP.spec_fail]
    have hpi_eq : pi = pts.val.get ⟨i.val, hi⟩ := by grind
    have hH0 : hornerAccum
        (pts.val.get ⟨i.val, hi⟩).x self.coefficients.val 0 = 0 := by
      rw [hornerAccum_zero_eq_eval]
      unfold Poly.evalAt Poly.toGF216Poly at heval
      exact heval
    have hlv_val_zero : left_val.value.val = 0 :=
      GF16_toGF216_eq_zero_imp left_val (by grind)
    have hlv_eq_zero : left_val.value = spqr.encoding.gf.GF16.ZERO.value :=
      UScalar.eq_of_val_eq (by simp only [spqr.encoding.gf.GF16.ZERO]; exact hlv_val_zero)
    exact absurd (b_post.mpr hlv_eq_zero) ‹¬b = true›

end spqr.encoding.polynomial.Poly
