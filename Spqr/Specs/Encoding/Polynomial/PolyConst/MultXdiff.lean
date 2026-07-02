/-
Copyright 2026 The Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE-APACHE.
Authors: Hoang Le Truong
-/
import Spqr.Specs.Encoding.Gf.GF16.ZERO
import Spqr.Math.List
import Spqr.Math.Poly.Identities.MultXdiff
import Spqr.Specs.Encoding.Gf.GF16.ConstSub
import Spqr.Specs.Encoding.Gf.GF16.ConstMul

/-! # Spec theorem for `PolyConst::mult_xdiff`: loop body 0

One step of the first loop in `mult_xdiff` (lines 430–440), which builds the `xp` (shifted)
and `dp` (scaled) arrays for computing `(x − difference) · self` in GF(2¹⁶)[X].

- **Done** (`i1 ≥ N`): returns `(xp, dp)` unchanged.
- **Continue** (`i1 < N`): sets `xp[i1+1] := a[i1]` (if `i1 < N−1`),
  `dp[i1] := a[i1] · difference`, and advances `i1`.

**Source**: spqr/src/encoding/polynomial.rs -/

open Aeneas Aeneas.Std Result spqr.encoding.polynomial spqr.encoding.gf Polynomial

namespace spqr.encoding.polynomial.PolyConst.mult_xdiff_loop0

/-- **Spec theorem for `encoding.polynomial.PolyConst.mult_xdiff_loop0.body`**:

Processes one index `i1` of the first loop, building `xp` and `dp`. Succeeds when `i.val < N.val`.

• **Done** (`i1 ≥ N`): `xp' = xp ∧ dp' = dp`.
• **Cont** (`i1 < N`): advances counter (`i2 = i1 + 1`), sets
  `dp1[i1].toGF216 = a[i1].toGF216 * difference.toGF216` (other `dp` positions unchanged),
  and if `i1 < i` sets `xp1[i1+1] = a[i1]` (other `xp` positions unchanged),
  otherwise `xp1 = xp`. -/
@[step]
theorem body_spec
    {N : Usize} (i i1 : Usize) (a xp dp : Array GF16 N) (difference : GF16)
    (h_i_lt_N : i < N) :
    body i a difference xp dp i1 ⦃ cf =>
      match cf with
      | ControlFlow.done (xp', dp') => xp' = xp ∧ dp' = dp ∧ ¬ (i1 < N)
      | ControlFlow.cont (xp1, dp1, i2) =>
          i1 < N ∧
          i2 = i1.val + 1 ∧
          (∀ (h_idx : i1 < dp1.length),
            (dp1.val.get ⟨i1.val, h_idx⟩).toGF216 = (a.val[i1.val]!).toGF216 * difference.toGF216) ∧
          (∀ (j : Nat), j ≠ i1 → dp1.val[j]? = dp.val[j]?) ∧
          (i1 < i → (∀ (h_idx : i1 + 1 < xp1.length),
            xp1.val.get ⟨i1 + 1, h_idx⟩ = a.val[i1.val]!) ∧
            ∀ (j : Nat), j ≠ i1 + 1 → xp1.val[j]? = xp.val[j]?) ∧
          (¬ i1 < i → xp1 = xp) ⦄ := by
  unfold body
  by_cases h_lt : i1.val < N.val
  · simp only [UScalar.lt_equiv, h_lt, ↓reduceIte, not_true_eq_false, and_false,
      List.Vector.length_val, List.get_eq_getElem, getElem!_pos, forall_true_left, ne_eq, not_lt,
      true_and]
    by_cases h_lt_i : i1 < i.val
    · simp only [h_lt_i, ↓reduceIte, bind_assoc, forall_const, isEmpty_Prop, not_le,
        IsEmpty.forall_iff, and_true]
      step*
      all_goals simp_all
    · simp only [h_lt_i, ↓reduceIte, bind_tc_ok, IsEmpty.forall_iff, true_and]
      step*
      all_goals simp_all
  · step*

/-! # Spec theorem for `PolyConst::mult_xdiff`: loop 0

Full first loop wrapper around `body_spec`, iterating `i1 = 0, …, N−1` to build `xp` and `dp`.

**Postcondition**:
- `dp[j].toGF216 = a[j].toGF216 * difference.toGF216` for all `j < N`.
- `xp[j+1] = a[j]` for `j < N−1`; position 0 and out-of-range positions unchanged.

**Source**: spqr/src/encoding/polynomial.rs -/
@[step]
theorem loop_spec
    {N : Usize} (i i1 : Usize) (a xp dp : Array GF16 N) (difference : GF16)
    (h_i_lt_N : i < N)
    (h_i1_le_N : i1 ≤ N)
    (h_dp_inv : ∀ (j : Nat), j < i1 →
        ∀ (hj : j < dp.length),
          (dp.val.get ⟨j, hj⟩).toGF216 =
            (a.val[j]!).toGF216 * difference.toGF216)
    (h_xp_inv : ∀ (j : Nat), j < i1 → j < i →
        ∀ (h_idx : j + 1 < xp.length),
          xp.val.get ⟨j + 1, h_idx⟩ = a.val[j]!) :
    mult_xdiff_loop0 i a difference xp dp i1 ⦃ result =>
      let (xpR, dpR) := result
      (∀ (j : Nat), j < N →
          ∀ (hj : j < dpR.length),
            (dpR.val.get ⟨j, hj⟩).toGF216 = (a.val[j]!).toGF216 * difference.toGF216) ∧
      (∀ (j : Nat), j < i →
          ∀ (h_idx : j + 1 < xpR.length), xpR.val.get ⟨j + 1, h_idx⟩ = a.val[j]!) ∧
      (∀ (j : Nat), ¬(0 < j ∧ j ≤ i) → xpR.val[j]? = xp.val[j]?) ⦄ := by
  unfold mult_xdiff_loop0
  apply loop.spec_decr_nat
    (measure := fun (p : (Array GF16 N) × (Array GF16 N) × Usize) => N - p.2.2)
    (inv := fun (p : (Array GF16 N) × (Array GF16 N) × Usize) =>
        p.2.2 ≤ N ∧
        (∀ (j : Nat), j < p.2.2 →
          ∀ (hj : j < p.2.1.length),
            (p.2.1.val.get ⟨j, hj⟩).toGF216 = (a.val[j]!).toGF216 * difference.toGF216) ∧
        (∀ (j : Nat), p.2.2 ≤ j → p.2.1.val[j]? = dp.val[j]?) ∧
        (∀ (j : Nat), j < p.2.2 → j < i →
          ∀ (h_idx : j + 1 < p.1.length),
            p.1.val.get ⟨j + 1, h_idx⟩ = a.val[j]!) ∧
        (∀ (j : Nat), ¬(0 < j ∧ j ≤ p.2.2 ∧ j ≤ i) →
          p.1.val[j]? = xp.val[j]?))
  · rintro ⟨xp', dp', i1'⟩
      ⟨h_i1_le, h_dp_proc, h_dp_rest, h_xp_shift, h_xp_rest⟩
    simp only [] at h_i1_le h_dp_proc h_dp_rest h_xp_shift h_xp_rest ⊢
    have h_body := body_spec i i1' a xp' dp' difference h_i_lt_N
    apply WP.spec_mono h_body
    intro cf h_cf
    match cf with
    | ControlFlow.done (xp_r, dp_r) => grind
    | ControlFlow.cont (xp1, dp1, i2) =>  grind
  · grind

end spqr.encoding.polynomial.PolyConst.mult_xdiff_loop0

/-! # Spec theorem for `PolyConst::mult_xdiff`: loop body 1

One step of the second loop (lines 446–451), computing `xp[i] := xp[i] − dp[i]` in GF(2¹⁶).

- **Done** (`i ≥ N`): returns `xp` unchanged.
- **Continue** (`i < N`): sets `xp[i] := xp[i] − dp[i]` and advances `i`.

**Source**: spqr/src/encoding/polynomial.rs -/

namespace spqr.encoding.polynomial.PolyConst.mult_xdiff_loop1

/-- **Spec theorem for `encoding.polynomial.PolyConst.mult_xdiff_loop1.body`**:

Processes one index `i` of the second loop, computing `xp[i] := xp[i] − dp[i]`.

• **Done** (`i ≥ N`): `xp' = xp`.
• **Cont** (`i < N`): advances counter (`i1 = i + 1`), sets
  `xp'[i].toGF216 = xp[i].toGF216 - dp[i].toGF216` (other positions unchanged). -/
@[step]
theorem body_spec
    {N : Usize} (dp xp : Array GF16 N) (i : Usize) :
    body dp xp i ⦃ cf =>
      match cf with
      | ControlFlow.done xp' =>
          xp' = xp ∧ ¬ (i < N)
      | ControlFlow.cont (xp', i1) =>
          i < N ∧
          i1 = i.val + 1 ∧
          (∀ (h_idx : i < xp'.length),
            (xp'.val.get ⟨i.val, h_idx⟩).toGF216 =
              (xp.val[i.val]!).toGF216 - (dp.val[i.val]!).toGF216) ∧
          (∀ (j : Nat), j ≠ i → xp'.val[j]? = xp.val[j]?) ⦄ := by
  unfold body
  by_cases h_lt : i.val < N.val
  · simp only [UScalar.lt_equiv, h_lt, ↓reduceIte, not_true_eq_false, and_false,
      List.Vector.length_val, List.get_eq_getElem, getElem!_pos, forall_true_left, ne_eq, true_and]
    step*
    all_goals simp_all
  · step*

/-! # Spec theorem for `PolyConst::mult_xdiff`: loop 1

Full second loop wrapper around `body_spec`, iterating `i = 0, …, N−1` to compute
element-wise `xp[i] := xp[i] − dp[i]` in GF(2¹⁶).

**Postcondition**:
- `xpR[j].toGF216 = xp[j].toGF216 − dp[j].toGF216` for `i ≤ j < N`.
- `xpR[j]? = xp[j]?` for `j < i`.

**Source**: spqr/src/encoding/polynomial.rs -/
@[step]
theorem loop_spec
    {N : Usize} (xp dp : Array GF16 N) (i : Usize)
    (h_i_le_N : i ≤ N) :
    mult_xdiff_loop1 xp dp i ⦃ xpR =>
      (∀ (j : Nat), i ≤ j ∧  j < N →
          ∀ (hj : j < xpR.val.length),
            (xpR.val.get ⟨j, hj⟩).toGF216 = (xp.val[j]!).toGF216 - (dp.val[j]!).toGF216) ∧
      (∀ (j : Nat), j < i → xpR[j]? = xp.val[j]?) ⦄ := by
  unfold mult_xdiff_loop1
  apply loop.spec_decr_nat
    (measure := fun (p : (Array GF16 N) × Usize) => N - p.2)
    (inv := fun (p : (Array GF16 N) × Usize) =>
        i ≤ p.2 ∧
        p.2 ≤ N ∧
        (∀ (j : Nat), i ≤ j → j < p.2 →
          ∀ (hj : j < p.1.length),
            (p.1.val.get ⟨j, hj⟩).toGF216 = (xp.val[j]!).toGF216 - (dp.val[j]!).toGF216) ∧
        (∀ (j : Nat), ¬(i ≤ j ∧ j < p.2) → p.1.val[j]? = xp.val[j]?))
  · rintro ⟨xp', i'⟩ ⟨h_i_le_i', h_i'_le_N, h_xp_proc, h_xp_rest⟩
    simp only at h_i_le_i' h_i'_le_N h_xp_proc h_xp_rest ⊢
    have h_body := body_spec dp xp' i'
    apply WP.spec_mono h_body
    grind
  · grind

end spqr.encoding.polynomial.PolyConst.mult_xdiff_loop1

/-! # Spec theorem for
`spqr::encoding::polynomial::{spqr::encoding::polynomial::PolyConst<N>}::mult_xdiff`

Computes `(x − diff) · self` in GF(2¹⁶)[X] by composing loop 0 (build `xp`, `dp`)
and loop 1 (element-wise `xp − dp`). Requires the polynomial degree to be strictly less
than `N − 1` (equivalently, `degree + 1 < N`), so that multiplying by a linear factor
keeps the result within the `N`-coefficient representation.

The postcondition is the polynomial identity:
  `listToGF216Poly result.coefficients.val =
     (X − C (diff.toGF216)) * listToGF216Poly self.coefficients.val`

**Source**: spqr/src/encoding/polynomial.rs -/

namespace spqr.encoding.polynomial.PolyConst

/-- **Spec theorem for `encoding.polynomial.PolyConst.mult_xdiff`**:

Succeeds when `0 < N` and the polynomial degree of `self` satisfies `self.degree + 1 < N`
(i.e., the polynomial fits in `N − 1` coefficients, leaving room for the degree-raising
multiplication by `(X − diff)`).

• **Postcondition**:
  `listToGF216Poly result.coefficients =
     (X − C (diff.toGF216)) * listToGF216Poly self.coefficients` -/
@[step]
theorem mult_xdiff_spec
    {N : Usize} (self : PolyConst N) (diff : GF16)
    (h_N_pos : 0 < N.val)
    (h_deg : self.degree + 1 < N) :
    mult_xdiff self diff ⦃ (result : PolyConst N) =>
      listToGF216Poly result.coefficients =
        (X - C (diff.toGF216)) * listToGF216Poly self.coefficients ⦄ := by
  have h_leading_zero  := getElem!_value_val_eq_zero_of_natDegree_lt self.coefficients.val N
    h_N_pos h_deg
  unfold mult_xdiff
  step*
  · grind
  apply @mult_xdiff_result_eq N (self.coefficients) diff i xp1 dp1 xp2 h_N_pos i_post1
  all_goals simp_all

end spqr.encoding.polynomial.PolyConst
