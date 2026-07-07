/-
Copyright 2026 The Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE-APACHE.
Authors: Hoang Le Truong
-/
import SrcTranslated.Funs
import Spqr.Specs.Encoding.Gf.GF16.New
import Spqr.Math.Poly.Basic.Defs
import Spqr.Specs.Encoding.Polynomial.PolyConst.LagrangeInterpolatePt
/-! # Spec theorem for `lagrange_polys_for_complete_points`: loop body 0

Specifies one iteration of the initialisation loop in `lagrange_polys_for_complete_points`.
The loop sets `ones[i].x.value = i as u16` and keeps
`ones[i].y = GF16::ONE`, building the "complete points" `0, 1, …, N−1` in GF(2¹⁶).

- **Done** (`i ≥ N`): returns `ones` unchanged.
- **Continue** (`i < N`): updates `ones[i].x.value := i`, leaves other entries intact, increments
  `i`.

After all `N` iterations, `ones[j].x.toGF216 = Nat.toGF216 j` and `ones[j].y = GF16::ONE`.

**Source**: spqr/src/encoding/polynomial.rs -/

open Aeneas Aeneas.Std Result spqr.encoding.polynomial spqr.encoding.gf Polynomial
open spqr.encoding.polynomial.PolyConst.lagrange_interpolate_pt_loop

namespace spqr.encoding.polynomial.lagrange_polys_for_complete_points_loop0

/-- **Spec theorem for `encoding.polynomial.lagrange_polys_for_complete_points_loop0.body`**:

One step setting `ones[i].x.value := i` (cast `usize → u16`) and `ones[i].y := GF16.ONE`.

- **Done** (`i ≥ N`): `ones' = ones`, loop terminates.
- **Cont** (`i < N`): `i1 = i + 1`; `ones1[i].x.value.val = i.val`, `ones1[i].y = GF16.ONE`;
  other positions unchanged.

No panic when `i < N ≤ 65536` (array access, cast, and increment all in bounds). -/
@[step]
theorem body_spec
    {N : Usize} (ones : Array Pt N) (i : Usize)
    (h_N_bound : N.val ≤ 65536) :
    body ones i ⦃ (cf : ControlFlow (Std.Array Pt N × Usize) (Std.Array Pt N)) =>
      match cf with
      | ControlFlow.done ones' => ones' = ones ∧ ¬ (i < N)
      | ControlFlow.cont (ones1, i1) =>
          i < N ∧
          i1 = i.val + 1 ∧
          (∀ (_ : i < ones1.length),
            (ones1[i]!).x.value.val = i.val ∧
            (ones1[i]!).y = GF16.ONE) ∧
          (∀ (j : Nat), j ≠ i → ones1[j]! = ones[j]!) ⦄ := by
  unfold body
  by_cases h_lt : i.val < N.val
  · simp only [UScalar.lt_equiv, h_lt, ↓reduceIte, not_true_eq_false, and_false, ne_eq, true_and]
    step*
    all_goals (simp_all [UScalar.cast_val_eq]; sorry)
  · step*

/-! # Spec theorem for `spqr::encoding::polynomial::lagrange_polys_for_complete_points`: loop 0

The `loop` wrapper iterating `body_spec` over `i = 0, …, N−1` to initialise the point array.

**Closed-form postcondition** (starting from index `i`):
- Processed positions (`i ≤ j < N`): `result[j].x.value.val = j`, `result[j].y = GF16.ONE`.
- Unprocessed positions (`j < i`): `result[j]? = ones[j]?`.

Starting at `i = 0`, all positions are processed.

**Source**: spqr/src/encoding/polynomial.rs -/
@[step]
theorem loop_spec
    {N : Usize} (ones : Array Pt N) (i : Usize)
    (h_N_bound : N.val ≤ 65536)
    (h_i_le_N : i ≤ N) :
    lagrange_polys_for_complete_points_loop0 ones i ⦃ (result : Std.Array Pt N) =>
      (∀ (j : Nat), i ≤ j ∧  j < N →
        (result[j]!).x.value.val = j ∧
        (result[j]!).y = GF16.ONE) ∧
      (∀ (j : Nat), j < i → result[j]! = ones[j]!) ⦄ := by
  unfold lagrange_polys_for_complete_points_loop0
  apply loop.spec_decr_nat
    (measure := fun (p : (Array Pt N) × Usize) => N - p.2)
    (inv := fun (p : (Array Pt N) × Usize) =>
        i ≤ p.2 ∧
        p.2 ≤ N ∧
        (∀ (j : Nat), i ≤ j → j < p.2 →
            (∀ (hj : j < p.1.length),
            (p.1[j]!).x.value.val = j ∧
            (p.1[j]!).y = GF16.ONE)) ∧
        (∀ (j : Nat), ¬(i ≤ j ∧ j < p.2) → p.1[j]! = ones[j]!))
  · rintro ⟨ones', i'⟩ ⟨h_i_le_i', h_i'_le_N, h_proc, h_rest⟩
    simp only at h_i_le_i' h_i'_le_N h_proc h_rest ⊢
    have h_body := body_spec ones' i' h_N_bound
    apply WP.spec_mono h_body
    intro cf h_cf
    match cf with
    | ControlFlow.done result => grind
    | ControlFlow.cont (ones1, i1) =>
      obtain ⟨h_lt, h_i1, h_at_i, h_others⟩ := h_cf
      refine ⟨⟨by grind, by grind, fun j h_ij h_ji1 h_idx => ?_, fun j h_not => by grind⟩, by grind⟩
      · by_cases h_eq : j = i'.val
        · subst h_eq
          exact h_at_i h_idx
        · grind
  · grind

end spqr.encoding.polynomial.lagrange_polys_for_complete_points_loop0

/-! # Spec theorem for `lagrange_polys_for_complete_points`: loop body 1

Specifies one iteration of the second loop (lines 488–493) which computes
`out[i] = PolyConst::<N>::lagrange_interpolate_pt(&ones, i)`.

- **Done** (`i ≥ N`): returns `out` unchanged.
- **Continue** (`i < N`): converts `ones` to a slice, calls `lagrange_interpolate_pt` to get
  the `i`-th scaled Lagrange basis polynomial, stores it in `out[i]`, increments `i`.

Each `out[j]` is the `j`-th term of the Lagrange interpolation formula.  For distinct
`x`-coordinates the Fermat exponent `(2¹⁶ − 2)` yields the inverse, giving the standard basis.

**Source**: spqr/src/encoding/polynomial.rs -/

namespace spqr.encoding.polynomial.lagrange_polys_for_complete_points_loop1

/-- **Spec theorem for `encoding.polynomial.lagrange_polys_for_complete_points_loop1.body`**:

One step computing `out[i] := lagrange_interpolate_pt(&ones, i)`.

- **Done** (`i ≥ N`): `out' = out`, loop terminates.
- **Cont** (`i < N`): `i1 = i + 1`; `out1[i]` stores the `i`-th scaled Lagrange basis polynomial;
  other positions unchanged.

No panic when `0 < N` and `i < N` (slice conversion, interpolation, update, and increment all
succeed). -/
@[step]
theorem body_spec
    {N : Usize} (ones : Array Pt N) (out : Array (PolyConst N) N) (i : Usize)
    (h_N_pos : 0 < N.val) :
    body ones out i ⦃ cf =>
      match cf with
      | ControlFlow.done out' => out' = out ∧ ¬ (i < N)
      | ControlFlow.cont (out1, i1) =>
          i < N ∧
          i1 = i.val + 1 ∧
          (∀ (h_idx : i < out1.length) (hi : i < ones.length),
            listToGF216Poly (out1[i].coefficients) =
              C ((ones[i]).y.toGF216 * (lagrangeDenomProd (ones[i]!).x
                    (ones.val.take N.val) 0) ^ (2 ^ 16 - 2)) *
                    condProdLinearFactors (ones[i]!).x (ones.val.take N.val) 0) ∧
          (∀ j < out.length, (_: j ≠ i.val) →  out1[j]? = out[j]?) ⦄ := by
  unfold body
  by_cases h_lt : i.val < N.val
  · simp only [UScalar.lt_equiv, h_lt, ↓reduceIte, true_and]
    step*
    subst s_post a_post
    simp_all [Array.to_slice]
  · step*

/-!
# Spec theorem for `spqr::encoding::polynomial::lagrange_polys_for_complete_points`: loop 1

The `loop` wrapper iterating `body_spec` over `i = 0, …, N−1` to fill `out` with Lagrange
basis polynomials.

**Closed-form postcondition** (starting from index `i`):
- Processed positions (`i ≤ j < N`): `result[j]` holds the `j`-th scaled Lagrange basis
  polynomial for the evaluation points in `ones`.
- Unprocessed positions (`j < i`): `result[j]? = out[j]?`.

Starting at `i = 0`, all positions are processed.

**Source**: spqr/src/encoding/polynomial.rs -/
@[step]
theorem loop_spec
    {N : Usize} (ones : Array Pt N) (out : Array (PolyConst N) N) (i : Usize)
    (h_N_pos : 0 < N.val)
    (h_i_le_N : i ≤ N) :
    lagrange_polys_for_complete_points_loop1 ones out i ⦃ result =>
      (∀ (j : Nat), i ≤ j ∧ j < N →
          ∀ (hj : j < result.length) (hjo : j < ones.length),
            listToGF216Poly (result.val[j]).coefficients.val =
              C ((ones.val[j]!).y.toGF216 *
                  (lagrangeDenomProd (ones[j]!).x (ones.val.take N.val) 0) ^ (2 ^ 16 - 2)) *
                condProdLinearFactors (ones[j]!).x (ones.val.take N.val) 0) ∧
      (∀ (j : Nat), j < i → result[j]? = out[j]?) ⦄ := by
  unfold lagrange_polys_for_complete_points_loop1
  apply loop.spec_decr_nat
    (measure := fun (p : (Array (PolyConst N) N) × Usize) => N - p.2)
    (inv := fun (p : (Array (PolyConst N) N) × Usize) =>
        i ≤ p.2 ∧
        p.2 ≤ N ∧
        (∀ (j : Nat), i ≤ j → j < p.2 →
          ∀ (hj : j < p.1.length) (hjo : j < ones.length),
            listToGF216Poly (p.1.val[j]).coefficients.val =
              C ((ones.val[j]!).y.toGF216 *
                  (lagrangeDenomProd (ones[j]!).x
                    (ones.val.take N.val) 0) ^ (2 ^ 16 - 2)) *
                condProdLinearFactors (ones[j]!).x
                  (ones.val.take N.val) 0) ∧
        (∀ (j : Nat), ¬(i ≤ j ∧ j < p.2) →
          p.1[j]? = out[j]?))
  · rintro ⟨out', i'⟩ ⟨h_i_le_i', h_i'_le_N, h_proc, h_rest⟩
    simp only at h_i_le_i' h_i'_le_N h_proc h_rest ⊢
    have h_body := body_spec ones out' i' h_N_pos
    apply WP.spec_mono h_body
    grind
  · refine ⟨le_refl _, h_i_le_N, fun _ h1 h2 => absurd h2 (by grind), fun _ _ => rfl⟩

end spqr.encoding.polynomial.lagrange_polys_for_complete_points_loop1

/-! # Spec theorem for `spqr::encoding::polynomial::lagrange_polys_for_complete_points`

Precomputes the `N` Lagrange basis polynomials for "complete points" `0, 1, …, N−1` in GF(2¹⁶).
Two phases:
1. **Loop 0** (lines 477–482): initialises `ones[j].x.value = j`, `ones[j].y = GF16::ONE`.
2. **Loop 1** (lines 488–493): fills `out[j] = lagrange_interpolate_pt(&ones, j)`.

**Postcondition**: there exists `ones1` with `ones1[j].x.value.val = j`, `ones1[j].y = GF16.ONE`,
and each `result[j]` is the `j`-th scaled Lagrange basis polynomial for the points in `ones1`.

**Source**: spqr/src/encoding/polynomial.rs -/

namespace spqr.encoding.polynomial

/-- **Spec theorem for `encoding.polynomial.lagrange_polys_for_complete_points`**:

Returns the `N`-element array of Lagrange basis polynomials for complete points `0, …, N−1`
in GF(2¹⁶).  Delegates to loop 0 (point init) then loop 1 (basis computation).
There exists an intermediate `ones1` such that:
- `ones1[j].x.value.val = j` and `ones1[j].y = GF16.ONE` for all `j < N`.
- `result[j]` stores the `j`-th scaled Lagrange basis polynomial for those points.
No panic when `0 < N ≤ 65536`. -/
@[step]
theorem lagrange_polys_for_complete_points_spec
    (N : Usize) (h_N_pos : 0 < N.val)
    (h_N_bound : N.val ≤ 65536) :
    lagrange_polys_for_complete_points N ⦃ (result : Std.Array (PolyConst N) N) =>
      ∃ (ones1 : Array Pt N),
        (∀ (j : Nat), j < N.val →
          (ones1[j]!).x.value.val = j ∧
          (ones1[j]!).y = GF16.ONE) ∧
        (∀ (j : Nat), j < N.val →
          ∀ (hj : j < result.length) (hjo : j < ones1.length),
            listToGF216Poly (result.val[j]).coefficients.val =
              C ((ones1.val[j]!).y.toGF216 *
                  (lagrangeDenomProd (ones1[j]!).x (ones1.val.take N.val) 0) ^ (2 ^ 16 - 2)) *
                condProdLinearFactors (ones1[j]!).x (ones1.val.take N.val) 0) ⦄ := by
  unfold lagrange_polys_for_complete_points
  step*
  exact ⟨ones1, fun j hj => ones1_post1 j (Nat.zero_le j) hj,
         fun j hj => result_post1 j (Nat.zero_le j) hj⟩

end spqr.encoding.polynomial
