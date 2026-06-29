/-
Copyright 2026 The Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE-APACHE.
Authors: Hoang Le Truong
-/
import Spqr.Math.List
import Spqr.Specs.Encoding.Gf.GF16.ConstMul
/-! # Spec theorem for `encoding.polynomial.PolyConst.mult_loop.body`

`PolyConst::mult` (`src/encoding/polynomial.rs`, lines 398:4-410:5) scales each coefficient
of a constant-sized polynomial `self` by a field element `m` in GF(2¹⁶)[X].

This file specifies **loop body 0** — one step of the loop (lines 403:8-408:9) in
`encoding.polynomial.PolyConst.mult_loop.body`:
  - **Done** (`i ≥ N`): returns `a` unchanged.
  - **Continue** (`i < N`): sets `a[i] := a[i].const_mul(m)` and advances `i1 = i + 1`.

GF(2¹⁶) multiplication is carry-less polynomial multiplication mod `x¹⁶+x¹²+x³+x+1` (0x1100b).

**Source**: spqr/src/encoding/polynomial.rs-/

open Aeneas Aeneas.Std spqr.encoding.gf Polynomial

namespace spqr.encoding.polynomial.PolyConst.mult_loop

/--
**Spec theorem for `encoding.polynomial.PolyConst.mult_loop.body`**:

One step of the scalar-multiplication loop; always succeeds.

• **done** (`i ≥ N`): `a' = a`.
• **cont** (`i < N`): `i1.val = i.val + 1`, position `i` gets the GF(2¹⁶) product
  `a1[i].toGF216 = a[i].toGF216 * m.toGF216` (in `GF216 = GaloisField 2 16`), and all
  other positions are unchanged (`a1[j]? = a[j]?` for `j ≠ i`). -/
@[step]
theorem body_spec
    {N : Usize} (m : GF16) (i : Usize) (a : Array GF16 N) :
    body m i a ⦃ cf =>
      match cf with
      | ControlFlow.done a' =>
          a' = a ∧ ¬ (i < N)
      | ControlFlow.cont (i1, a1) =>
          i < N ∧
          i1 = i.val + 1 ∧
          (∀ (h_idx : i < a1.length),
            (a1.val.get ⟨i, h_idx⟩).toGF216 = (a.val[i.val]!).toGF216 * m.toGF216) ∧
          (∀ (j : Nat), j ≠ i.val → a1.val[j]? = a.val[j]?) ⦄ := by
  unfold body
  by_cases h_lt : i.val < N.val
  · simp only [UScalar.lt_equiv, h_lt, ↓reduceIte, not_true_eq_false, and_false,
      List.Vector.length_val, List.get_eq_getElem, getElem!_pos, forall_true_left, ne_eq, true_and]
    step*
    grind
  · step*

/-! # Spec theorem for `PolyConst::mult`: loop 0

This file specifies **loop 0** — the `loop` fixed-point wrapper around the body, iterating
over `i = 0, …, N−1` and scaling each coefficient of the output array by `m`.

Closed-form postcondition (from `i` to `N−1`):
  - **Processed** (`i ≤ j < N`): `result[j].toGF216 = a[j].toGF216 * m.toGF216`
    (in `GF216 = GaloisField 2 16`).
  - **Unprocessed** (`j < i`): `result[j]? = a[j]?`.

Called with `i = 0`, every position is scaled, giving the polynomial product `m · self`.

GF(2¹⁶) multiplication is carry-less polynomial multiplication mod `x¹⁶+x¹²+x³+x+1` (0x1100b).

**Source**: spqr/src/encoding/polynomial.rs -/
@[step]
theorem loop_spec
    {N : Usize} (m : GF16) (i : Usize) (a : Array GF16 N)
    (h_i_le_N : i ≤ N) :
    mult_loop m i a ⦃ result =>
      (∀ (j : Nat), i ≤ j ∧  j < N → (result.val[j]!).toGF216 = (a.val[j]!).toGF216 * m.toGF216) ∧
      (∀ (j : Nat), j < i → result.val[j]! = a.val[j]!) ⦄ := by
  unfold mult_loop
  apply loop.spec_decr_nat
    (measure := fun (p : Usize × (Array GF16 N)) => N - p.1)
    (inv := fun (p : Usize × (Array GF16 N)) =>
        i ≤ p.1 ∧
        p.1 ≤ N ∧
        (∀ (j : Nat), i ≤ j ∧ j < p.1 → (p.2.val[j]!).toGF216 = (a.val[j]!).toGF216 * m.toGF216) ∧
        (∀ (j : Nat), ¬(i ≤ j ∧ j < p.1) → p.2.val[j]! = a.val[j]!))
  · rintro ⟨i', a'⟩ ⟨h_i_le_i', h_i'_le_N, h_a_proc, h_a_rest⟩
    simp only at h_i_le_i' h_i'_le_N h_a_proc h_a_rest ⊢
    have h_body := body_spec m i' a'
    apply WP.spec_mono h_body
    intro cf h_cf
    match cf with
    | ControlFlow.done a_r => grind
    | ControlFlow.cont (i1, a1) => grind[list_get_of_getElem?_eq]
  · refine ⟨le_refl _, h_i_le_N, by grind, fun _ _ => rfl⟩

end spqr.encoding.polynomial.PolyConst.mult_loop

/-!
# Spec theorem for `spqr::encoding::polynomial::{spqr::encoding::polynomial::PolyConst<N>}::mult`

`PolyConst::mult` (`src/encoding/polynomial.rs`, lines 398:4-410:5) scales each coefficient of
`self` by `m` in GF(2¹⁶)[X]. The extracted function just runs `mult_loop` (from `i = 0`) and
re-wraps the result into a `PolyConst`.

Since every coefficient is scaled by `m`, the result equals multiplication by the constant
polynomial `C m`:
  `listToGF216Poly result.coefficients.val = C (m.toGF216) * listToGF216Poly self.coefficients.val`
This is proved by composing `mult_loop.loop_spec` with the coefficient-wise identity
`(C m · p).coeff j = m · p.coeff j` (commutativity of GF(2¹⁶) multiplication).

GF(2¹⁶) multiplication is carry-less polynomial multiplication mod `x¹⁶+x¹²+x³+x+1` (0x1100b).

**Source**: spqr/src/encoding/polynomial.rs -/

namespace spqr.encoding.polynomial.PolyConst

private lemma mult_result_eq
    {N : Usize} (a : Array GF16 N) (m : GF16) (result : Array GF16 N)
    (h_scaled : ∀ (j : Nat), j < N →
      ∀ (_ : j < result.length), (result[j]).toGF216 = (a.val[j]!).toGF216 * m.toGF216) :
    listToGF216Poly result = C (m.toGF216) * listToGF216Poly a := by
  apply listToGF216Poly_eq_of_coeffs
  · grind [← getElem!_toGF216_eq_coeff]
  · intro j hj
    simp only [List.Vector.length_val] at hj
    rw [coeff_C_mul, listToGF216Poly_coeff_eq_zero _ j (by grind), mul_zero]

/-- **Spec theorem for `encoding.polynomial.PolyConst.mult`**:

Always succeeds, with the scalar-multiplication postcondition
  `listToGF216Poly result.coefficients = C (m.toGF216) * listToGF216Poly self.coefficients`
where `listToGF216Poly` reads a `List GF16` as a polynomial in `GF216[X]` and `C` is the constant
embedding. Proved by composing `mult_loop.loop_spec` with `mult_result_eq`. -/
@[step]
theorem mult_spec
    {N : Usize} (self : PolyConst N) (m : GF16) :
    mult self m ⦃ (result : PolyConst N) =>
      listToGF216Poly result.coefficients =
        C (m.toGF216) * listToGF216Poly self.coefficients ⦄ := by
  unfold mult
  step*
  apply @mult_result_eq N self.coefficients m a
  all_goals simp_all

end spqr.encoding.polynomial.PolyConst
