/-
Copyright 2026 The Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE-APACHE.
Authors: Hoang Le Truong
-/
import Spqr.Math.Poly.Coeff.ListOps
import Spqr.Math.Poly.Eval
import Spqr.Specs.Encoding.Gf.GF16.AddAssign

/-! # Spec theorem for `spqr::encoding::polynomial::{spqr::encoding::polynomial::Poly}::add_assign`

Computes `self + other` in `GF216[X]` by iterating over `other`'s coefficients via
`deref → iter → enumerate → add_assign_loop`.

**Source**: spqr/src/encoding/polynomial.rs -/
open Aeneas Aeneas.Std Result ControlFlow spqr.encoding.gf Polynomial spqr.encoding.polynomial
open  core.iter.adapters.enumerate core.slice.iter

namespace spqr.encoding.polynomial.Poly.add_assign_loop

lemma usize_checked_add_one_val (x : Usize)
    (h : x.val + 1 ≤ Usize.max) :
    ∃ (y : Usize), (x + 1#usize : Result Usize) = ok y ∧ y.val = x.val + 1 := by
  have h_add : x.val + (1#usize : Usize).val ≤ Usize.max := by scalar_tac
  have h_spec := Usize.add_spec h_add
  revert h_spec
  generalize (x + 1#usize : Result Usize) = res
  intro h_spec
  match res with
  | .ok z => exact ⟨z, rfl, by simp_all [WP.spec_ok]⟩
  | .fail e => simp_all
  | .div => simp_all

lemma EnumerateSliceIter_next_post
    (iter : Enumerate (Iter GF16))
    (h_bound : iter.iter.i < iter.iter.slice.length → iter.count.val + 1 ≤ Usize.max) :
    ∃ (opt : Option (Usize × GF16))
      (iter' : Enumerate (Iter GF16)),
      IteratorEnumerate.next
        (core.iter.traits.iterator.IteratorSliceIter GF16) iter =
          ok (opt, iter') := by
  simp only [IteratorEnumerate.next,
    IteratorSliceIter.next]
  split
  · have h_add_bound : iter.count.val + 1 ≤ Usize.max := h_bound (by scalar_tac)
    obtain ⟨count', h_add_eq, _⟩ := usize_checked_add_one_val iter.count h_add_bound
    rw [h_add_eq]
    exact ⟨_, _, rfl⟩
  · exact ⟨_, _, rfl⟩

/-- **Spec theorem for `encoding.polynomial.Poly.add_assign_loop.body`**:

One iteration step. Returns **done** (unchanged `self`) when the iterator is exhausted,
or **cont** with `(i, v)` where:
- **In-range** (`i < len`): `self'[i].toGF216 = self[i].toGF216 + v.toGF216`, length and
  other positions preserved.
- **Extension** (`i ≥ len`): `self'.coefficients = self.coefficients ++ [v]`.

Requires `self.degree < Usize.max`.

**Source**: spqr/src/encoding/polynomial.rs -/
@[step]
theorem body_spec
    (iter : Enumerate (Iter GF16)) (self : Poly)
    (h_self_len : self.degree < Usize.max)
    (h_count_bound : iter.iter.i < iter.iter.slice.length → iter.count.val + 1 ≤ Usize.max) :
    body iter self ⦃ cf =>
      match cf with
      | ControlFlow.done self' => self' = self
      | ControlFlow.cont (_, self') =>
          ∃ (i : Usize) (v : GF16),
            (i < self.degree →
              self'.degree = self.degree ∧
              (∀ (_ : i < self'.degree),
                (self'.coefficients[i]!).toGF216 = (self.coefficients[i]!).toGF216 + v.toGF216) ∧
              (∀ k ≠ i.val, self'.coefficients.val[k]! = self.coefficients.val[k]!)) ∧
            (¬ i.val < self.degree → self'.coefficients.val = self.coefficients.val ++ [v]) ⦄ := by
  unfold body
  obtain ⟨opt, iter1, hnext⟩ := EnumerateSliceIter_next_post iter h_count_bound
  rw [hnext]
  simp only [bind_tc_ok, degree]
  cases opt with
  | none => simp [WP.spec_ok]
  | some p =>
    obtain ⟨i, v⟩ := p
    step*
    · simp_all only [alloc.vec.Vec.set_val_eq, degree]
      refine ⟨ i, v, by grind⟩
    · simp_all [degree]

/-! # Spec theorem for `Poly::add_assign`: loop 0

The loop maintains the invariant `self.toGF216Poly = self₀.toGF216Poly +
listToGF216Poly (other_coeffs.take k)` after `k` steps. When exhausted, yields the full sum.

Preconditions: `h_iter_data` (iterator matches `other_coeffs`), `h_count_eq` (counter = index),
`h_start` (starts at 0), `h_len` (combined length ≤ `Usize.max`).

**Source**: spqr/src/encoding/polynomial.rs -/

lemma poly_update_in_range
    (self self' : Poly) (i : Nat) (v : GF16)
    (h_lt : i < self.degree)
    (h_len_eq : self'.degree = self.degree)
    (h_upd : ∀ (h : i < self'.degree),
      self'.coefficients[i].toGF216 = self.coefficients[i].toGF216 + v.toGF216)
    (h_other : ∀ k ≠ i,
      self'.coefficients[k]! = self.coefficients.val[k]!) :
    self'.toGF216Poly = self.toGF216Poly + C (v.toGF216) * X ^ i := by
  unfold Poly.toGF216Poly
  ext m
  simp only [listToGF216Poly_coeff, coeff_add, coeff_C_mul, coeff_X_pow]
  by_cases hm_lt : m < self.coefficients.length
  · have hm_lt' : m < self'.coefficients.length := by grind [degree]
    by_cases hm_eq : m = i
    · grind
    · rw [if_neg hm_eq, mul_zero, add_zero]
      have h_eq := h_other m hm_eq
      grind
  · have hm_lt' : ¬(m < self'.coefficients.length) := by grind [degree]
    grind

lemma poly_update_extension
    (self self' : Poly) (v : GF16)
    (h_ext : self'.coefficients = self.coefficients ++ [v]) :
    self'.toGF216Poly = self.toGF216Poly + C (v.toGF216) * X ^ self.degree := by
  unfold Poly.toGF216Poly
  rw [h_ext]
  exact listToGF216Poly_append_singleton self.coefficients.val v

lemma step_invariant_preservation
    (orig_poly : GF216[X]) (self self' : Poly) (other : List GF16) (k : Nat) (v : GF16)
    (hk : k < other.length)
    (hv : other[k] = v)
    (h_prev : self.toGF216Poly = orig_poly + listToGF216Poly (other.take k))
    (h_step : self'.toGF216Poly = self.toGF216Poly + C (v.toGF216) * X ^ k) :
    self'.toGF216Poly = orig_poly + listToGF216Poly (other.take (k + 1)) := by
  rw [h_step, h_prev]
  have h_take_succ : other.take (k + 1) = other.take k ++ [other[k]] := by simp
  rw [h_take_succ, listToGF216Poly_append_singleton]
  have h_take_len : (other.take k).length = k := by grind [List.length_take]
  rw [h_take_len, hv]
  ring

lemma enumerate_sliceiter_next_some
    (iter : Enumerate (Iter GF16))
    (h_lt : iter.iter.i < iter.iter.slice.length)
    (h_count : iter.count = iter.iter.i)
    (h_bound : iter.iter.slice.length ≤ Usize.max) :
    ∃ (iter1 : Enumerate (Iter GF16)),
      IteratorEnumerate.next
        (core.iter.traits.iterator.IteratorSliceIter GF16) iter =
          ok (some (iter.count, iter.iter.slice.val[iter.iter.i]), iter1) ∧
      iter1.iter.slice = iter.iter.slice ∧
      iter1.iter.i = iter.iter.i + 1 ∧
      iter1.count.val = iter.iter.i + 1 := by
  simp only [
    IteratorEnumerate.next,
    IteratorSliceIter.next]
  have h_lt' : iter.iter.i < (↑iter.iter.slice.len : Nat) := by scalar_tac
  rw [dif_pos h_lt']
  have h_add_bound : iter.count.val + 1 ≤ Usize.max := by
    rw [h_count]
    omega
  obtain ⟨count', h_add_eq, h_add_val⟩ := usize_checked_add_one_val iter.count h_add_bound
  rw [h_add_eq]
  exact ⟨_, rfl, rfl, rfl, by rw [h_add_val, h_count]⟩

private theorem body_cont_spec
    (iter' : Enumerate (Iter GF16)) (self' : Poly)
    (h_count' : iter'.count = iter'.iter.i)
    (h_lt : iter'.iter.i < iter'.iter.slice.length)
    (h_bound' : iter'.iter.slice.length ≤ Usize.max) :
    body iter' self' ⦃ cf =>
      match cf with
      | ControlFlow.done _ => False
      | ControlFlow.cont (iter'', self'') =>
          iter''.iter.slice = iter'.iter.slice ∧
          iter''.iter.i = iter'.iter.i + 1 ∧
          iter''.count.val = iter'.iter.i + 1 ∧
          (∃ (_ : iter'.iter.i < iter'.iter.slice.length)
           (i : Nat) (v : GF16),
            i = iter'.iter.i ∧
            v = iter'.iter.slice[iter'.iter.i] ∧
            (i < self'.degree →
              self''.degree = self'.degree ∧
              (∀ (_ : i < self''.degree),
                self''.coefficients[i].toGF216 = self'.coefficients[i]!.toGF216 + v.toGF216) ∧
              (∀ k ≠ i, self''.coefficients[k]! = self'.coefficients[k]!)) ∧
            (¬ i < self'.degree → self''.coefficients = self'.coefficients ++ [v])) ⦄ := by
  obtain ⟨iter1, h_next, h_iter1_slice, h_iter1_i, h_iter1_count⟩ :=
    enumerate_sliceiter_next_some iter' h_lt h_count' h_bound'
  unfold body
  rw [h_next]
  simp only [degree]
  step*
  simp_all only [alloc.vec.Vec.set_val_eq,  ne_eq, true_and, not_lt]
  grind

private theorem body_test_done_spec
    (iter' : Enumerate (Iter GF16)) (self' : Poly)
    (h_not_lt : ¬(iter'.iter.i < iter'.iter.slice.length)) :
    body iter' self' ⦃ cf =>
      match cf with
      | ControlFlow.done result => result = self'
      | ControlFlow.cont _ => False ⦄ := by
  unfold body
  simp only [IteratorEnumerate.next, IteratorSliceIter.next]
  split
  · rename_i h_lt
    exact absurd h_lt h_not_lt
  · simp [WP.spec_ok]

/-- **Spec theorem for `encoding.polynomial.Poly.add_assign_loop`**:

Iterates over all `(i, v)` pairs and returns `result` with
`result.toGF216Poly = self.toGF216Poly + listToGF216Poly other_coeffs`.
Total when preconditions hold. With a fresh iterator from `other.coefficients`, this gives
`result.toGF216Poly = self.toGF216Poly + other.toGF216Poly`.

**Source**: spqr/src/encoding/polynomial.rs -/
@[step]
theorem loop_spec
    (iter : Enumerate (Iter GF16)) (self : Poly) (other : List GF16)
    (h_iter_data : iter.iter.slice.val.drop iter.iter.i = other)
    (h_count_eq : iter.count = iter.iter.i)
    (h_start : iter.iter.i = 0)
    (h_len : max self.degree other.length < Usize.max) :
    add_assign_loop iter self ⦃ (result : Poly) =>
      result.degree = max self.degree other.length ∧
      result.toGF216Poly = self.toGF216Poly + listToGF216Poly other ⦄ := by
  unfold add_assign_loop
  apply loop.spec_decr_nat
    (measure := fun (p : Enumerate (Iter GF16) × Poly) => p.1.iter.slice.length - p.1.iter.i)
    (inv := fun (p : Enumerate (Iter GF16) × Poly) =>
        p.1.iter.slice = iter.iter.slice ∧
        iter.iter.i ≤ p.1.iter.i ∧
        p.1.iter.i ≤ p.1.iter.slice.length ∧
        p.1.count = p.1.iter.i ∧
        max p.2.degree (p.1.iter.slice.length - p.1.iter.i) ≤ Usize.max ∧
        p.2.degree = max self.degree p.1.iter.i ∧
        p.2.toGF216Poly =
          self.toGF216Poly + listToGF216Poly (other.take (p.1.iter.i - iter.iter.i)))
  · rintro ⟨iter', self'⟩ ⟨h_slice', h_ge', h_le_slice', h_count', h_len', h_coeff_len', h_poly'⟩
    simp only  at h_slice' h_ge' h_le_slice' h_count' h_len' h_coeff_len' h_poly' ⊢
    by_cases h_more : iter'.iter.i < iter'.iter.slice.length
    · have h_self_len : self'.degree < Usize.max := by grind [degree]
      have h_bound' : iter'.iter.slice.length ≤ Usize.max := by grind
      have h_body := body_cont_spec iter' self' (by omega) h_more h_bound'
      apply WP.spec_mono h_body
      intro cf h_cf
      match cf with
      | ControlFlow.done result => exact h_cf.elim
      | ControlFlow.cont (iter'', self'') =>
        simp only at h_cf ⊢
        obtain ⟨h_slice'', h_i_adv, h_count'', h_lt_slice, i, v, h_i_val, h_v_val,
          h_in_range, h_extension⟩ := h_cf
        have h_k : iter'.iter.i - iter.iter.i < other.length := by grind
        have h_v_eq : other.get ⟨iter'.iter.i - iter.iter.i, h_k⟩ = v := by grind
        have h_k_eq : iter'.iter.i - iter.iter.i = iter'.iter.i := by omega
        have h_poly_step :
          self''.toGF216Poly = self'.toGF216Poly + C (v.toGF216) * X ^ iter'.iter.i := by
          simp only [h_i_val,  List.getElem!_eq_getElem?_getD, ne_eq, alloc.vec.Vec.getElem!_Nat_eq,
            not_lt] at h_in_range h_extension
          by_cases h_lt_coeff : iter'.iter.i < self'.degree
          · obtain ⟨h_len_eq, h_upd, h_other_k⟩ := h_in_range h_lt_coeff
            apply poly_update_in_range self' self'' iter'.iter.i v
            all_goals grind
          · have : self'.degree ≤ iter'.iter.i := by grind
            have h_ext := h_extension this
            have h_len_eq_k : self'.degree = iter'.iter.i := by grind
            have h_poly := poly_update_extension self' self'' v h_ext
            grind
        constructor
        · simp [h_i_val] at h_in_range h_extension
          refine ⟨?_, by omega, ?_, ?_, ?_, ?_, ?_⟩
          · rw [h_slice'', h_slice']
          · grind
          · rw [h_i_adv, h_count'']
          · have h_slice_len : iter''.iter.slice.length = iter'.iter.slice.length := by
              rw [h_slice'']
            by_cases h_lt_coeff : iter'.iter.i < self'.degree
            · omega
            · have : self''.degree = self'.degree + 1 := by grind [degree]
              omega
          · by_cases h_lt_coeff : iter'.iter.i < self'.degree
            · omega
            · have : self''.degree = self'.degree + 1 := by grind[degree]
              omega
          · rw [h_i_adv]
            have h_new_k :
              iter'.iter.i + 1 - iter.iter.i = (iter'.iter.i - iter.iter.i) + 1 := by omega
            rw [h_new_k]
            exact step_invariant_preservation
              self.toGF216Poly self' self'' other
              (iter'.iter.i - iter.iter.i) v h_k h_v_eq h_poly'
              (by rw [h_k_eq]; exact h_poly_step)
        · grind
    · have h_body := body_test_done_spec iter' self' h_more
      apply WP.spec_mono h_body
      grind
  · refine ⟨rfl, le_refl _, ?_, h_count_eq, ?_, ?_, (by simp [List.take_zero])⟩
    all_goals grind

end spqr.encoding.polynomial.Poly.add_assign_loop

namespace spqr.encoding.polynomial.Poly.test

/-- **Spec theorem for `encoding.polynomial.Poly.add_assign`**:

Total when combined length < `Usize.max`. Postcondition:
`result.toGF216Poly = self.toGF216Poly + other.toGF216Poly` (coefficient-wise XOR in char 2). -/
@[step]
theorem add_assign_spec
    (self other : Poly)
    (h_len : max self.degree other.degree < Usize.max) :
    add_assign self other ⦃ (result : Poly) =>
      result.degree = max self.degree other.degree ∧
      result.toGF216Poly = self.toGF216Poly + other.toGF216Poly ⦄ := by
  unfold add_assign
  simp only [alloc.vec.Vec.deref, core.slice.Slice.iter,
             core.slice.iter.IteratorSliceIter.enumerate, bind_tc_ok]
  apply WP.spec_mono (add_assign_loop.loop_spec _ self other.coefficients
    (by simp) (by simp) rfl h_len)
  intro result h
  exact h

end spqr.encoding.polynomial.Poly.test
