/-
Copyright 2026 The Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE-APACHE.
Authors: Hoang Le Truong
-/
import SrcTranslated.Funs

/-!
# Spec theorems for `core::slice::iter::{Iterator for Iter<'_, T>}::next`

In Rust's standard library, `Iter<'_, T>` is the immutable iterator over a slice `&[T]`.  The `next`
method advances the internal cursor by one position:

  * If the cursor `i` is within bounds (`i < slice.len()`), it yields `Some(&slice[i])` and sets
    `i ← i + 1`.
  * If the cursor is at or past the end (`i ≥ slice.len()`), it yields `None` and leaves the
    iterator unchanged.

The Aeneas-extracted Lean function `core.slice.iter.IteratorSliceIter.next` mirrors this behavior.

Three equivalent formulations are provided:

  1. `next_spec` — a `WP.spec` form suitable for use with `@[step]` and the `step*` tactic.
  2. `next_ok` — a bare existential asserting that `next` always returns `ok`.
  3. `next_post` — a full existential with named witnesses and both-branch postconditions,
     matching the style used in `PolyEncoder.into_pb_loop1.body`.

**Source**: core/src/slice/iter.rs (Iterator impl for Iter)
-/

open Aeneas Aeneas.Std Result

namespace Aeneas.Std.core.slice.iter.IteratorSliceIter

/--
**Spec theorem for `core.slice.iter.IteratorSliceIter.next`** (WP form):

The slice iterator `next` always succeeds and either:
  * yields `none` when the iterator is exhausted (`i ≥ slice.len`), leaving the iterator unchanged;
  * yields `some x` with `x = slice[i]`, advancing the cursor to `i + 1`.

**Source**: core/src/slice/iter.rs (Iterator impl for Iter)
-/
@[step]
theorem next_spec {T : Type}
    (iter : core.slice.iter.Iter T) :
    core.slice.iter.IteratorSliceIter.next iter
      ⦃ (opt, iter') =>
        match opt with
        | none => ¬ iter.i < iter.slice.len ∧ iter' = iter
        | some _ =>
            iter.i < iter.slice.len ∧
            iter'.slice = iter.slice ∧
            iter'.i = iter.i + 1 ⦄ := by
  suffices h : ∃ opt iter',
      core.slice.iter.IteratorSliceIter.next iter
        = ok (opt, iter') ∧
      match opt with
      | none => ¬ iter.i < iter.slice.len ∧ iter' = iter
      | some _ =>
          iter.i < iter.slice.len ∧
          iter'.slice = iter.slice ∧
          iter'.i = iter.i + 1 by
    obtain ⟨opt, iter', heq, hpost⟩ := h
    rw [heq]; simp only [WP.spec_ok]
    exact hpost
  simp only [core.slice.iter.IteratorSliceIter.next]
  by_cases hlt : iter.i < iter.slice.len
  · rw [dif_pos hlt]
    exact ⟨some (iter.slice[iter.i]),
           { iter with i := iter.i + 1 }, rfl,
           hlt, rfl, rfl⟩
  · rw [dif_neg hlt]
    exact ⟨none, iter, rfl,
           hlt, rfl⟩

/--
**Totality lemma for `core.slice.iter.IteratorSliceIter.next`**:

`next` always succeeds — it returns `ok (o, iter')` for some option `o` and iterator `iter'`.
This is used in body proofs to extract the result and case-split on the option.

**Source**: core/src/slice/iter.rs (Iterator impl for Iter)
-/
theorem next_ok {T : Type}
    (iter : core.slice.iter.Iter T) :
    ∃ o iter1,
      core.slice.iter.IteratorSliceIter.next iter = ok (o, iter1) := by
  unfold core.slice.iter.IteratorSliceIter.next
  split <;> exact ⟨_, _, rfl⟩

/--
**Spec theorem for `core.slice.iter.IteratorSliceIter.next`** (existential form):

An alternative formulation with named witnesses for the option value and updated iterator,
and direct `getElem` access to the yielded element.

**Source**: core/src/slice/iter.rs (Iterator impl for Iter)
-/
theorem next_post {T : Type}
    (iter : core.slice.iter.Iter T) :
    ∃ opt iter',
      core.slice.iter.IteratorSliceIter.next iter = ok (opt, iter') ∧
      (¬ iter.i < iter.slice.val.length →
          opt = none ∧ iter' = iter) ∧
      (∀ (h : iter.i < iter.slice.val.length),
          opt = some (iter.slice.val[iter.i]'h) ∧
          iter'.i = iter.i + 1 ∧
          iter'.slice = iter.slice) := by
  unfold core.slice.iter.IteratorSliceIter.next
  split
  · next h =>
    exact ⟨_, _, rfl, fun h' => absurd h h', fun _ => ⟨rfl, rfl, rfl⟩⟩
  · next h =>
    exact ⟨_, _, rfl, fun _ => ⟨rfl, rfl⟩, fun h' => absurd h' h⟩

end Aeneas.Std.core.slice.iter.IteratorSliceIter
