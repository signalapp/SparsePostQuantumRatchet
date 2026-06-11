/-
Copyright 2026 The Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE-APACHE.
Authors: Hoang Le Truong
-/
import SrcTranslated.Funs

/-!
# Spec theorem for `core::ops::range::{Iterator for Range<usize>}::next`

In Rust's standard library, `Range<usize>` implements `Iterator<Item = usize>`.  The `next` method
checks whether `self.start < self.end`:

  * If `start < end`, it yields `Some(start)` and advances the iterator by setting
    `start ← start + 1` (via `Step::forward_checked`).
  * If `start ≥ end`, it yields `None` and leaves the iterator unchanged.

The Aeneas-extracted Lean function `core.iter.range.IteratorRange.next` with the `StepUsize`
instance mirrors this behavior exactly.

This is the foundational specification used pervasively across `Spqr.Specs.Encoding.Polynomial` in
every loop body that drives a `for i in 0..n` iteration pattern.

**Source**: core/src/ops/range.rs (Iterator impl for Range)
-/

open Aeneas Aeneas.Std Result

namespace Aeneas.Std.core.iter.range.IteratorRange

/--
**Spec theorem for `core.iter.range.IteratorRange.next` with `StepUsize`**:

The range iterator `next` always returns `ok` and either provides the current `start` value (when
`start < end`) or `none` (when `start ≥ end`).  This is the concrete specification for the
`core.ops.range.Range<usize>` iterator used in Rust `for i in 0..n` loops.

**Postcondition**:
  * If `range.start.val ≥ range.«end».val`:
      `opt = none` and `range' = range` (iterator unchanged).
  * If `range.start.val < range.«end».val`:
      `opt = some range.start`,
      `range'.start.val = range.start.val + 1`,
      `range'.«end» = range.«end»`.

**Source**: core/src/ops/range.rs (Iterator impl for Range)
-/
theorem next_Usize_spec
    (range : core.ops.range.Range Std.Usize) :
    ∃ opt range',
      core.iter.range.IteratorRange.next core.iter.range.StepUsize range
        = ok (opt, range') ∧
      (¬ range.start.val < range.«end».val →
          opt = none ∧ range' = range) ∧
      (range.start.val < range.«end».val →
          opt = some range.start ∧
          range'.start.val = range.start.val + 1 ∧
          range'.«end» = range.«end») := by
  simp only [core.iter.range.IteratorRange.next]
  simp only [liftFun2, liftFun1, core.clone.impls.CloneUsize.clone, bind_tc_ok, not_lt]
  have h_lt_iff :
      (core.cmp.impls.PartialOrdUsize.lt range.start range.«end» = true) =
      (range.start.val < range.«end».val) := by
    simp [core.cmp.impls.PartialOrdUsize.lt]
  simp only [h_lt_iff]
  by_cases hlt : range.start.val < range.«end».val
  · rw [if_pos hlt]
    have hbound : range.start.val + 1 ≤ Usize.max := by
      have := range.«end».hBounds; scalar_tac
    refine ⟨some range.start,
            {range with start := ⟨range.start.val + 1, by scalar_tac⟩},
            ?_, ?_, ?_⟩
    · simp only [core.iter.range.StepUsize.forward_checked, bind_tc_ok]
      have hca := Usize.checked_add_bv_spec range.start 1#usize
      rcases heq : Usize.checked_add range.start 1#usize with _ | z
      · rw [heq] at hca; scalar_tac
      · simp only
        rw [heq] at hca
        obtain ⟨_, hval, _⟩ := hca
        have hzval : z.val = range.start.val + 1 := by scalar_tac
        congr 4
        exact UScalar.eq_of_val_eq hzval
    · intro h; omega
    · intro _; exact ⟨rfl, rfl, rfl⟩
  · rw [if_neg hlt]
    exact ⟨none, range, rfl, fun _ => ⟨rfl, rfl⟩, fun h => absurd h hlt⟩

end Aeneas.Std.core.iter.range.IteratorRange
