/-
Copyright 2026 The Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE-APACHE.
Authors: Hoang Le Truong
-/
import SrcTranslated.Funs

/-! # Spec theorem for `core.iter.range.IteratorRange.next core.iter.range.StepUsize`**:

The `next` method of the `Iterator` instance for `Range<usize>`, specified at the WP / postcondition
level: on a `range : Range Usize`, `next` returns `(opt, range')` where:

* if `range.start.val ≥ range.end.val` (the range is exhausted), then `opt = none` and `range' =
  range` (the iterator is unchanged);
* if `range.start.val < range.end.val` (the range still has an element), then `opt = some
  range.start`, `range'.start.val = range.start.val + 1`, and `range'.end = range.end` (the upper
  bound is preserved). -/

open Aeneas Aeneas.Std Result core.ops.range core.iter.range

namespace core.iter.range.IteratorRange

/-- **Spec theorem for `core.iter.range.IteratorRange.next core.iter.range.StepUsize`**:

The `next` method of the `Iterator` instance for `Range<usize>`, specified at the WP / postcondition
level: on a `range : Range Usize`, `next` returns `(opt, range')` where:

* if `range.start.val ≥ range.end.val` (the range is exhausted), then `opt = none` and `range' =
  range` (the iterator is unchanged);
* if `range.start.val < range.end.val` (the range still has an element), then `opt = some
  range.start`, `range'.start.val = range.start.val + 1`, and `range'.end = range.end` (the upper
  bound is preserved). -/
@[step]
theorem next_spec (range : Range Usize) :
    IteratorRange.next StepUsize range ⦃ (opt, range') =>
      (¬ range.start.val < range.end.val → opt = none ∧ range' = range) ∧
      (range.start.val < range.end.val →
            opt = some range.start ∧
            range'.start.val = range.start.val + 1 ∧
            range'.end = range.end) ⦄ := by
  suffices h : ∃ opt range',
      IteratorRange.next StepUsize range
        = ok (opt, range') ∧
      (¬ range.start.val < range.end.val → opt = none ∧ range' = range) ∧
      (range.start.val < range.end.val →
          opt = some range.start ∧
          range'.start.val = range.start.val + 1 ∧
          range'.end = range.end) by grind
  simp only [IteratorRange.next]
  simp only [liftFun2, liftFun1, core.clone.impls.CloneUsize.clone, bind_tc_ok, not_lt]
  have h_lt_iff :
      (core.cmp.impls.PartialOrdUsize.lt range.start range.end = true) =
      (range.start.val < range.end.val) := by
    simp [core.cmp.impls.PartialOrdUsize.lt]
  simp only [h_lt_iff]
  by_cases hlt : range.start.val < range.end.val
  · rw [if_pos hlt]
    have hbound : range.start.val + 1 ≤ Usize.max := by scalar_tac
    refine ⟨some range.start,
            {range with start := ⟨range.start.val + 1, by scalar_tac⟩},
            ?_, ?_, ?_⟩
    · simp only [core.iter.range.StepUsize.forward_checked, bind_tc_ok]
      have hca := Usize.checked_add_bv_spec range.start 1#usize
      rcases heq : Usize.checked_add range.start 1#usize with _ | z
      · scalar_tac
      · simp only
        have hzval : z.val = range.start.val + 1 := by scalar_tac
        congr 4
        exact UScalar.eq_of_val_eq hzval
    · grind
    · intro _
      exact ⟨rfl, rfl, rfl⟩
  · rw [if_neg hlt]
    exact ⟨none, range, rfl, fun _ => ⟨rfl, rfl⟩, fun h => absurd h hlt⟩

end core.iter.range.IteratorRange
