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

-- TODO: restate this for core.cmp.PartialOrdUsize.lt so it is general
@[step]
theorem core.iter.range.StepUsize.partialOrdInst_lt_spec (x y : Usize) :
    StepUsize.partialOrdInst.lt x y ⦃ (b : Bool) => b ↔ x.val < y.val ⦄ := by
  simp [core.iter.range.UScalarStep, core.cmp.impls.PartialOrdUsize.lt]

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
      (range.start.val < range.end.val → opt = some range.start ∧
      range'.start.val = range.start.val + 1 ∧ range'.end = range.end) ⦄ := by
  by_cases range.start.val < range.end.val
  · step*
  · unfold IteratorRange.next; step*

end core.iter.range.IteratorRange
