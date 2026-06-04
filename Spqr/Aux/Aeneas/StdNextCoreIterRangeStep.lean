/-
Copyright 2026 The Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Hoang Le Truong
-/
import Spqr.Code.Funs
import Spqr.Code.FunsExternal

/-! # **Spec theorem for `Range<i32>` iterator `next`**:

The `next` method of the `Iterator` instance for `Range<i32>`, specified at the WP / postcondition
level: on an `iter : Range I32`, `next` returns `(opt, iter')` where:

* if `iter.start.val ≥ iter.end.val` (the range is exhausted), then `opt = none` and `iter' =
  iter` (the iterator is unchanged);
* if `iter.start.val < iter.end.val` (the range still has an element), then `opt = some
  iter.start`, `iter'.start.val = iter.start.val + 1`, and `iter'.end = iter.end` (the upper bound
  is preserved). -/

open Aeneas Aeneas.Std Result core.ops.range core.iter.range

namespace core.iter.range.IteratorRange


/-- **Spec theorem for `Range<i32>` iterator `next`**:

The `next` method of the `Iterator` instance for `Range<i32>`, specified at the WP / postcondition
level: on an `iter : Range I32`, `next` returns `(opt, iter')` where:

* if `iter.start.val ≥ iter.end.val` (the range is exhausted), then `opt = none` and `iter' =
  iter` (the iterator is unchanged);
* if `iter.start.val < iter.end.val` (the range still has an element), then `opt = some
  iter.start`, `iter'.start.val = iter.start.val + 1`, and `iter'.end = iter.end` (the upper bound
  is preserved). -/
@[step]
theorem IteratorRange_next_I32_spec
    (iter : Range I32) :
    IteratorRange.next spqr.I32.Insts.CoreIterRangeStep iter ⦃ (opt, iter1) =>
      match opt with
      | none   => ¬ iter.start.val < iter.end.val ∧ iter1 = iter
      | some v => iter.start.val < iter.end.val ∧ v = iter.start ∧
        iter1.start.val = iter.start.val + 1 ∧ iter1.end = iter.end ⦄ := by
  simp only [IteratorRange.next]
  simp only [liftFun2, liftFun1, core.clone.impls.CloneI32.clone, bind_tc_ok]
  have h_lt_iff :
      (core.cmp.impls.PartialOrdI32.lt iter.start iter.end = true) =
      (iter.start.val < iter.end.val) := by
    simp [core.cmp.impls.PartialOrdI32.lt]
  simp only [h_lt_iff]
  by_cases hlt : iter.start.val < iter.end.val
  · rw [if_pos hlt]
    have hbound : iter.start.val + 1 ≤ I32.max := by scalar_tac
    step
    grind
  · rw [if_neg hlt]
    grind

end core.iter.range.IteratorRange
