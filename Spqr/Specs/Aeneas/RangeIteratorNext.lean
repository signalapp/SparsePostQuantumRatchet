/-
Copyright 2026 The Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE-APACHE.
Authors: Hoang Le Truong
-/
import SrcTranslated.Funs
import Spqr.Aux.Aeneas.StdNextStepUsize

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
Note: Aeneas provides `core.iter.range.IteratorRange.next_Usize_spec` but is only for one branch.
-/
theorem next_Usize_spec' (range : core.ops.range.Range Std.Usize) :
    next core.iter.range.StepUsize range ⦃ (opt, range') =>
      (¬ range.start.val < range.end.val → opt = none ∧ range' = range) ∧
      (range.start.val < range.end.val → opt = some range.start ∧
      range'.start.val = range.start.val + 1 ∧ range'.end = range.end) ⦄ := by
  by_cases range.start.val < range.end.val
  · step*
  · unfold next; step*

end Aeneas.Std.core.iter.range.IteratorRange
