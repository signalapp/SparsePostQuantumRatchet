/-
Copyright 2026 The Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE-APACHE.
Authors: Hoang Le Truong
-/
import SrcTranslated.Funs

/-!
# Spec theorem for `core::iter::traits::collect::{IntoIterator for &[T]}::into_iter`

In Rust's standard library, `&[T]` (a shared slice reference) implements `IntoIterator` by
constructing a `core::slice::Iter<'_, T>`.  The `into_iter` method simply wraps the slice with an
initial cursor position of `0`, producing an iterator that will traverse the slice from front to
back.

The Aeneas-extracted Lean function
`SharedASlice.Insts.CoreIterTraitsCollectIntoIteratorSharedATIter.into_iter`
mirrors this behavior: it takes a `Slice T` and returns an `Iter T` with the original slice and
cursor `i = 0`.

**Source**: core/src/slice/iter.rs (IntoIterator impl for &[T])
-/

open Aeneas Aeneas.Std Result

namespace Aeneas.Std.Specs.IntoIteratorSlice

/--
**Spec theorem for `SharedASlice.Insts.CoreIterTraitsCollectIntoIteratorSharedATIter.into_iter`**:

• Takes a `Slice T` — a shared slice reference.
• Returns a `core.slice.iter.Iter T` whose `slice` field is the original input and whose `i` field
  (the iteration cursor) is `0`.

The function always succeeds (no panic) for any `Slice T` input.

**Postcondition**:
  `result.slice = s` — the iterator wraps the same slice data.
  `result.i = 0`     — iteration begins at the first element.

**Source**: core/src/slice/iter.rs (IntoIterator impl for &[T])
-/
@[step]
theorem into_iter_spec {T : Type} (s : Slice T) :
    SharedASlice.Insts.CoreIterTraitsCollectIntoIteratorSharedATIter.into_iter s ⦃
      (iter : core.slice.iter.Iter T) =>
      iter.slice = s ∧ iter.i = 0 ⦄ := by
  unfold SharedASlice.Insts.CoreIterTraitsCollectIntoIteratorSharedATIter.into_iter
  simp [WP.spec_ok]

end Aeneas.Std.Specs.IntoIteratorSlice
