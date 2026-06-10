/-
Copyright 2026 The Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE-APACHE.
Authors: Markus Dablander
-/
import Spqr.Code.Funs
import Spqr.Specs.Util.Inz

/-!
# Spec theorem for `spqr::util::is_non_zero`

Constant-time-firewalled wrapper around `inz`: applies `core::hint::black_box`
to the result of `inz value` and is marked `#[inline(never)]` so the compiler
cannot optimize the branchless indicator computation back into a data-dependent
branch. Semantically, this is the identity on top of `inz`, so the spec asserts
the same indicator semantics as `inz`: the result equals `1` when the input
byte is non-zero, and `0` when it is zero.

**Source:** "spqr/src/util.rs"
-/

open Aeneas Aeneas.Std
namespace spqr.util

/-- **Spec theorem for `spqr::util::is_non_zero`**
• The function never panics (total function, no preconditions).
• The result equals `1` when `value.val ≠ 0` and `0` when `value.val = 0`.
-/
@[step]
theorem is_non_zero_spec (value : U8) :
    is_non_zero value ⦃ (result : U8) =>
      result.val = if value.val = 0 then 0 else 1 ⦄ := by
  unfold is_non_zero
  step*

end spqr.util
