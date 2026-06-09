/-
Copyright 2026 The Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE-APACHE.
Authors: Markus Dablander
-/
import Spqr.Code.Funs

/-!
# Spec theorem for `spqr::util::inz`

Branchless "is non-zero" indicator on a single byte: returns 1 if the input
byte is non-zero, and 0 if it is zero. Implemented via the standard
"sign-bit of `x | -x`" constant-time idiom, lifted from `u8` to `u16` so the
high bit lives at position 8 and can be isolated by `>> 8 & 1`.

**Source:** "spqr/src/util.rs"
-/

open Aeneas Aeneas.Std
namespace spqr.util

/-- **Spec theorem for `spqr::util::inz`**
• The function never panics (total function, no preconditions).
• The result equals `1` when `value.val ≠ 0` and `0` when `value.val = 0`.
-/
@[step]
theorem inz_spec (value : U8) :
    inz value ⦃ (result : U8) =>
      result.val = if value.val = 0 then 0 else 1 ⦄ := by
  unfold inz
  step*
  split <;> bv_tac 16

end spqr.util
