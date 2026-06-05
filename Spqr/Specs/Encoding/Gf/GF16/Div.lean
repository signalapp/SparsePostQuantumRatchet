/-
Copyright 2026 The Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Hoang Le Truong
-/
import Spqr.Code.Funs
import Spqr.Math.Gf16.Field
import Spqr.Specs.Encoding.Gf.GF16.DivImpl

/-! # Spec theorem for `spqr::encoding::gf::{impl ops::Div for GF16}::div`

In GF(2¹⁶), `a / b = a · b^(2¹⁶ − 2)` since `b^(2¹⁶ − 1) = 1` for `b ≠ 0`.
The by-value `Div` just delegates to `div_impl`.

**Source**: spqr/src/encoding/gf.rs -/

open Aeneas Aeneas.Std Result
open spqr.encoding.gf.GF16

namespace spqr.encoding.gf.GF16.Insts.CoreOpsArithDivGF16GF16

/-- **Spec theorem for `spqr.encoding.gf.GF16.Insts.CoreOpsArithDivGF16GF16.div`**:
`div self other` yields `self · other^(2¹⁶ − 2)` in `GF216`. -/
@[step]
theorem div_spec (self other : GF16) :
    div self other ⦃ (result : GF16) =>
      result.toGF216 = self.toGF216 * other.toGF216 ^ (2 ^ 16 - 2) ⦄ := by
  unfold div
  step*

end spqr.encoding.gf.GF16.Insts.CoreOpsArithDivGF16GF16

/-! # Spec theorem for `spqr::encoding::gf::{impl ops::Div<&GF16> for GF16}::div`

Same as the by-value `Div`; the `&GF16` reference is erased by Aeneas.

**Source**: spqr/src/encoding/gf.rs -/

namespace spqr.encoding.gf.GF16.Insts.CoreOpsArithDivShared0GF16GF16

/-- **Spec theorem for `spqr.encoding.gf.GF16.Insts.CoreOpsArithDivShared0GF16GF16.div`**:
`div self other` yields `self · other^(2¹⁶ − 2)` in `GF216`. -/
@[step]
theorem div_spec (self other : GF16) :
    div self other ⦃ (result : GF16) =>
      result.toGF216 = self.toGF216 * other.toGF216 ^ (2 ^ 16 - 2) ⦄ := by
  unfold div
  step*

end spqr.encoding.gf.GF16.Insts.CoreOpsArithDivShared0GF16GF16
