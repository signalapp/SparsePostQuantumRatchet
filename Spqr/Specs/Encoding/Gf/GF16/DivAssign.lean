/-
Copyright 2026 The Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Hoang Le Truong
-/
import Spqr.Code.Funs
import Spqr.Math.Gf16.Field
import Spqr.Specs.Encoding.Gf.GF16.DivImpl

/-! # Spec theorem for `spqr.encoding.gf.GF16.Insts.CoreOpsArithDivAssignShared0GF16.div_assign`

In GF(2¹⁶), `a / b = a · b^(2¹⁶ − 2)` since `b^(2¹⁶ − 1) = 1` for `b ≠ 0`.
The by-reference `DivAssign<&GF16>` just delegates to `div_impl`.

**Source**: spqr/src/encoding/gf.rs (lines 535:4-537:5) -/

open Aeneas Aeneas.Std

namespace spqr.encoding.gf.GF16.Insts.CoreOpsArithDivAssignShared0GF16

/-- **Spec theorem for `spqr.encoding.gf.GF16.Insts.CoreOpsArithDivAssignShared0GF16.div_assign`**:
`div_assign self other` yields `self · other^(2¹⁶ − 2)` in `GF216`. -/
@[step]
theorem div_assign_spec (self other : GF16) :
    div_assign self other ⦃ (result : GF16) =>
      result.toGF216 = self.toGF216 * other.toGF216 ^ (2 ^ 16 - 2) ⦄ := by
  unfold div_assign
  step*

end spqr.encoding.gf.GF16.Insts.CoreOpsArithDivAssignShared0GF16

/-! # Spec theorem for `spqr.encoding.gf.GF16.Insts.CoreOpsArithDivAssignGF16.div_assign`

Same as the by-reference `DivAssign`; the by-value vs by-reference distinction is erased by Aeneas.

**Source**: spqr/src/encoding/gf.rs (lines 542:4-544:5) -/

namespace spqr.encoding.gf.GF16.Insts.CoreOpsArithDivAssignGF16

/-- **Spec theorem for `spqr.encoding.gf.GF16.Insts.CoreOpsArithDivAssignGF16.div_assign`**:
`div_assign self other` yields `self · other^(2¹⁶ − 2)` in `GF216`. -/
@[step]
theorem div_assign_spec (self other : GF16) :
    div_assign self other ⦃ (result : GF16) =>
      result.toGF216 = self.toGF216 * other.toGF216 ^ (2 ^ 16 - 2) ⦄ := by
  unfold div_assign
  step*

end spqr.encoding.gf.GF16.Insts.CoreOpsArithDivAssignGF16
