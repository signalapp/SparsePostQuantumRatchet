/-
Copyright 2026 The Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE-APACHE.
Authors: Hoang Le Truong
-/
import SrcTranslated.Funs

/-!
# Spec theorem for `core::fmt::Arguments::from_str`

In Rust's standard library, `core::fmt::Arguments::from_str` builds a `fmt::Arguments` value from
a string literal.  This is used in `format_args!` and `assert!` macros to produce the error
message argument.

The Aeneas-extracted Lean function `core.fmt.Arguments.from_str` always succeeds (returns `ok`).

**Source**: core/src/fmt/mod.rs (Arguments::from_str)
-/

open Aeneas Aeneas.Std Result

namespace Aeneas.Std.core.fmt.Arguments

/--
**Spec theorem for `core.fmt.Arguments.from_str`**:

The `from_str` function always succeeds (returns `ok`).  This is the Lean model for
`core::fmt::Arguments::from_str` which builds a format argument from a string literal.

**Source**: core/src/fmt/mod.rs (Arguments::from_str)
-/
@[step]
theorem from_str_spec (s : Str) :
    core.fmt.Arguments.from_str s
      ⦃ (_ : core.fmt.Arguments) => True ⦄ := by
  unfold core.fmt.Arguments.from_str
  simp [WP.spec_ok]

end Aeneas.Std.core.fmt.Arguments
