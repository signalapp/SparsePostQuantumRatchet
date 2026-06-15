/-
Copyright 2026 The Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Liao Zhang
-/
import Spqr.Lint.SpecIndent

/-!
# SparsePostQuantumRatchet verification project linters

Importing this module activates all project-specific linters.  It is imported transitively
by `SrcTranslated.TypesExternal` (and hence `SrcTranslated.FunsExternal`), which together
cover the full transitive import graph of spec theorem files.

## Linters provided

| Option | What it checks |
|---|---|
| `linter.spqr.specIndent` | `@[step]` theorem indentation (binders/type/body/proof) |

All linters are enabled by default (`defValue := true`) and can be suppressed locally with a
documented `set_option linter.spqr.* false in` — consistent with the style guide's
requirement that suppressions carry an explanatory comment.
-/
