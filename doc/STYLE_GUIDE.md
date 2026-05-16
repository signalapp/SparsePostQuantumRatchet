# Style Guide

## General Style Guidelines

We follow the [Mathlib style guide][mathlib-style] with some additions related to the specific patterns we use in verification.

### Header and Imports

File headers of edited files should be of the form:
```lean
/-
Copyright 2026 The Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Joe Cool
-/
```
The copyright holder should be the author or their current employer. Any authors who have made significant contributions to the file should be added to the list. They are added in chronological order based on when they edit the file. AI tools cannot be listed as authors. There are no strict rules on what contributions qualify for inclusion, the general idea is that the people listed here should be the ones we would reach out to if we have questions about the design or development of the Lean code.

### Avoiding Flexible Tactics

Flexible (non-terminal) tactics make proofs fragile and harder to maintain.
Avoid them as much as possible:

- **`simp`**: Use `simp?` to obtain the explicit lemma list, then replace with
  `simp only [...]`. This makes the proof deterministic and resistant to
  changes in the simp set.
- **`simp_all`**: Same rule — use `simp_all?` to obtain `simp_all only [...]`.
- **`grind`**: Prefer more targeted alternatives (`omega`, `ring`,
  `linear_combination`, `decide`, etc.) where feasible.
- **`exact?`** / **`apply?`**: Use these *interactively* to discover the right
  lemma, then replace with the explicit `exact` or `apply` call.

When a flexible tactic is genuinely the best option (e.g. a `simp` that closes
a goal and whose lemma list would be impractically long), document why in a
short comment.

### Linters

Linter warnings should be **resolved, not suppressed**. Avoid `#check`/`#eval`
leftovers and `set_option linter.* false` unless there is a clear justification
documented in a comment.

### Heartbeats

Keep `set_option maxHeartbeats` increases to the bare minimum needed.
Use multiples of **200000** as a standard increment (e.g. 400000, 800000).
If a proof requires a very large heartbeat budget, consider refactoring it
into helper lemmas to bring the cost down.
[text](../CONTRIBUTING.md)

### Formatting

- Limit all lines to 100 characters.
- In multi-line comments, wrap only when necessary, each line should use as much of the 100-character limit as possible before breaking.
- Imports should be listed immediately after the file header without empty lines.
- When adding definitions and theorems (except for spec theorems), follow the [Mathlib naming guidelines][mathlib-naming].

## Spec Theorem File Guidelines

- Each spec theorem lives in its own file together with any additional lemmas which are required for the proof of it, unless they can also be used elsewhere, in which case they should be placed in a central location.
- The file contains a module docstring which explains concisely the function and includes the Rust source file path where the associated function is originally defined. The module docstring should appear immediately after the imports.
  ```lean
  /-!
  # Spec theorem for `function_name`

  Brief description of what the function is doing / its purpose.

  Source: "rust/source/path.rs"
  -/
  ```
- Further details or an overview of the proof can be included in other comments in the file if useful for the specific file.
- The file is named according to the associated function name but in UpperCamelCase. E.g., if the function is extracted in Lean to `from_bytes` then the file will be called `FromBytes.lean`.
- Place the file in a folder which is named to match the Rust source file where the function is defined. This folder is then placed within a directory structure which mirrors the Rust source code directory structure. In case there are two identically named functions defined in the same Rust file, add a relevant prefix to create the Lean file name so they can be distinguished from each other.

### Spec Theorem Style

All spec theorems should be stated using `⦃ ... ⦄` Aeneas WP syntax. The canonical layout is:

```lean
/-- **Spec theorem for `full::rust::function::name::including::module`**

Concise natural language description of the spec. -/
@[step]
theorem fun_name_spec (a : argType) (b : argType) (h1 : pre_condition1)
    (h2 : pre_condition2) :
    fun_name a b ⦃ (result : resultType) =>
      post_condition_1 ∧
      post_condition_2 ⦄ := by
  sorry
```

- Add the attribute `@[step]` so the Aeneas step tactic can find them. Start a new line after the attributes.
- The theorem name should be the name of the function with the suffix `_spec`. Note the identifier of the spec theorem should be the __full name__ of the function with this suffix.
- Open namespaces properly so that the identifier prefix is not cluttering the spec theorem code and yet the spec theorem identifier is the full identifier of the function with suffix as required. I.e., for a spec theorem for `crate_name.mod_name.type_name.fun_name` the theorem will be as in the example above and it is required to open `namespace crate_name.mod_name.type_name` earlier in the file and `end` it later in the file.
- Arguments and preconditions (i.e., `(a : argType) (b : argType)`, `(h : pre_condition)`, ... ) are placed after the name and on following lines.
- Immediately after the main `:` of the theorem start a new line and write the function application and WP binder: `fun_name a b ⦃ (result : resultType) =>`
- `result` should always be given its appropriate `resultType` (note that this requires brackets to parse correctly)
- Postconditions should be written as a logical conjunction via `post_condition_1 ∧ post_condition_2 ∧ ...` inside `⦃ ... ⦄`.
- The arguments of the spec theorem should be named exactly like the corresponding entities in the original function definition for `fun_name`.
- Indentation Structure:
  - `@[step]` tag and `theorem fun_name_spec` statement: 0 spaces
  - Arguments, preconditions and line with function application: 4 spaces
  - Postconditions `post_condition_i ∧`: 6 spaces
  - Proof body: 2 spaces


[mathlib-style]: https://leanprover-community.github.io/contribute/style.html
[mathlib-naming]: https://leanprover-community.github.io/contribute/naming.html
