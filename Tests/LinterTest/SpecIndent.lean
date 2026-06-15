/-
Copyright 2026 The Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Liao Zhang
-/
import Aeneas
import Spqr.Lint.Basic

/-!
# Tests for `linter.spqr.specIndent`

Tests for the four indentation checks.  The first three checks fire only on `@[step]`
theorems; the proof-body (Check 4) rule fires on every theorem.  Each `#guard_msgs` block
targets exactly one violation so the expected-output annotation stays minimal.

These tests live in the `Tests` Lake library (module `Tests.LinterTest.SpecIndent`) rather
than in the `Spqr` library, so the dummy theorems below (and their `@[step]`
registrations) never leak into the production library or its public namespace.  They are
additionally wrapped in the `Spqr.Lint.Test` namespace as a second line of
defence.
-/

open Aeneas Aeneas.Std Result Aeneas.Std.WP

namespace Spqr.Lint.Test

-- Two minimal dummy functions for the test cases below.
private def dummyI (n : Nat) : Result Nat := .ok n
private def dummyP (n : Nat) : Result (Nat × Nat) := .ok ⟨n, n⟩

/-! ## Check 1 — continuation line at wrong column -/

/--
warning: Continuation line is at column 2, expected 4. Arguments, preconditions, and the function application line on a new line should be indented 4 spaces per the spec theorem style guide.

Note: This linter can be disabled with `set_option linter.spqr.specIndent false`
-/
#guard_msgs in
-- Triggers `specIndent` check 1: `(_h : n > 0)` wraps to a new line but uses only 2 spaces.
@[step]
theorem dummyI_binder_wrong_spec (n : Nat)
  (_h : n > 0) :
    dummyI n ⦃ (r : Nat) =>
      r = n ⦄ := by
  simp [dummyI]

-- No warning: `(_h : n > 0)` starts on the theorem-keyword line, so the linter
-- does not flag it — only binders whose node begins on a new line are checked.
#guard_msgs in
@[step]
theorem dummyI_binder_ok_spec (n : Nat) (_h
: n > 0) :
    dummyI n ⦃ (r : Nat) =>
      r = n ⦄ := by
  simp [dummyI]

/-! ## Check 1 (cont.) — function application line at wrong column -/

/--
warning: Continuation line is at column 2, expected 4. Arguments, preconditions, and the function application line on a new line should be indented 4 spaces per the spec theorem style guide.

Note: This linter can be disabled with `set_option linter.spqr.specIndent false`
-/
#guard_msgs in
-- Triggers `specIndent` check 1: type term is on a new line but only 2 spaces deep.
@[step]
theorem dummyI_type_wrong_spec (n : Nat) :
  dummyI n ⦃ (r : Nat) =>
      r = n ⦄ := by
  simp [dummyI]

-- No warning: type term is correctly at column 4.
#guard_msgs in
@[step]
theorem dummyI_type_ok_spec (n : Nat) :
    dummyI n ⦃ (r : Nat) =>
      r = n ⦄ := by
  simp [dummyI]

/-! ## Check 3 — postcondition at wrong column -/

/-! ### Check 3a — first postcondition body at wrong column -/

/--
warning: Postcondition body is at column 8, expected 6. The postcondition body after `=>` should be indented 6 spaces per the spec theorem style guide.

Note: This linter can be disabled with `set_option linter.spqr.specIndent false`
-/
#guard_msgs in
-- Triggers `specIndent` check 3a: WP body `r = n` is on a new line but at column 8, not 6.
@[step]
theorem dummyI_postcond_body_wrong_spec (n : Nat) :
    dummyI n ⦃ (r : Nat) =>
        r = n ⦄ := by
  simp [dummyI]

-- No warning: postcondition body is correctly at column 6.
#guard_msgs in
@[step]
theorem dummyI_postcond_body_ok_spec (n : Nat) :
    dummyI n ⦃ (r : Nat) =>
      r = n ∧
      r = n ∧ 1 = 1 ⦄ := by
  simp [dummyI]

/-! ### Check 3b — `∧` postcondition RHS at wrong column -/

/--
warning: Postcondition conjunct is at column 8, expected 6. Conjunction operands on new lines should be indented 6 spaces per the spec theorem style guide.

Note: This linter can be disabled with `set_option linter.spqr.specIndent false`
-/
#guard_msgs in
-- Triggers `specIndent` check 3b: `∧` RHS `r.2 = n` wraps to a new line at column 8.
-- The WP body `r.1 = n` is at column 6 (correct), so check 3a does not fire.
@[step]
theorem dummyP_postcond_wrong_spec (n : Nat) :
    dummyP n ⦃ (r : Nat × Nat) =>
      r.1 = n ∧
        r.2 = n ⦄ := by
  simp [dummyP]

-- No warning: ∧ RHS is correctly at column 6.
#guard_msgs in
@[step]
theorem dummyP_postcond_ok_spec (n : Nat) :
    dummyP n ⦃ (r : Nat × Nat) =>
      r.1 = n ∧ r.2 = n ⦄ := by
  simp [dummyP]

/-! ### Check 3b — `∧` operator placed at the start of a new line -/

/--
warning: ∧ operator should be appended to the end of the preceding line, not placed at the start of a new line, per the spec theorem style guide.

Note: This linter can be disabled with `set_option linter.spqr.specIndent false`
-/
#guard_msgs in
-- Triggers `specIndent` check 3b's operator-placement branch: the `∧` starts a new line
-- instead of being appended to the previous one.  The body is at column 6 (so check 3a
-- does not fire) and the RHS shares the `∧` line (so the conjunct-indentation branch does
-- not fire), isolating the operator-placement warning.
@[step]
theorem dummyP_and_on_new_line_spec (n : Nat) :
    dummyP n ⦃ (r : Nat × Nat) =>
      r.1 = n
      ∧ r.2 = n ⦄ := by
  simp [dummyP]

/-! ### Check 3a/3b interaction — no double warning on a misindented conjunctive body -/

/--
warning: Postcondition body is at column 8, expected 6. The postcondition body after `=>` should be indented 6 spaces per the spec theorem style guide.

Note: This linter can be disabled with `set_option linter.spqr.specIndent false`
-/
#guard_msgs in
-- The WP body is itself a conjunction that, as a whole, starts on a new line at column 8.
-- Check 3a flags the body; Check 3b must be suppressed on this body so the single
-- block-level indentation mistake yields exactly one message (not one per conjunct).
@[step]
theorem dummyP_conj_body_misindent_spec (n : Nat) :
    dummyP n ⦃ (r : Nat × Nat) =>
        r.1 = n ∧
        r.2 = n ⦄ := by
  simp [dummyP]

/-! ## Check 4 — proof body after `by` at wrong column -/

/--
warning: Proof body is at column 4, expected 2. Tactics after `by` should be indented 2 spaces per the project style guide.

Note: This linter can be disabled with `set_option linter.spqr.specIndent false`
-/
#guard_msgs in
-- Triggers `specIndent` check 4: first tactic is at column 4 instead of 2.
@[step]
theorem dummyI_proof_wrong_spec (n : Nat) :
    dummyI n ⦃ (r : Nat) =>
      r = n ⦄ := by
    simp [dummyI]

-- No warning: proof body is correctly at column 2.
#guard_msgs in
@[step]
theorem dummyI_proof_ok_spec (n : Nat) :
    dummyI n ⦃ (r : Nat) =>
      r = n ⦄ := by
  simp [dummyI]

/-! ## Check 4 — non-`@[step]` theorems still get the proof-body indent rule -/

/--
warning: Proof body is at column 4, expected 2. Tactics after `by` should be indented 2 spaces per the project style guide.

Note: This linter can be disabled with `set_option linter.spqr.specIndent false`
-/
#guard_msgs in
-- Plain theorem (no `@[step]`): only Check 4 applies, and it must fire on the bad indent.
theorem plain_proof_wrong (n : Nat) : n = n := by
    rfl

-- No warning: plain theorem with proof body correctly at column 2.
#guard_msgs in
theorem plain_proof_ok (n : Nat) : n = n := by
  rfl

-- No warning: plain theorem violating the `@[step]`-only continuation-line rule
-- (binder wraps to a new line at column 2) must NOT trigger any check, because
-- Checks 1, 3a, 3b are gated on `@[step]`.
#guard_msgs in
theorem plain_binder_wrap_ok (n : Nat)
  (_h : n > 0) : n = n := by
  rfl

-- No warning: `by` and the first tactic share a line — the proof body must start on a
-- NEW line below `by` for Check 4 to fire, so `:= by rfl` is fine.
#guard_msgs in
theorem plain_proof_same_line_ok (n : Nat) : n = n := by rfl

-- No warning: term-mode proof (`:= rfl`, not `:= by …`) has no by-tactic block at all,
-- so `runProofBodyCheck` exits before reaching the indent comparison.
#guard_msgs in
theorem plain_proof_term_mode_ok (n : Nat) : n = n := rfl

/--
warning: Proof body is at column 4, expected 2. Tactics after `by` should be indented 2 spaces per the project style guide.

Note: This linter can be disabled with `set_option linter.spqr.specIndent false`
-/
#guard_msgs in
-- Plain theorem with BOTH a wrapped binder at column 2 (would-be Check 1 violation) and
-- a proof body at column 4.  Confirms that `runStepChecks` is gated off, so only the
-- universal Check 4 warning is emitted — not Check 1.
theorem plain_both_violations_only_check4 (n : Nat)
  (_h : n > 0) : n = n := by
    rfl

-- No warning: suppression via `set_option` must work on plain theorems too.
#guard_msgs in
set_option linter.spqr.specIndent false in
theorem plain_proof_suppressed_ok (n : Nat) : n = n := by
    rfl

/-! ## Suppression -/

-- No warning expected: the whole indentation linter is suppressed.
#guard_msgs in
set_option linter.spqr.specIndent false in
@[step]
theorem dummyI_suppressed_spec (n : Nat)
  (_h : n > 0) :
  dummyI n ⦃ (r : Nat) => r = n ⦄ := by
    simp [dummyI]

/-! ## Fully-correct canonical layout — no warnings at all -/

#guard_msgs in
@[step]
theorem dummyP_canonical_spec (n : Nat)
    (_h : n > 0) :
    dummyP n ⦃ (r : Nat × Nat) =>
      r.1 = n ∧
      (r.2 = n ∧ 1 = 1) ∧
      2 = 2 ⦄ := by
  simp [dummyP]

#guard_msgs in
@[step]
theorem dummyP_canonical2_spec
    (n : Nat)
    (_h : n > 0) :
    dummyP n ⦃ (r : Nat × Nat) =>
      r.1 = n ∧
      (r.2 = n ∧ 1 = 1) ∧
      2 = 2 ⦄ := by
  simp
  simp [dummyP]

end Spqr.Lint.Test
