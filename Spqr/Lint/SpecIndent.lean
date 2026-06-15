/-
Copyright 2026 The Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Liao Zhang
-/
import Lean
import Mathlib.Tactic.Linter

/-!
# Linter: `specIndent` — spec theorem indentation style

Enforces the four indentation rules defined in `doc/STYLE_GUIDE.md`:

| Location | Expected column (0-indexed) | Scope |
|---|---|---|
| Continuation line on a new line after the `theorem` line | 4 | `@[step]` only |
| Postcondition body on a new line after `=>` in the WP binder | 6 | `@[step]` only |
| `∧` RHS of the conjunction directly after the first `=>` of the WP binder | 6 | `@[step]` only |
| Proof body after `by` (when on a new line) | 2 | all theorems |

The first three checks apply only to `@[step]` Aeneas spec theorems; the proof-body indent
rule applies to every theorem so that the project's 2-space proof style is uniform.  The
linter is controlled by a single option `linter.spqr.specIndent` so that a justified
deviation can be suppressed uniformly.
-/

namespace Spqr.Lint

open Lean Elab Command Linter

/-! ## Option -/

/-- Warns when a theorem's indentation deviates from the project style guide.
See `doc/STYLE_GUIDE.md` §"Indentation Structure". -/
register_option linter.spqr.specIndent : Bool := {
  defValue := true
  descr := "Warns when a theorem's indentation deviates from the style guide."
}

/-! ## Helpers -/

/-- Return `true` when the declaration command `stx` carries an `@[step]` attribute.
Only inspects `declModifiers` (`stx[0]`) to avoid false positives from proof bodies. -/
private def hasStepAttr (stx : Syntax) : Bool :=
  match stx.getArgs[0]? with
  | none      => false
  | some mods => mods.find? (fun s => s.isIdent && s.getId == `step) |>.isSome

/-- 0-indexed column of `stx`'s leading source position. -/
private def colOf (stx : Syntax) (fm : FileMap) : Option Nat :=
  stx.getPos? >>= fun p => some (fm.toPosition p).column

/-- 1-indexed source line of `stx`'s leading position. -/
private def lineOf (stx : Syntax) (fm : FileMap) : Option Nat :=
  stx.getPos? >>= fun p => some (fm.toPosition p).line

/-- 1-indexed source line of `stx`'s trailing (end) position. -/
private def tailLineOf (stx : Syntax) (fm : FileMap) : Option Nat :=
  stx.getTailPos? >>= fun p => some (fm.toPosition p).line

/-- `true` iff `stx` is a `A ∧ B` node (the `«term_∧_»` notation).
Matches by checking that the node has exactly three children and the middle child is the
`∧` atom.  We use the atom-value check rather than `stx.getKind == \`«term_∧_»` to stay
independent of namespace resolution details. -/
private def isAndNode (stx : Syntax) : Bool :=
  stx.getArgs.size == 3 &&
  match stx.getArgs[1]? with
  | some (Syntax.atom _ v) => v.trimAscii == "∧"
  | _                      => false

/-- Recursively collect every WP-binder body — the term immediately after `=>` in
`⦃ binder => body ⦄` — that starts on a new line after `=>` and is NOT at `expected` column. -/
private partial def collectMisindentedWpBodies
    (stx : Syntax) (fm : FileMap) (expected : Nat) : Array Syntax :=
  let childResults := stx.getArgs.flatMap (collectMisindentedWpBodies · fm expected)
  let args := stx.getArgs
  -- Only match nodes that have ` ⦃ ` as a direct atom child (WP binder notation).
  let hasLLBracket := args.any fun c =>
    match c with | Syntax.atom _ v => v.trimAscii == "⦃" | _ => false
  if !hasLLBracket then childResults
  else
    match args.findIdx? (fun c =>
    match c with | Syntax.atom _ v => v.trimAscii == "=>" | _ => false) with
    | none => childResults
    | some arrowIdx =>
      match args[arrowIdx]?, args[arrowIdx + 1]? with
      | some arrowAtom, some body =>
        match lineOf arrowAtom fm, lineOf body fm, colOf body fm with
        | some arrowLine, some bodyLine, some bodyCol =>
          if bodyLine > arrowLine && bodyCol ≠ expected then childResults.push body
          else childResults
        | _, _, _ => childResults
      | _, _ => childResults

/-- Recursively collect every WP-binder body term (the `body` in `⦃ binder => body ⦄`).
Used to scope `∧`-RHS checks to postconditions only. -/
private partial def collectWpBodies (stx : Syntax) : Array Syntax :=
  let args := stx.getArgs
  let hasLLBracket := args.any fun c =>
    match c with | Syntax.atom _ v => v.trimAscii == "⦃" | _ => false
  if !hasLLBracket then args.flatMap collectWpBodies
  else
    match args.findIdx? (fun c =>
      match c with | Syntax.atom _ v => v.trimAscii == "=>" | _ => false) with
      | none     => #[]
      | some idx => match args[idx + 1]? with
        | some body => #[body]
        | none      => #[]


private partial def collectMisindentedAndRhs_aux
    (stx : Syntax) (fm : FileMap) (expected : Nat) : Array (Syntax × String) :=
  if isAndNode stx then
    match stx.getArgs[0]?, stx.getArgs[1]?, stx.getArgs[2]? with
    | some lhs, some andNode, some rhs =>
        let acc := collectMisindentedAndRhs_aux rhs fm expected
        match tailLineOf lhs fm, lineOf andNode fm, lineOf rhs fm, colOf rhs fm with
        | some lhsTailLine, some andLine, some rhsLine, some rhsCol =>
          let acc :=
            if andLine > lhsTailLine then
              acc.push (andNode,
                "∧ operator should be appended to the end of the preceding line, \
                not placed at the start of a new line, \
                per the spec theorem style guide.")
            else acc
          let acc :=
            if rhsLine > andLine && rhsCol ≠ expected then
              acc.push (rhs,
                s!"Postcondition conjunct is at column {rhsCol}, expected {expected}. \
                Conjunction operands on new lines should be indented {expected} spaces \
                per the spec theorem style guide.")
            else acc
          acc
        | _, _, _, _ => acc
    | _, _, _ => #[]
  else #[]


/-- Check the conjunction that is *directly* the postcondition body — the term immediately
after the first `=>` of the WP binder.  We deliberately do NOT recurse into sub-terms: when
the body is some other form (e.g. a `match` whose arms each introduce their own `=>`), the
conjuncts nested under those later arrows have their own natural indentation and must not be
flagged.  The rule scopes to the indentation after the *first* `=>` only. -/
private def collectMisindentedAndRhs
    (stx : Syntax) (fm : FileMap) (expected : Nat) : Array (Syntax × String) :=
  if isAndNode stx then
    collectMisindentedAndRhs_aux stx fm expected
  else
    #[]


/-! ## Linter -/

/-- `@[step]`-gated checks: continuation lines (col 4), postcondition body (col 6),
and `∧` RHS (col 6).  Runs only when the theorem carries `@[step]`. -/
private def runStepChecks
    (inner : Syntax) (bindersNode typeTerm : Syntax) (kwLine : Nat) (fm : FileMap)
    : CommandElabM Unit := do
  let _ := inner
  -- ── Check 1: Continuation lines at column 4 ─────────────────────────────
  -- Arguments, preconditions, and the function application line all share the
  -- same 4-space rule.  Keep only the first node on each continuation line so
  -- that multiple binders sharing a line (e.g. `(n : Nat) (_h : n > 0)`) count
  -- as one logical line.
  let (firstPerLine, _) := (bindersNode.getArgs ++ #[typeTerm]).foldl
    (fun acc node =>
      let (arr, seen) := acc
      match lineOf node fm with
      | some l => if l > kwLine && !seen.contains l then (arr.push node, seen.cons l)
                  else acc
      | none   => acc)
    ((#[] : Array Syntax), ([] : List Nat))
  for node in firstPerLine do
    if let some nodeCol := colOf node fm then
      unless nodeCol == 4 do
        logLint linter.spqr.specIndent node
          m!"Continuation line is at column {nodeCol}, expected 4. \
            Arguments, preconditions, and the function application line \
            on a new line should be indented 4 spaces \
            per the spec theorem style guide."
  -- ── Check 3a: First postcondition body at column 6 ──────────────────────
  let misindentedBodies := collectMisindentedWpBodies typeTerm fm 6
  for node in misindentedBodies do
    let col := (colOf node fm).getD 0
    logLint linter.spqr.specIndent node
      m!"Postcondition body is at column {col}, expected 6. \
        The postcondition body after `=>` should be indented 6 spaces \
        per the spec theorem style guide."
  -- ── Check 3b: ∧ postcondition RHS at column 6 ────────────────────────────
  -- Suppress 3b on any WP body that 3a already flagged: when the whole conjunctive
  -- body is misindented, 3a's body warning already covers the mistake, so re-reporting
  -- each conjunct would emit several messages for one block-level indentation slip.
  let flaggedBodyPos := misindentedBodies.filterMap (·.getPos?)
  for body in collectWpBodies typeTerm do
    if (body.getPos?.map flaggedBodyPos.contains).getD false then continue
    for (node, msg) in collectMisindentedAndRhs body fm 6 do
      logLint linter.spqr.specIndent node m!"{msg}"

/-- Check 4 (applies to every theorem): proof body after `by` must be at column 2
when it starts on a new line. -/
private def runProofBodyCheck (declVal : Syntax) (fm : FileMap) : CommandElabM Unit := do
  unless declVal.isOfKind ``Lean.Parser.Command.declValSimple do return
  -- declValSimple[0]=":=", [1]=declBody, [2]=Termination.suffix, [3]=whereDecls
  let some proofTerm := declVal.getArgs[1]? | return
  unless proofTerm.isOfKind ``Lean.Parser.Term.byTactic do return
  -- byTactic[0]="by ", [1]=tacticSeq
  let some byKw      := proofTerm.getArgs[0]? | return
  let some tacticSeq := proofTerm.getArgs[1]? | return
  if let some byLine  := lineOf byKw fm then
    if let some tacLine := lineOf tacticSeq fm then
      if tacLine > byLine then
        if let some tacCol := colOf tacticSeq fm then
          unless tacCol == 2 do
            logLint linter.spqr.specIndent tacticSeq
              m!"Proof body is at column {tacCol}, expected 2. \
                Tactics after `by` should be indented 2 spaces \
                per the project style guide."

/-- Implementation of `linter.spqr.specIndent`. -/
def specIndentLinter : Linter where run stx := do
  unless getLinterValue linter.spqr.specIndent (← getLinterOptions) do return
  unless stx.isOfKind ``Lean.Parser.Command.declaration do return
  let some inner := stx.getArgs[1]? | return
  unless inner.isOfKind ``Lean.Parser.Command.theorem do return
  let fm ← getFileMap
  -- ── Extract key sub-trees ─────────────────────────────────────────────────
  let some kwNode  := inner.getArgs[0]? | return   -- "theorem" keyword
  let some sig     := inner.getArgs[2]? | return   -- declSig
  let some declVal := inner.getArgs[3]? | return   -- declVal
  let some kwLine  := lineOf kwNode fm  | return
  -- declSig[0] = binder array,  declSig[1] = typeSpec
  let some bindersNode := sig.getArgs[0]? | return
  let some typeSpec    := sig.getArgs[1]? | return
  -- typeSpec[0] = ":" atom,  typeSpec[1] = type term
  let some typeTerm  := typeSpec.getArgs[1]? | return
  -- `@[step]`-gated structural checks (continuation lines, postcondition body, ∧ RHS).
  if hasStepAttr stx then
    runStepChecks inner bindersNode typeTerm kwLine fm
  -- Universal proof-body indent check (applies to every theorem).
  runProofBodyCheck declVal fm

initialize addLinter specIndentLinter

end Spqr.Lint
