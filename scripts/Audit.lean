/-
Axiom audit and sorry-manifest generator.

Usage:
  lake env lean scripts/Audit.lean

Scans all `Spqr.*` modules reachable via `import Spqr` (i.e. those
already part of the build), then for each theorem/def/opaque/axiom it
collects the transitive axiom closure and reports non-builtin ones.

Any `Spqr.*` module not imported by the root `Spqr` module will not be
scanned.  Ensure new modules are re-exported from `Spqr.lean`.

Section 1 focuses on `Spqr.Specs.*` (hand-written proofs).
Section 2 traces how `sorry` reaches specs theorems.
Section 3 gives a full project summary.
Section 4 writes `sorry-manifest.txt` (machine-readable, one line per
  sorry-tainted declaration) consumed by `scripts/sorry-diff.py` for
  CI delta reporting.

Reference: https://lean-lang.org/doc/reference/latest/ValidatingProofs/
-/
import Spqr

open Lean Elab Command

private def isBuiltinAxiom (n : Name) : Bool :=
  n == ``propext || n == ``Classical.choice || n == ``Quot.sound

run_cmd liftTermElabM do
  let env ← getEnv
  let moduleNames := env.header.moduleNames

  -- Pre-compute module-index sets (avoids repeated toString in hot paths)
  let mut projectModuleIdxs : Std.HashSet Nat := {}
  let mut specsModuleIdxs : Std.HashSet Nat := {}
  let mut projectModuleNames : Array Name := #[]
  let mut specsModuleNames : Array Name := #[]
  for h : i in [:moduleNames.size] do
    let m := moduleNames[i]
    if m == `Spqr || m.getRoot == `Spqr then
      projectModuleIdxs := projectModuleIdxs.insert i
      projectModuleNames := projectModuleNames.push m
      if m.toString.startsWith "Spqr.Specs" then
        specsModuleIdxs := specsModuleIdxs.insert i
        specsModuleNames := specsModuleNames.push m

  logInfo m!"=== Project modules detected ==="
  for h : i in [:projectModuleNames.size] do
    logInfo m!"  {projectModuleNames[i]}"
  logInfo m!"\n=== Specs modules ==="
  for h : i in [:specsModuleNames.size] do
    logInfo m!"  {specsModuleNames[i]}"

  -- Single pass over all constants: build module lookup + categorise decls.
  -- Previous version did three separate env.constants.fold passes.
  let (moduleLookup, specsThms, allProjectDecls) :=
    env.constants.fold
      (init := (({} : Std.HashMap Name Name), (#[] : Array Name), (#[] : Array Name)))
    fun acc nm ci =>
      let (ml, st, pa) := acc
      match env.getModuleIdxFor? nm with
      | some idx =>
        if !projectModuleIdxs.contains idx.toNat then acc
        else
          match ci with
          | .thmInfo _ | .defnInfo _ | .opaqueInfo _ | .axiomInfo _ =>
            let ml := ml.insert nm (moduleNames[idx.toNat]?.getD `unknown)
            let inSpecs := specsModuleIdxs.contains idx.toNat
            let st := if inSpecs then
              match ci with | .thmInfo _ | .axiomInfo _ => st.push nm | _ => st
            else st
            (ml, st, pa.push nm)
          | _ => acc
      | none => acc

  let modOf (nm : Name) : String :=
    moduleLookup[nm]?.map toString |>.getD "(current file)"

  let getBodyRefs (nm : Name) : Array Name :=
    match env.find? nm with
    | some (.thmInfo   ci) => ci.value.getUsedConstants
    | some (.defnInfo  ci) => ci.value.getUsedConstants
    | some (.opaqueInfo ci) => ci.value.getUsedConstants
    | _ => #[]

  -- Cache collectAxioms for every project declaration exactly once.
  -- Sections 1 and 3 both read from this cache instead of recomputing.
  let mut axiomCache : Std.HashMap Name (Array Name) := {}
  for h : i in [:allProjectDecls.size] do
    let nm := allProjectDecls[i]
    let usedAxioms ← Lean.collectAxioms nm
    axiomCache := axiomCache.insert nm usedAxioms

  -- ── SECTION 1: Hand-written specs ─────────────────────────────────────

  logInfo m!"\n╔══════════════════════════════════════════════════════╗"
  logInfo m!"║  SECTION 1: Hand-written specs (Spqr.Specs.*)        ║"
  logInfo m!"╚══════════════════════════════════════════════════════╝"
  logInfo m!"Theorems+axioms in Spqr.Specs.*: {specsThms.size}"

  let mut specsSorry := false
  let mut specsTrust := false
  let mut specsResults : Array (Name × Array Name) := #[]
  let mut specsAllCustom : Std.HashSet Name := {}

  for h : i in [:specsThms.size] do
    let nm := specsThms[i]
    let usedAxioms := axiomCache[nm]?.getD #[]
    let nonBuiltin := usedAxioms.filter fun a => !isBuiltinAxiom a
    if nonBuiltin.size > 0 then
      specsResults := specsResults.push (nm, nonBuiltin)
    if usedAxioms.any (· == ``sorryAx) then specsSorry := true
    if usedAxioms.any (· == ``Lean.trustCompiler) then specsTrust := true
    for h2 : j in [:nonBuiltin.size] do
      specsAllCustom := specsAllCustom.insert nonBuiltin[j]

  if specsSorry then logInfo m!"⚠  `sorry` found in specs!"
  else logInfo m!"✓  No `sorry` in specs."
  if specsTrust then logInfo m!"⚠  `Lean.trustCompiler` found in specs."
  else logInfo m!"✓  No `Lean.trustCompiler` in specs."
  logInfo m!"\nSpecs with non-builtin axioms: {specsResults.size} / {specsThms.size}"

  for h : i in [:specsResults.size] do
    let (nm, axioms) := specsResults[i]
    let mut msg := m!"\n  [{modOf nm}] {nm}"
    for h2 : j in [:axioms.size] do
      msg := msg ++ m!"\n    └─ {axioms[j]}"
    logInfo msg

  logInfo m!"\n--- Custom axioms used across all specs ---"
  for a in specsAllCustom.toArray do
    logInfo m!"  • {a}"

  -- ── SECTION 2: Where does `sorryAx` come from? ────────────────────────

  logInfo m!"\n╔══════════════════════════════════════════════════════╗"
  logInfo m!"║  SECTION 2: Where does `sorry` come from?             ║"
  logInfo m!"╚══════════════════════════════════════════════════════╝"

  let mut directSorrySet : Std.HashSet Name := {}
  let mut directSorryList : Array Name := #[]
  for h : i in [:allProjectDecls.size] do
    let nm := allProjectDecls[i]
    if (getBodyRefs nm).any (· == ``sorryAx) then
      directSorrySet := directSorrySet.insert nm
      directSorryList := directSorryList.push nm

  logInfo m!"Declarations whose own body directly uses `sorry`: {directSorryList.size}"
  for h : i in [:directSorryList.size] do
    logInfo m!"  [{modOf directSorryList[i]}] {directSorryList[i]}"

  logInfo m!"\n--- How `sorry` reaches each specs theorem ---"
  logInfo m!"(For each sorry-tainted spec, which direct-sorry decl does it call?)\n"

  let mut sorrySpecCount : Nat := 0
  for h : i in [:specsResults.size] do
    let (nm, axioms) := specsResults[i]
    unless axioms.any (· == ``sorryAx) do continue
    sorrySpecCount := sorrySpecCount + 1

    let mut msg := m!"[{modOf nm}] {nm}"

    if directSorrySet.contains nm then
      msg := msg ++ m!"\n    → sorry directly in this declaration"
    else
      -- BFS restricted to project constants; predecessor map instead of
      -- per-node path copies (O(V) memory instead of O(V·depth)).
      let mut visited : Std.HashSet Name := {}
      let mut queue : Array Name := #[nm]
      let mut pred : Std.HashMap Name Name := {}
      let mut found : Array Name := #[]
      let mut qIdx : Nat := 0
      while hq : qIdx < queue.size do
        let cur := queue[qIdx]
        qIdx := qIdx + 1
        if visited.contains cur then continue
        visited := visited.insert cur
        if directSorrySet.contains cur then
          found := found.push cur
          continue
        for r in getBodyRefs cur do
          if !visited.contains r && moduleLookup.contains r then
            if !pred.contains r then
              pred := pred.insert r cur
            queue := queue.push r

      if found.isEmpty then
        msg := msg ++ m!"\n    (sorry origin not in project — likely in Aeneas dependency)"
      for h3 : k in [:found.size] do
        let target := found[k]
        let mut path : Array Name := #[target]
        let mut cur := target
        while cur != nm do
          match pred[cur]? with
          | some p => path := path.push p; cur := p
          | none => break
        path := path.reverse
        msg := msg ++ m!"\n    → sorry in [{modOf target}] {target}"
        msg := msg ++ m!"\n      path ({path.size} hops): "
        let showPath := if path.size ≤ 5 then path
          else #[path[0]!, path[1]!] ++ #[`«...»] ++ #[path[path.size - 2]!, path[path.size - 1]!]
        for h4 : l in [:showPath.size] do
          if l > 0 then msg := msg ++ m!" → "
          msg := msg ++ m!"{showPath[l]}"
    logInfo msg
    logInfo m!""

  logInfo m!"Sorry-tainted specs: {sorrySpecCount} / {specsThms.size}"

  -- ── SECTION 3: Full project summary ───────────────────────────────────

  logInfo m!"\n╔══════════════════════════════════════════════════════╗"
  logInfo m!"║  SECTION 3: Full project summary (Spqr.*)            ║"
  logInfo m!"╚══════════════════════════════════════════════════════╝"

  let mut projSorry := false
  let mut projTrust := false
  let mut projNonBuiltinCount : Nat := 0
  let mut projAllCustom : Std.HashSet Name := {}

  for h : i in [:allProjectDecls.size] do
    let nm := allProjectDecls[i]
    let usedAxioms := axiomCache[nm]?.getD #[]
    let nonBuiltin := usedAxioms.filter fun a => !isBuiltinAxiom a
    if nonBuiltin.size > 0 then projNonBuiltinCount := projNonBuiltinCount + 1
    if usedAxioms.any (· == ``sorryAx) then projSorry := true
    if usedAxioms.any (· == ``Lean.trustCompiler) then projTrust := true
    for h2 : j in [:nonBuiltin.size] do
      projAllCustom := projAllCustom.insert nonBuiltin[j]

  logInfo m!"Total project declarations: {allProjectDecls.size}"
  logInfo m!"With non-builtin axioms: {projNonBuiltinCount} / {allProjectDecls.size}"
  if projSorry then logInfo m!"⚠  `sorry` found in project."
  else logInfo m!"✓  No `sorry` in project."
  if projTrust then logInfo m!"⚠  `Lean.trustCompiler` found in project."
  else logInfo m!"✓  No `Lean.trustCompiler` in project."
  logInfo m!"\nTotal custom axioms: {projAllCustom.size}"

  -- ── SECTION 4: Machine-readable sorry manifest ──────────────────────────

  logInfo m!"\n╔══════════════════════════════════════════════════════╗"
  logInfo m!"║  SECTION 4: Sorry manifest (sorry-manifest.txt)     ║"
  logInfo m!"╚══════════════════════════════════════════════════════╝"

  let mut manifestLines : Array String := #[]
  for h : i in [:allProjectDecls.size] do
    let nm := allProjectDecls[i]
    let usedAxioms := axiomCache[nm]?.getD #[]
    if usedAxioms.any (· == ``sorryAx) then
      let modName := moduleLookup[nm]?.map toString |>.getD "(unknown)"
      let kind := if directSorrySet.contains nm then "direct" else "transitive"
      manifestLines := manifestLines.push s!"{modName} {nm} {kind}"
  let sorted := manifestLines.qsort (· < ·)
  let content := String.join (sorted.toList.map (· ++ "\n"))
  IO.FS.writeFile "sorry-manifest.txt" content
  logInfo m!"sorry-manifest.txt written ({sorted.size} sorry-tainted declarations)"
