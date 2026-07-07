/-
  status: verification-status report for the spqr crate.

  Reads `translation.json` (Aeneas `emit-json`), which links each extracted Lean
  decl to its Rust `def_id` / name / source, then queries the Lean environment
  for each extracted function: does a `_spec` theorem exist, which axioms it
  uses, and its verification status. Writes `status.json`.

  Run with:  lake exe status [output.json]
-/
import Lean
import Utils.Config
import Utils.Lib.Analysis
import Utils.Lib.Translation

open Lean
open Utils.Lib.Analysis Utils.Lib.Translation

/-- Import the spqr environment (hand-written specs + extracted code). -/
def loadEnvironment : IO Environment := do
  Lean.initSearchPath (← Lean.findSysroot)
  importModules #[{ module := Utils.Config.mainModule }] {}

/-- JSON record for one extracted function. -/
def functionJson (env : Environment) (known : Std.HashSet Name)
    (f : TransFun) : Json :=
  let name := f.leanName.toName
  let exists_ := env.find? name |>.isSome
  let hasSpec := hasSpecTheorem env name
  let deps := (filterToKnownFunctions known (getDirectDeps env name)).qsort
    (fun a b => a.toString < b.toString)
  let base : List (String × Json) := [
    ("lean_id", Json.str f.leanName),
    ("def_id", toJson f.defId),
    ("rust_name", Json.str f.rustName),
    ("source", Json.str f.source),
    ("line_start", toJson f.lineStart),
    ("line_end", toJson f.lineEnd),
    ("is_local", Json.bool f.isLocal),
    ("is_opaque", Json.bool f.isOpaque),
    ("is_extraction_artifact", Json.bool f.isLoopArtifact),
    ("can_fail", Json.bool f.canFail),
    ("exists", Json.bool exists_),
    ("has_spec", Json.bool hasSpec),
    ("dependencies", Json.arr (deps.map (fun d => Json.str d.toString)))
  ]
  -- Only meaningful when a spec theorem exists.
  let specFields : List (String × Json) :=
    if hasSpec then
      [ ("spec_name", Json.str (getSpecName name).toString),
        ("verified_modulo_specs", Json.bool (isVerified env name)),
        ("axioms", Json.arr (((specAxioms env name).qsort
          (fun a b => a.toString < b.toString)).map (fun a => Json.str a.toString))) ]
    else []
  Json.mkObj (base ++ specFields)

def main (args : List String) : IO UInt32 := do
  let outPath := args[0]?.getD Utils.Config.statusOutPath
  IO.eprintln "Loading spqr environment..."
  let env ← loadEnvironment
  IO.eprintln "Reading translation.json..."
  let allFuns ← readTranslation
  IO.eprintln s!"  {allFuns.size} function entries"
  -- Restrict the report to crate-local functions we actually track for verification:
  -- exclude trait-impl methods and opaque functions.
  let funs := allFuns.filter fun f => f.isLocal && !f.isTraitImpl && !f.isOpaque
  IO.eprintln s!"  {funs.size} crate-local verifiable entries"
  -- Known function set (for dependency filtering): resolvable, crate-local lean ids.
  let known : Std.HashSet Name := funs.foldl (init := {}) fun acc f =>
    let n := f.leanName.toName
    if env.find? n |>.isSome then acc.insert n else acc

  let records := funs.map fun f => functionJson env known f

  -- Output is a bare array of per-function records; consumers derive any
  -- summary/filtered views from the metadata themselves.
  IO.FS.writeFile outPath ((Json.arr records).pretty ++ "\n")
  let specifiedN := (funs.filter (fun f => hasSpecTheorem env f.leanName.toName)).size
  IO.println s!"Wrote {outPath}: {funs.size} functions, {specifiedN} specified."
  return 0
