import Lean
import Utils.Config
/-! Analysis: spec-existence, verification status, dependency and axiom analysis.

* `isVerified`: the spec's own proof has no `sorry`;
* `specAxioms`: the spec's full transitive axiom closure. -/

open Lean

namespace Utils.Lib.Analysis

/-- Spec theorem name for a function: `foo` ↦ `foo_spec`. -/
def getSpecName (name : Name) : Name := name.appendAfter Utils.Config.specSuffix

/-- Direct dependencies of a constant, from its value expression. -/
def getDirectDeps (env : Environment) (name : Name) : Array Name :=
  match env.find? name with
  | some ci =>
    match ci.value? (allowOpaque := true) with
    | some value => value.getUsedConstants
    | none => #[]
  | none => #[]

/-- Keep only dependencies that are in the given set of known functions. -/
def filterToKnownFunctions (knownNames : Std.HashSet Name) (deps : Array Name) : Array Name :=
  deps.filter (fun n => knownNames.contains n)

/-- Does a spec theorem exist for this function? -/
def hasSpecTheorem (env : Environment) (name : Name) : Bool :=
  env.find? (getSpecName name) |>.isSome

/-- Does a declaration's own proof term directly use `sorry`? -/
def proofContainsSorry (env : Environment) (name : Name) : Bool :=
  match env.find? name with
  | some ci =>
    match ci.value? (allowOpaque := true) with
    | some value => value.getUsedConstants.any (· == ``sorryAx)
    | none => true
  | none => true

/-- Verified *modulo specs*: the spec exists and its own proof has no `sorry`. -/
def isVerified (env : Environment) (name : Name) : Bool :=
  match env.find? (getSpecName name) with
  | some _ => !proofContainsSorry env (getSpecName name)
  | none => false

/-! Axiom analysis: There is no separate "fully verified" predicate: a spec is fully proven iff its
axoms contains no `sorryAx`. Consumers read that directly off the emitted `axioms` list. -/

abbrev EnvM := ReaderT Environment Id
instance : MonadEnv EnvM where
  getEnv := read
  modifyEnv _ := pure ()

/-- The axioms in a spec theorem's transitive closure, via `Lean.collectAxioms`. -/
def specAxioms (env : Environment) (name : Name) : Array Name :=
  let specName := getSpecName name
  if env.find? specName |>.isNone then #[]
  else Id.run <| (Lean.collectAxioms (m := EnvM) specName).run env

end Utils.Lib.Analysis
