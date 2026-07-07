import Lean
import Utils.Config
/-! Translation: parse `translation.json` (Aeneas `emit-json`) into the `TransFun` model. It links
each extracted Lean function to its Rust source directly, so no separate charon summary (and no
join) is needed. -/

open Lean

namespace Utils.Lib.Translation

/-! ## Small `Lean.Json` accessors (lenient: defaults instead of errors) -/

def jVal? (j : Json) (k : String) : Option Json := (j.getObjVal? k).toOption
def jStr (j : Json) (k : String) : String := ((j.getObjVal? k).bind Json.getStr?).toOption.getD ""
def jNat (j : Json) (k : String) : Nat := ((j.getObjVal? k).bind Json.getNat?).toOption.getD 0
def jBool (j : Json) (k : String) : Bool := ((j.getObjVal? k).bind Json.getBool?).toOption.getD false
def jArr (j : Json) (k : String) : Array Json := ((j.getObjVal? k).bind Json.getArr?).toOption.getD #[]

/-! ## translation.json -/

/-- One Aeneas-emitted function entry from `translation.json`. -/
structure TransFun where
  defId : Nat
  leanName : String
  leanFile : String
  isOpaque : Bool
  canFail : Bool
  /-- `true` for loop wrapper/body entries (Aeneas extraction artifacts). -/
  isLoopArtifact : Bool
  /-- Rust path of the function. -/
  rustName : String
  /-- Source file the function was extracted from. -/
  source : String
  lineStart : Nat
  lineEnd : Nat
  /-- Defined in the crate (vs a dependency / std). -/
  isLocal : Bool
  deriving Repr, Inhabited

/-- `true` if this is a trait-impl method (e.g. `Clone`, `prost::Message`, `Add` for `GF16`, …).
Aeneas nests every trait-instance method under a `…Insts.<TraitInst>.<method>` namespace, so the
`.Insts.` marker identifies them. (Verified to coincide exactly with `translation.json`'s
`trait_impls` registry; inherent methods and free functions never contain it.) -/
def TransFun.isTraitImpl (f : TransFun) : Bool := (f.leanName.splitOn ".Insts.").length > 1

def parseTransFun (j : Json) : TransFun :=
  let src := jVal? j "source"
  { defId := jNat j "def_id"
    leanName := jStr j "lean_name"
    leanFile := jStr j "lean_file"
    isOpaque := jBool j "is_opaque"
    canFail := jBool j "can_fail"
    -- Loop wrapper/body entries carry a (non-null) `loop` field; ordinary functions omit it.
    isLoopArtifact := match jVal? j "loop" with
      | some Json.null => false
      | some _ => true
      | none => false
    rustName := jStr j "rust_name"
    source := (src.map (jStr · "file")).getD ""
    lineStart := (src.map (jNat · "begin_line")).getD 0
    lineEnd := (src.map (jNat · "end_line")).getD 0
    isLocal := jBool j "is_local" }

/-- Parse the `functions` array of `translation.json`. -/
def parseTranslation (j : Json) : Array TransFun :=
  (jArr j "functions").map parseTransFun

/-- Read and parse `translation.json`. -/
def readTranslation : IO (Array TransFun) := do
  let transStr ← IO.FS.readFile Utils.Config.translationJsonPath
  let transJson ← IO.ofExcept (Json.parse transStr)
  return parseTranslation transJson

end Utils.Lib.Translation
