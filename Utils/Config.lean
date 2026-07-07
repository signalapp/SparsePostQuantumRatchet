import Lean
/-! Config: project-specific settings for the verification status tracking utility. -/

open Lean

namespace Utils.Config

/-- The module to import to obtain the full environment (hand-written specs + the extracted
`SrcTranslated.*` declarations, which `Spqr` imports). -/
def mainModule : Name := `Spqr

/-- The crate name (matches the LLBC `crate_name`). -/
def crateName : String := "spqr"

/-- Suffix forming a spec theorem name: function `foo` ↦ theorem `foo_spec`. -/
def specSuffix : String := "_spec"

/-- Location of translation.json produced by Aeneas. -/
def translationJsonPath : String := "translation.json"

/-- Default output path for the status report. -/
def statusOutPath : String := "status.json"

end Utils.Config
