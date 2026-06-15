/-
Copyright 2026 The Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE-APACHE.
Authors: Markus Dablander
-/
import SrcTranslated.Funs

/-!
# Spec theorem for `spqr::authenticator::Authenticator::MACSIZE`

`MACSIZE` is the byte length (= 32) of the authentication tag used by the
`Authenticator`.

**Source:** "spqr/src/authenticator.rs"
-/

namespace spqr.authenticator.Authenticator

/-- **Spec theorem for `spqr::authenticator::Authenticator::MACSIZE`**
• `MACSIZE.val` equals `32`.
-/
@[simp]
theorem MACSIZE_spec :
    MACSIZE.val = 32 := by
  simp [MACSIZE]

end spqr.authenticator.Authenticator
