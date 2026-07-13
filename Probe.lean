/-
Stage-0 go/no-go probe (throwaway).

Elaborating this single file proves the transpiled extraction (`SrcTranslated`) and the
secure-messaging model (`SecureMessaging.KEM.MLKEM.Incremental`) co-elaborate against ONE
unified Lean/mathlib toolchain (v4.30.0 release). This is Gate B1 of the incremental-ML-KEM
e2e PoC roadmap.

Delete once the real PoC specs land under `Spqr/Specs/IncrementalMlkem768/`.
-/
import SrcTranslated
import SecureMessaging.KEM.MLKEM.Incremental

-- Touch a declaration from each side so both import roots are genuinely exercised, not just
-- parsed: the transpiled wrapper `generate`, and n1's shipped-code failure bound.
#check @spqr.incremental_mlkem768.generate
#check @MLKEM.incrementalCorrectExp_failure_le_mlkem768
