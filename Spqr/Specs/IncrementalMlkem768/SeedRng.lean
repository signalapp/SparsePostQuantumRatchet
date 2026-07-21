/-
Copyright 2026 The Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Alessandro D'Angelo
-/
import SrcTranslated.FunsExternal

/-! # Deterministic seed dispenser for the extracted rng interface

The extracted SPQR wrapper threads randomness through the `rand_core.RngCore` /
`rand.rng.Rng` / `rand_core.CryptoRng` trait structures (`SrcTranslated/Types.lean:239-258`);
each entry point draws via a single `fill_bytes` call (`generate`: 64 bytes; `encaps1`:
32 bytes).  `SeedDispenser` is the deterministic instance used by the e2e PoC: it carries the
exact bytes to be served, and `fill_bytes` deals them out front-first.  The probabilistic
layer samples the model randomness and loads its byte image into a dispenser, so the
extracted functions stay deterministic while the experiment stays probabilistic. -/

open Aeneas Aeneas.Std Result
open spqr

namespace Spqr.IncrementalMlkem768

/-- A deterministic rng that serves exactly the bytes it carries. -/
structure SeedDispenser where
  /-- The bytes still to be served, front-first. -/
  bytes : List Std.U8

namespace SeedDispenser

/-- Serve the next `s.length` bytes: the filled slice is `bytes.take s.length`, the dispenser
keeps `bytes.drop s.length`.  Panics (like a depleted test rng) if not enough bytes remain. -/
def fillBytes (d : SeedDispenser) (s : Slice Std.U8) :
    Result (SeedDispenser × Slice Std.U8) :=
  if h : s.length ≤ d.bytes.length then
    ok (⟨d.bytes.drop s.length⟩, ⟨d.bytes.take s.length, by scalar_tac⟩)
  else
    fail .panic

/-- `RngCore` instance: `fill_bytes` deals from the dispenser; the SPQR wrapper never calls
`next_u32`/`next_u64`, so they are modelled as panics. -/
def rngCore : rand_core.RngCore SeedDispenser where
  next_u32 := fun _ => fail .panic
  next_u64 := fun _ => fail .panic
  fill_bytes := fillBytes

/-- `Rng` instance over `rngCore`. -/
def rng : rand.rng.Rng SeedDispenser where
  rand_coreRngCoreInst := rngCore

/-- `CryptoRng` instance over `rngCore`. -/
def cryptoRng : rand_core.CryptoRng SeedDispenser where
  RngCoreInst := rngCore

@[simp] theorem rng_fill_bytes_eq :
    rng.rand_coreRngCoreInst.fill_bytes = fillBytes := by
  rfl

@[step]
theorem fillBytes_spec (d : SeedDispenser) (s : Slice Std.U8)
    (h : s.length ≤ d.bytes.length) :
    fillBytes d s
      ⦃ fun (r : SeedDispenser × Slice Std.U8) =>
        r.1.bytes = d.bytes.drop s.length ∧ r.2.val = d.bytes.take s.length ⦄ := by
  simp [fillBytes, h]

end SeedDispenser

end Spqr.IncrementalMlkem768
