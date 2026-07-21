/-
Copyright 2026 The Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Alessandro D'Angelo
-/
import LatticeCrypto.MLKEM.Concrete.Instance

/-! # Budgeted SampleNTT acceptance domain (staged for upstream VCV-io)

`LatticeCrypto.MLKEM.Concrete.Instance`'s `concreteSampleNTT` squeezes a fixed 840-byte
SHAKE-128 stream and zero-pads if rejection sampling does not fill all 256 coefficients;
shipped implementations (e.g. libcrux's `sample_from_xof`) squeeze the same stream but keep
squeezing past 840 bytes until full.  The two agree exactly on inputs where the first 840
bytes already yield 256 accepted candidates.  `sampleNTTWithinBudget` names that domain
through the public `FFI.shake128` surface only, so contracts about shipped implementations
can be premise-guarded by it instead of asserting an equality on the (plausibly nonempty)
exhaustion domain.

Faithfulness note: `acceptedCandidates` mirrors the acceptance count of `Instance.lean`'s
private `rejectionSample` (same 3-byte candidate extraction, same `< q` test, uncapped
count); the private definition cannot be referenced from here, so the mirror's fidelity is
established by inspection and is part of any consuming contract's documented justification.

Upstream destination: alongside `Concrete/Instance.lean`, ideally superseded by a streaming
`sampleNTT` semantics with an almost-sure-termination axiom (cf. SymCRust's
`kyber_terminates` in [microsoft/SymCrypt, branch
`feature/verifiedcrypto`](https://github.com/microsoft/SymCrypt)), after which this guard
dissolves. -/

namespace MLKEM.Concrete

/-- Number of accepted rejection-sampling candidates in a SHAKE-128 stream, per FIPS 203
Algorithm 7: each 3-byte group yields candidates `d₁ = b₀ + 256·(b₁ % 16)` and
`d₂ = b₁/16 + 16·b₂`, accepted iff `< q = 3329`.  Uncapped count — reaching `256` is exactly
the condition under which the budgeted sampler fills all coefficients. -/
def acceptedCandidates (stream : ByteArray) : Nat := Id.run do
  let mut count := 0
  for chunk in [0:stream.size / 3] do
    let pos := chunk * 3
    let b0 := (stream.get! pos).toNat
    let b1 := (stream.get! (pos + 1)).toNat
    let b2 := (stream.get! (pos + 2)).toNat
    if b0 + 256 * (b1 % 16) < 3329 then
      count := count + 1
    if b1 / 16 + 16 * b2 < 3329 then
      count := count + 1
  return count

/-- `SampleNTT(ρ ‖ j ‖ i)` fills all 256 coefficients within `concreteSampleNTT`'s fixed
840-byte squeeze — the domain on which the budgeted sampler agrees with a streaming
implementation.  Input construction mirrors `concreteSampleNTT` (seed bytes, then `j`, then
`i`). -/
def sampleNTTWithinBudget (rho : Seed32) (j i : Nat) : Prop :=
  256 ≤ acceptedCandidates
    (FFI.shake128 (((⟨rho.toArray⟩ : ByteArray).push j.toUInt8).push i.toUInt8) 840)

/-- Every entry of the `k × k` public matrix samples within budget at seed `ρ`. -/
def matrixSampleWithinBudget (k : Nat) (rho : Seed32) : Prop :=
  ∀ i j : Nat, i < k → j < k → sampleNTTWithinBudget rho j i

end MLKEM.Concrete
