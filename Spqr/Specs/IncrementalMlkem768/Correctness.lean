/-
Copyright 2026 The Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Alessandro D'Angelo
-/
import Spqr.Specs.IncrementalMlkem768.Instance
import VCVio.EvalDist.Monad.Disagreement
import VCVio.EvalDist.Bool

/-! # Incremental ML-KEM-768 correctness transfer

The failure-probability transfer proceeds by normalizing both correctness experiments to
three samples `(d, z, m)`, proving pointwise equality of their deterministic residues on
the sampling guard (the program equality on that event, packaged as `byteTail_eq_modelTail`),
and applying VCV-io's `probEvent_bind_le_add_of_disagree` to prove

```text
Pr[SPQR failure] ≤ Pr[model failure] + Pr[the sampling guard is false].
```

The hypothesis `hTail` bounds the last term by `εSample`.  Independently,
`MLKEM.incrementalCorrectExp_failure_le_mlkem768` bounds the model term under the explicit
joint-distribution hypothesis `FIPS203NoiseModel`.  The theorem does not identify or justify
either premise: both are stated in its signature.
-/

open Aeneas Aeneas.Std Result OracleComp ENNReal
open spqr

namespace Spqr.IncrementalMlkem768

noncomputable section



/-- The sampling guard as an event on keygen seed `d`: every entry of the `3 × 3` matrix at
`ρ = (G(d)).1` is rejection-sampled as in FIPS 203 Algorithm 7, within the model's fixed
840-byte SHAKE-128 budget.
Source: FIPS 203, <https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.203.pdf>.
The predicate is `MLKEM.Concrete.matrixSampleWithinBudget`; all three contract guards in
the experiment reduce to this one event through `keygenInternal_fst_rho`. -/
def keygenSampleWithinBudget (d : MLKEM.Seed32) : Prop :=
  MLKEM.Concrete.matrixSampleWithinBudget 3 (Prims768.gKeygen d).1

/-- The SPQR byte-level round-trip result after fixing the three random samples `(d, z, m)`.
It calls the byte-level KEM built from the transpiled wrapper entry points. -/
def spqrRoundTripResult (d z : MLKEM.Seed32) (m : MLKEM.Message) : Bool :=
  let (pk, sk) := keygenRun d z
  let (st, c1, k) := encaps1Run pk.val.1 m
  let c2 := encaps2Run st pk.val.2
  decide (decapsRun sk (c1, c2) = some k)

/-- The ML-KEM model's round-trip result after fixing `(d, z, m)`.  This is the deterministic
body obtained by expanding the secure-messaging `CorrectExp` after its three samples. -/
def mlkemModelRoundTripResult (d z : MLKEM.Seed32) (m : MLKEM.Message) : Bool :=
  let ek := (MLKEM.keygenInternal Ring768 Enc768 Prims768 d z).1
  let dk := (MLKEM.keygenInternal Ring768 Enc768 Prims768 d z).2
  let s :=
    MLKEM.incrementalEncaps1 Ring768 Prims768 (MLKEM.incrementalHeader Prims768 ek) m
  let c2 := MLKEM.incrementalEncaps2 Ring768 Prims768 s.1 ek.tHatEncoded
  decide (some (MLKEM.decapsInternal Ring768 Enc768 Prims768 dk
    { uEncoded := s.2.1, vEncoded := c2 }) = some s.2.2)

/-- Pure monad-law normalization exposes the extracted experiment as three samples `(d, z, m)`
followed by `spqrRoundTripResult`. -/
theorem spqrIncremental_correctExp_eq :
    spqrIncremental.CorrectExp = (do
      let d ←$ᵗ MLKEM.Seed32
      let z ←$ᵗ MLKEM.Seed32
      let m ←$ᵗ MLKEM.Message
      return spqrRoundTripResult d z m) := by
  rw [spqrIncremental.correctExp_eq]
  simp only [KEMScheme.CorrectExp, spqrKEM, spqrEncaps1, spqrEncaps2,
    spqrRoundTripResult, Equiv.refl_symm, Equiv.refl_apply, bind_assoc, pure_bind]

/-- Pure monad-law normalization exposes the model experiment as three samples `(d, z, m)`
followed by `mlkemModelRoundTripResult`. -/
theorem mlkemIncremental_correctExp_eq :
    (MLKEM.mlkemIncremental .MLKEM768 Ring768 Prims768).CorrectExp = (do
      let d ←$ᵗ MLKEM.Seed32
      let z ←$ᵗ MLKEM.Seed32
      let m ←$ᵗ MLKEM.Message
      return mlkemModelRoundTripResult d z m) := by
  rw [(MLKEM.mlkemIncremental .MLKEM768 Ring768 Prims768).correctExp_eq]
  simp only [KEMScheme.CorrectExp, MLKEM.mlkemScheme, MLKEM.asKEMScheme,
    MLKEM.keygen, mlkemModelRoundTripResult, monad_norm,
    MLKEM.encapsInternal_eq_staged]

/-- On the sampling guard, the transpiled wrapper stack and the model compute equal Booleans.
This is the transfer's core: it chains the four on-guard evaluation bridges and uses the
proved inverse laws for the two byte representations. -/
theorem byteResult_eq_modelResult (codec : StateCodec) (hcore : CoreSpec codec)
    (d z : MLKEM.Seed32) (m : MLKEM.Message) (hd : keygenSampleWithinBudget d) :
    spqrRoundTripResult d z m = mlkemModelRoundTripResult d z m := by
  have hbudget : MLKEM.Concrete.matrixSampleWithinBudget 3 (Prims768.gKeygen d).1 := hd
  have hkg := keygenRun_of_budget codec hcore d z hbudget
  have hhdrBudget : MLKEM.Concrete.matrixSampleWithinBudget 3
      (MLKEM.incrementalHeader Prims768
        (MLKEM.keygenInternal Ring768 Enc768 Prims768 d z).1).1 := by
    simpa only [MLKEM.incrementalHeader, keygenInternal_fst_rho] using hbudget
  have he1 := encaps1Run_of_budget codec hcore
    (keygenRun d z).1.val.1
    (MLKEM.incrementalHeader Prims768
      (MLKEM.keygenInternal Ring768 Enc768 Prims768 d z).1)
    m hkg.1 hhdrBudget
  have he2 := encaps2Run_of_encoded codec hcore
    (encaps1Run (keygenRun d z).1.val.1 m).1
    (MLKEM.incrementalEncaps1 Ring768 Prims768
      (MLKEM.incrementalHeader Prims768
        (MLKEM.keygenInternal Ring768 Enc768 Prims768 d z).1) m).1
    (keygenRun d z).1.val.2
    (MLKEM.keygenInternal Ring768 Enc768 Prims768 d z).1.tHatEncoded
    he1.1 hkg.2.1
  have hdkBudget : MLKEM.Concrete.matrixSampleWithinBudget 3
      (MLKEM.keygenInternal Ring768 Enc768 Prims768 d z).2.ekPKE.rho := by
    simpa only [keygenInternal_snd_ekPKE, keygenInternal_fst_rho] using hbudget
  have hc1 : (encaps1Run (keygenRun d z).1.val.1 m).2.1.length = 960 := by
    rw [alloc.vec.Vec.length, he1.2.1]
    exact length_u8ListOfEncodedU_incrementalEncaps1
      (MLKEM.incrementalHeader Prims768
        (MLKEM.keygenInternal Ring768 Enc768 Prims768 d z).1) m
  have hdec := decapsRun_of_wellFormed codec hcore
    (keygenRun d z).2
    (MLKEM.keygenInternal Ring768 Enc768 Prims768 d z).2
    ((encaps1Run (keygenRun d z).1.val.1 m).2.1,
      encaps2Run (encaps1Run (keygenRun d z).1.val.1 m).1 (keygenRun d z).1.val.2)
    (wellFormedDK_keygenInternal d z) hdkBudget hkg.2.2 hc1 he2.2
  have hct :
      ciphertextOfU8Lists
        (encaps1Run (keygenRun d z).1.val.1 m).2.1.val
        (encaps2Run (encaps1Run (keygenRun d z).1.val.1 m).1
          (keygenRun d z).1.val.2).val =
      { uEncoded := (MLKEM.incrementalEncaps1 Ring768 Prims768
          (MLKEM.incrementalHeader Prims768
            (MLKEM.keygenInternal Ring768 Enc768 Prims768 d z).1) m).2.1,
        vEncoded := MLKEM.incrementalEncaps2 Ring768 Prims768
          (MLKEM.incrementalEncaps1 Ring768 Prims768
            (MLKEM.incrementalHeader Prims768
              (MLKEM.keygenInternal Ring768 Enc768 Prims768 d z).1) m).1
          (MLKEM.keygenInternal Ring768 Enc768 Prims768 d z).1.tHatEncoded } := by
    rw [he1.2.1, he2.1]
    simp [ciphertextOfU8Lists, u8ListOfEncodedU, u8ListOfEncodedV]
  rw [hct] at hdec
  have hmap_iff :
      decapsRun (keygenRun d z).2
          ((encaps1Run (keygenRun d z).1.val.1 m).2.1,
            encaps2Run (encaps1Run (keygenRun d z).1.val.1 m).1
              (keygenRun d z).1.val.2) =
        some (encaps1Run (keygenRun d z).1.val.1 m).2.2 ↔
      (decapsRun (keygenRun d z).2
          ((encaps1Run (keygenRun d z).1.val.1 m).2.1,
            encaps2Run (encaps1Run (keygenRun d z).1.val.1 m).1
              (keygenRun d z).1.val.2)).map (fun v => v.val) =
        some (encaps1Run (keygenRun d z).1.val.1 m).2.2.val := by
    constructor
    · intro h
      rw [h]
      rfl
    · intro h
      cases ho : decapsRun (keygenRun d z).2
          ((encaps1Run (keygenRun d z).1.val.1 m).2.1,
            encaps2Run (encaps1Run (keygenRun d z).1.val.1 m).1
              (keygenRun d z).1.val.2) with
      | none => simp only [ho, Option.map, reduceCtorEq] at h
      | some v =>
        rw [ho, Option.map, Option.some.injEq] at h
        rw [Option.some.injEq]
        exact Subtype.ext h
  have hbyte_iff :
      decapsRun (keygenRun d z).2
          ((encaps1Run (keygenRun d z).1.val.1 m).2.1,
            encaps2Run (encaps1Run (keygenRun d z).1.val.1 m).1
              (keygenRun d z).1.val.2) =
        some (encaps1Run (keygenRun d z).1.val.1 m).2.2 ↔
      some (MLKEM.decapsInternal Ring768 Enc768 Prims768
          (MLKEM.keygenInternal Ring768 Enc768 Prims768 d z).2
          { uEncoded := (MLKEM.incrementalEncaps1 Ring768 Prims768
              (MLKEM.incrementalHeader Prims768
                (MLKEM.keygenInternal Ring768 Enc768 Prims768 d z).1) m).2.1,
            vEncoded := MLKEM.incrementalEncaps2 Ring768 Prims768
              (MLKEM.incrementalEncaps1 Ring768 Prims768
                (MLKEM.incrementalHeader Prims768
                  (MLKEM.keygenInternal Ring768 Enc768 Prims768 d z).1) m).1
              (MLKEM.keygenInternal Ring768 Enc768 Prims768 d z).1.tHatEncoded }) =
        some (MLKEM.incrementalEncaps1 Ring768 Prims768
          (MLKEM.incrementalHeader Prims768
            (MLKEM.keygenInternal Ring768 Enc768 Prims768 d z).1) m).2.2 := by
    rw [hmap_iff, hdec, he1.2.2, Option.some.injEq, Option.some.injEq]
    exact u8ListOfBytes_injective.eq_iff
  simp only [spqrRoundTripResult, mlkemModelRoundTripResult]
  apply Bool.eq_iff_iff.mpr
  simpa only [decide_eq_true_eq] using hbyte_iff

/-- At fixed on-guard `d`, pointwise result equality lifts across the `(z, m)` samples to
equality of the two tails, discharging the disagreement bound away from its bad event. -/
theorem byteTail_eq_modelTail (codec : StateCodec) (hcore : CoreSpec codec)
    (d : MLKEM.Seed32) (hd : keygenSampleWithinBudget d) :
    (do
      let z ←$ᵗ MLKEM.Seed32
      let m ←$ᵗ MLKEM.Message
      return spqrRoundTripResult d z m : ProbComp Bool) = (do
      let z ←$ᵗ MLKEM.Seed32
      let m ←$ᵗ MLKEM.Message
      return mlkemModelRoundTripResult d z m) := by
  simp_rw [byteResult_eq_modelResult codec hcore d _ _ hd]

/-- The correctness experiment on transpiled SPQR incremental ML-KEM-768 — extracted shipped
code, never a model stand-in — fails with probability at most
`fips203DecapsulationFailureBound .MLKEM768 + εSample`: 2^(−164.8), the ML-KEM-768
decapsulation-failure rate from FIPS 203, Table 1, plus the sampling tail.
Source: FIPS 203, <https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.203.pdf>.

The `codec` and `hcore` hypotheses are an assumed contract on the shipped libcrux core, in
deterministic explicit-randomness form; see `CoreSpec.lean`. `hModel` states the exact
per-coordinate joint law formalized in secure-messaging:the decoded message coefficient is a uniform
bit independent of a coefficient drawn from the folded ML-KEM noise law.  The branch also does not
prove `hModel`.  Separately, `hTail` bounds the probability that the fixed-budget SampleNTT guard is
false; `εSample` is not fixed here.

Round-trip correctness alone does not certify the FO check; the FO content lives in
`CoreSpec.decapsulate_eq_decapsInternal`'s all-ciphertext quantification.  The folder
`README.md` gives the complete assumption and trust ledger. -/
theorem spqr_incrementalCorrectExp_failure_le_mlkem768
    (codec : StateCodec) (hcore : CoreSpec codec)
    (hModel : MLKEM.FIPS203NoiseModel .MLKEM768 MLKEM.Concrete.concreteNTTRingOps
      MLKEM.Concrete.mlkem768Primitives)
    (εSample : ℝ≥0∞)
    (hTail : Pr[ (fun d => ¬ keygenSampleWithinBudget d) |
      ($ᵗ MLKEM.Seed32 : ProbComp MLKEM.Seed32)] ≤ εSample) :
    Pr[= false | ProbCompRuntime.probComp.evalDist spqrIncremental.CorrectExp]
      ≤ MLKEM.fips203DecapsulationFailureBound .MLKEM768 + εSample := by
  classical
  have hDisagree :
      Pr[ (· = false) | (do
        let d ← $ᵗ MLKEM.Seed32
        let z ← $ᵗ MLKEM.Seed32
        let m ← $ᵗ MLKEM.Message
        return spqrRoundTripResult d z m : ProbComp Bool)] ≤
      Pr[ (· = false) | (do
        let d ← $ᵗ MLKEM.Seed32
        let z ← $ᵗ MLKEM.Seed32
        let m ← $ᵗ MLKEM.Message
        return mlkemModelRoundTripResult d z m : ProbComp Bool)] + εSample := by
    have h := probEvent_bind_le_add_of_disagree
      (mx := ($ᵗ MLKEM.Seed32 : ProbComp MLKEM.Seed32))
      (my := fun d => (do
        let z ← $ᵗ MLKEM.Seed32
        let m ← $ᵗ MLKEM.Message
        return spqrRoundTripResult d z m : ProbComp Bool))
      (oc := fun d => (do
        let z ← $ᵗ MLKEM.Seed32
        let m ← $ᵗ MLKEM.Message
        return mlkemModelRoundTripResult d z m : ProbComp Bool))
      (q := (· = false)) (D := fun d => ¬ keygenSampleWithinBudget d)
      (ε₁ := εSample) (ε₂ := 0) hTail (by
        intro d _ hd
        have hd' : keygenSampleWithinBudget d := by simpa only [not_not] using hd
        change Pr[ (· = false) | (do
          let z ← $ᵗ MLKEM.Seed32
          let m ← $ᵗ MLKEM.Message
          return spqrRoundTripResult d z m : ProbComp Bool)] ≤
          Pr[ (· = false) | (do
            let z ← $ᵗ MLKEM.Seed32
            let m ← $ᵗ MLKEM.Message
            return mlkemModelRoundTripResult d z m : ProbComp Bool)] + 0
        rw [byteTail_eq_modelTail codec hcore d hd', add_zero])
    simpa only [add_zero] using h
  have hModelBound := MLKEM.incrementalCorrectExp_failure_le_mlkem768 hModel
  rw [mlkemIncremental_correctExp_eq] at hModelBound
  rw [← probEvent_not_eq_probOutput] at hModelBound
  simp only [ProbCompRuntime.probComp, ProbCompRuntime.evalDist,
    SPMFSemantics.ofMonadLift_evalDist] at hModelBound
  rw [spqrIncremental_correctExp_eq]
  rw [← probEvent_not_eq_probOutput]
  simp only [ProbCompRuntime.probComp, ProbCompRuntime.evalDist,
    SPMFSemantics.ofMonadLift_evalDist]
  exact hDisagree.trans (add_le_add_left hModelBound εSample)

end

end Spqr.IncrementalMlkem768
