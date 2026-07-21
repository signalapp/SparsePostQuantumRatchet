/-
Copyright 2026 The Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Alessandro D'Angelo
-/
import Spqr.Specs.IncrementalMlkem768.WrapperSpecs

/-! # Extracted incremental ML-KEM-768 byte instance

This byte-level KEM instance runs the extracted functions, never the model.  Its unreachable
failure arms use fixed junk constants; they do not track the inputs or compute model
functions.  For seeds satisfying the sampling guard, `CoreSpec` rules those arms out.  The
probability proof in `Spqr.Specs.IncrementalMlkem768.Correctness` bounds the remaining seeds
by the separate hypothesis `Pr[¬keygenSampleWithinBudget] ≤ εSample`.

`ValidBytePair` is the byte-level validity predicate the shipped validator decides: hash
match and canonicality.  It is deliberately stronger than the model's hash-only `validPK`;
the canonical-support reduction below states their precise relationship.
-/

open Aeneas Aeneas.Std Result OracleComp
open spqr

namespace Spqr.IncrementalMlkem768

noncomputable section

/-- Byte-level public-key header: the 64-byte libcrux `pk1` (`rho || H(ek)`). -/
abbrev ByteHeader := {l : List Std.U8 // l.length = 64}

/-- Byte-level public-key vector: the 1152-byte serialized `tHat` (libcrux `pk2`). -/
abbrev ByteVector := {l : List Std.U8 // l.length = 1152}

/-- The byte-level validity predicate: the stored hash matches
`H(tHatEncoded || rho)` AND the vector is a canonical 12-bit encoding.  This is what the
shipped `validate_pk_bytes` decides (`ek_matches_header_eq_validBytePair`); it is deliberately
stronger than the model's hash-only `validPK` -- see `validBytePair_encodedModel_eq_validPK` for
the reduction on canonical support. -/
def ValidBytePair (hdr : ByteHeader) (vec : ByteVector) : Bool :=
  (decide (MLKEM.encapsulationKeyHash Enc768 Prims768
      { tHatEncoded := tHatOfU8List vec.val,
        rho := (headerOfU8List hdr.val hdr.property).1 }
    = (headerOfU8List hdr.val hdr.property).2))
    && Enc768.publicKeyCanonical (tHatOfU8List vec.val)

/-- Byte-level public key: a header/vector pair passing `ValidBytePair`. -/
abbrev BytePK := {parts : ByteHeader × ByteVector // ValidBytePair parts.1 parts.2 = true}

/-- Byte-level secret key / shared secret / ciphertext components: extracted byte vectors. -/
abbrev ByteSK := alloc.vec.Vec Std.U8
abbrev ByteK := alloc.vec.Vec Std.U8
abbrev ByteC1 := alloc.vec.Vec Std.U8
abbrev ByteC2 := alloc.vec.Vec Std.U8
abbrev ByteC := ByteC1 × ByteC2
abbrev ByteSt := alloc.vec.Vec Std.U8

/-- Decidable byte-vector equality lets the correctness experiment's final `decide` compare
the extracted shared secrets. -/
instance : DecidableEq (alloc.vec.Vec Std.U8) :=
  fun a b => decidable_of_iff (a.val = b.val) Subtype.ext_iff.symm

/-- Model key generation embeds its encapsulation key in the decapsulation key; this projection
is used when applying the wrapper contract to model-keygen outputs. -/
theorem keygenInternal_snd_ekPKE (d z : MLKEM.Seed32) :
    (MLKEM.keygenInternal Ring768 Enc768 Prims768 d z).2.ekPKE =
      (MLKEM.keygenInternal Ring768 Enc768 Prims768 d z).1 := by
  rfl

/-- Model key generation stores `H(ek)` in the decapsulation key, supplying the header-hash
equation for model-keygen outputs. -/
theorem keygenInternal_snd_ekHash (d z : MLKEM.Seed32) :
    (MLKEM.keygenInternal Ring768 Enc768 Prims768 d z).2.ekHash =
      MLKEM.encapsulationKeyHash Enc768 Prims768
        (MLKEM.keygenInternal Ring768 Enc768 Prims768 d z).1 := by
  rfl

/-- The model keygen image uses the first `G(d)` output as `ρ`, reducing every sampling guard
arising in the fresh-key round trip to one event on `d`. -/
theorem keygenInternal_fst_rho (d z : MLKEM.Seed32) :
    (MLKEM.keygenInternal Ring768 Enc768 Prims768 d z).1.rho = (Prims768.gKeygen d).1 := by
  rfl

/-- The model keygen image encodes `t̂` in 1152 bytes, as required by the byte carrier and
the wrapper contract. -/
theorem keygenInternal_fst_tHat_len (d z : MLKEM.Seed32) :
    (u8ListOfTHat (MLKEM.keygenInternal Ring768 Enc768 Prims768 d z).1.tHatEncoded).length
      = 1152 := by
  simpa only [keygenInternal_snd_ekPKE] using
    (wellFormedDK_keygenInternal d z).tHat_len

/-- Model-keygen outputs use the canonical 12-bit encoding, so the shipped byte validator
accepts them under `CoreSpec`. -/
theorem keygenInternal_fst_canonical (d z : MLKEM.Seed32) :
    Enc768.publicKeyCanonical
      (MLKEM.keygenInternal Ring768 Enc768 Prims768 d z).1.tHatEncoded = true := by
  simp [MLKEM.keygenInternal, MLKEM.KPKE.keygenFromSeed]

/-- A byte-encoded model header/vector pair with matching hash and canonical encoding passes
the byte-level validator. -/
theorem validBytePair_of_encodedModel (hdrM : MLKEM.Seed32 × MLKEM.PublicKeyHash)
    (vecM : Enc768.EncodedTHat) (hlen : (u8ListOfTHat vecM).length = 1152)
    (hcanon : Enc768.publicKeyCanonical vecM = true)
    (hhash : MLKEM.encapsulationKeyHash Enc768 Prims768
      { tHatEncoded := vecM, rho := hdrM.1 } = hdrM.2) :
    ValidBytePair ⟨u8ListOfHeader hdrM, length_u8ListOfHeader hdrM⟩
      ⟨u8ListOfTHat vecM, hlen⟩ = true := by
  simp [ValidBytePair, hcanon, hhash]

/-- On canonically encoded vectors, the byte predicate reduces to the model's hash-only
`validPK` (the canonical-support reduction; canonicity is automatic on keygen
images).  This supersedes any global "byte validator = model validator" reading. -/
theorem validBytePair_encodedModel_eq_validPK (hdrM : MLKEM.Seed32 × MLKEM.PublicKeyHash)
    (vecM : Enc768.EncodedTHat) (hlen : (u8ListOfTHat vecM).length = 1152)
    (hcanon : Enc768.publicKeyCanonical vecM = true) :
    ValidBytePair ⟨u8ListOfHeader hdrM, length_u8ListOfHeader hdrM⟩
      ⟨u8ListOfTHat vecM, hlen⟩ =
      (MLKEM.mlkemIncremental .MLKEM768 Ring768 Prims768).validPK hdrM vecM := by
  simp [ValidBytePair, hcanon, MLKEM.mlkemIncremental]

/-- The shipped validator (through the SPQR wrapper) computes exactly `ValidBytePair`. -/
theorem ek_matches_header_eq_validBytePair (codec : StateCodec) (hcore : CoreSpec codec)
    (hdrB : ByteHeader) (vecB : ByteVector) (ek hdr : alloc.vec.Vec Std.U8)
    (hek : ek.val = vecB.val) (hhdr : hdr.val = hdrB.val) :
    incremental_mlkem768.ek_matches_header ek hdr = ok (ValidBytePair hdrB vecB) := by
  have hhdr' : hdr.val =
      u8ListOfHeader (headerOfU8List hdrB.val hdrB.property) := by
    rw [hhdr, u8ListOfHeader_headerOfU8List]
  have heklen : ek.length = 1152 := by
    simpa only [alloc.vec.Vec.length, hek] using vecB.property
  obtain ⟨b, hb, hiff⟩ := WP.spec_imp_exists
    (ek_matches_header_correct_spec codec hcore
      (headerOfU8List hdrB.val hdrB.property) ek hdr hhdr' heklen)
  have hbv : b = ValidBytePair hdrB vecB := by
    apply Bool.eq_iff_iff.mpr
    rw [hiff]
    simp only [ValidBytePair, Bool.and_eq_true, decide_eq_true_eq, hek]
  simpa only [hbv] using hb

/-- Fixed fallback public key for the junk arms: the byte encoding of model keygen at
constant seeds.  A constant is not a mock: it tracks no input. -/
def junkPK : BytePK :=
  ⟨(⟨u8ListOfHeader (MLKEM.incrementalHeader Prims768
        (MLKEM.keygenInternal Ring768 Enc768 Prims768 default default).1),
      length_u8ListOfHeader _⟩,
    ⟨u8ListOfTHat
        (MLKEM.keygenInternal Ring768 Enc768 Prims768 default default).1.tHatEncoded,
      keygenInternal_fst_tHat_len default default⟩),
    validBytePair_of_encodedModel _ _ _ (keygenInternal_fst_canonical default default) (by
      simp [MLKEM.incrementalHeader])⟩

/-- Run the extracted `generate` on the dispensed seed bytes; junk on the arms that
`CoreSpec` proves unreachable on the sampling guard. -/
def keygenRun (d z : MLKEM.Seed32) : BytePK × ByteSK :=
  match incremental_mlkem768.generate SeedDispenser.rng SeedDispenser.cryptoRng
      ⟨u8ListOfBytes d ++ u8ListOfBytes z⟩ with
  | ok (keys, _) =>
    if h : keys.hdr.val.length = 64 ∧ keys.ek.val.length = 1152 then
      if hv : ValidBytePair ⟨keys.hdr.val, h.1⟩ ⟨keys.ek.val, h.2⟩ = true then
        (⟨(⟨keys.hdr.val, h.1⟩, ⟨keys.ek.val, h.2⟩), hv⟩, keys.dk)
      else (junkPK, alloc.vec.Vec.new Std.U8)
    else (junkPK, alloc.vec.Vec.new Std.U8)
  | _ => (junkPK, alloc.vec.Vec.new Std.U8)

/-- Run the extracted `encaps1` on the dispensed message bytes. -/
def encaps1Run (hdr : ByteHeader) (m : MLKEM.Message) : ByteSt × ByteC1 × ByteK :=
  match incremental_mlkem768.encaps1 SeedDispenser.rng SeedDispenser.cryptoRng
      ⟨hdr.val, by scalar_tac +nonLin⟩ ⟨u8ListOfBytes m⟩ with
  | ok ((ct1, es, ss), _) => (es, ct1, ss)
  | _ => (alloc.vec.Vec.new Std.U8, alloc.vec.Vec.new Std.U8, alloc.vec.Vec.new Std.U8)

/-- Run the extracted `encaps2`. -/
def encaps2Run (st : ByteSt) (vec : ByteVector) : ByteC2 :=
  match incremental_mlkem768.encaps2 ⟨vec.val, by scalar_tac +nonLin⟩ st with
  | ok ct2 => ct2
  | _ => alloc.vec.Vec.new Std.U8

/-- Run the extracted `decaps`; `none` on failure (never proven reachable on-guard). -/
def decapsRun (sk : ByteSK) (c : ByteC) : Option ByteK :=
  match incremental_mlkem768.decaps sk c.1 c.2 with
  | ok ss => some ss
  | _ => none

/-- Stage 1 as a probabilistic program: sample the model message, run the extracted code. -/
def spqrEncaps1 (hdr : ByteHeader) : ProbComp (ByteSt × ByteC1 × ByteK) := do
  let m ←$ᵗ MLKEM.Message
  return encaps1Run hdr m

/-- Stage 2: deterministic. -/
def spqrEncaps2 (st : ByteSt) (_hdr : ByteHeader) (vec : ByteVector) : ProbComp ByteC2 :=
  return encaps2Run st vec

/-- The byte-level KEM over the extracted SPQR entry points.  `encaps` is the staged
composite: the SPQR crate exposes no monolithic encapsulation. -/
def spqrKEM : KEMScheme ProbComp ByteK BytePK ByteSK ByteC where
  keygen := do
    let d ←$ᵗ MLKEM.Seed32
    let z ←$ᵗ MLKEM.Seed32
    return keygenRun d z
  encaps := fun pk => do
    let (st, c1, k) ← spqrEncaps1 pk.val.1
    let c2 ← spqrEncaps2 st pk.val.1 pk.val.2
    pure ((Equiv.refl ByteC).symm (c1, c2), k)
  decaps := fun sk c => return decapsRun sk c

/-- The extracted SPQR ML-KEM-768 staged-encapsulation witness in the sense of the
[ML-KEM Braid specification §1.2.1](https://signal.org/docs/specifications/mlkembraid/),
consumed by the correctness transfer in `Correctness.lean`. -/
def spqrIncremental : spqrKEM.IncrementalStructure where
  PKheader := ByteHeader
  PKvector := ByteVector
  C₁ := ByteC1
  C₂ := ByteC2
  St := ByteSt
  validPK := ValidBytePair
  splitPK := Equiv.refl BytePK
  splitC := Equiv.refl ByteC
  encaps1 := spqrEncaps1
  encaps2 := spqrEncaps2
  factor := fun _pk => rfl

/-- On the sampling guard at `ρ = (G(d)).1`, extracted key generation returns exactly the
model header, vector, and decapsulation key in the extracted byte representation. -/
theorem keygenRun_of_budget (codec : StateCodec) (hcore : CoreSpec codec)
    (d z : MLKEM.Seed32)
    (hbudget : MLKEM.Concrete.matrixSampleWithinBudget 3 (Prims768.gKeygen d).1) :
    (keygenRun d z).1.val.1.val = u8ListOfHeader (MLKEM.incrementalHeader Prims768
        (MLKEM.keygenInternal Ring768 Enc768 Prims768 d z).1) ∧
    (keygenRun d z).1.val.2.val =
      u8ListOfTHat (MLKEM.keygenInternal Ring768 Enc768 Prims768 d z).1.tHatEncoded ∧
    (keygenRun d z).2.val =
      u8ListOfDK (MLKEM.keygenInternal Ring768 Enc768 Prims768 d z).2 := by
  obtain ⟨⟨keys, rng⟩, hcall, hhdr, hek, hdk, _hrng⟩ := WP.spec_imp_exists
    (generate_correct_spec codec hcore d z hbudget)
  have hhlen : keys.hdr.val.length = 64 := by
    rw [hhdr]
    exact length_u8ListOfHeader _
  have heklen : keys.ek.val.length = 1152 := by
    rw [hek]
    exact keygenInternal_fst_tHat_len d z
  have hv : ValidBytePair ⟨keys.hdr.val, hhlen⟩ ⟨keys.ek.val, heklen⟩ = true := by
    have hhdrB : (⟨keys.hdr.val, hhlen⟩ : ByteHeader) =
        ⟨u8ListOfHeader (MLKEM.incrementalHeader Prims768
          (MLKEM.keygenInternal Ring768 Enc768 Prims768 d z).1),
          length_u8ListOfHeader _⟩ := by
      apply Subtype.ext
      exact hhdr
    have hekB : (⟨keys.ek.val, heklen⟩ : ByteVector) =
        ⟨u8ListOfTHat
          (MLKEM.keygenInternal Ring768 Enc768 Prims768 d z).1.tHatEncoded,
          keygenInternal_fst_tHat_len d z⟩ := by
      apply Subtype.ext
      exact hek
    rw [hhdrB, hekB]
    exact validBytePair_of_encodedModel _ _ _
      (keygenInternal_fst_canonical d z) (by simp [MLKEM.incrementalHeader])
  have hrun : keygenRun d z =
      (⟨(⟨keys.hdr.val, hhlen⟩, ⟨keys.ek.val, heklen⟩), hv⟩, keys.dk) := by
    unfold keygenRun
    simp only [hcall]
    have hp : keys.hdr.val.length = 64 ∧ keys.ek.val.length = 1152 :=
      ⟨hhlen, heklen⟩
    rw [dif_pos hp]
    have hvp : ValidBytePair ⟨keys.hdr.val, hp.1⟩ ⟨keys.ek.val, hp.2⟩ = true := by
      simpa only using hv
    rw [dif_pos hvp]
  rw [hrun]
  exact ⟨hhdr, hek, hdk⟩

/-- On the sampling guard at the header seed, extracted stage one returns exactly the model
state, first ciphertext, and shared secret in the extracted byte representation. -/
theorem encaps1Run_of_budget (codec : StateCodec) (hcore : CoreSpec codec)
    (hdr : ByteHeader) (hdrM : MLKEM.Seed32 × MLKEM.PublicKeyHash) (m : MLKEM.Message)
    (hhdr : hdr.val = u8ListOfHeader hdrM)
    (hbudget : MLKEM.Concrete.matrixSampleWithinBudget 3 hdrM.1) :
    (encaps1Run hdr m).1.val =
      codec.encodeState (MLKEM.incrementalEncaps1 Ring768 Prims768 hdrM m).1 ∧
    (encaps1Run hdr m).2.1.val =
      u8ListOfEncodedU (MLKEM.incrementalEncaps1 Ring768 Prims768 hdrM m).2.1 ∧
    (encaps1Run hdr m).2.2.val =
      u8ListOfBytes (MLKEM.incrementalEncaps1 Ring768 Prims768 hdrM m).2.2 := by
  obtain ⟨⟨⟨ct1, es, ss⟩, rng⟩, hcall, hct, hst, hss, _hrng⟩ := WP.spec_imp_exists
    (encaps1_correct_spec codec hcore hdrM m
      ⟨hdr.val, by scalar_tac +nonLin⟩ hhdr hbudget)
  unfold encaps1Run
  rw [hcall]
  exact ⟨hst, hct, hss⟩

/-- From an exact codec image, extracted stage two returns the model's second ciphertext in the
extracted byte representation and proves its 128-byte length; no sampling guard is needed. -/
theorem encaps2Run_of_encoded (codec : StateCodec) (hcore : CoreSpec codec)
    (st : ByteSt) (stM : MLKEM.Message × MLKEM.Coins) (vec : ByteVector)
    (vecM : Enc768.EncodedTHat)
    (hst : st.val = codec.encodeState stM) (hvec : vec.val = u8ListOfTHat vecM) :
    (encaps2Run st vec).val =
      u8ListOfEncodedV (MLKEM.incrementalEncaps2 Ring768 Prims768 stM vecM) ∧
    (encaps2Run st vec).length = 128 := by
  have hlen : (u8ListOfTHat vecM).length = 1152 := hvec ▸ vec.property
  obtain ⟨ct2, hcall, hval, hctlen⟩ := WP.spec_imp_exists
    (encaps2_correct_spec codec hcore stM vecM
      ⟨vec.val, by scalar_tac +nonLin⟩ st hvec hlen hst)
  unfold encaps2Run
  rw [hcall]
  exact ⟨hval, hctlen⟩

/-- With a well-formed key, correctly sized ciphertexts, and the key's sampling guard,
extracted decapsulation returns the model shared secret in the extracted byte representation. -/
theorem decapsRun_of_wellFormed (codec : StateCodec) (hcore : CoreSpec codec)
    (sk : ByteSK) (dkM : MLKEM.DecapsulationKey P768 Enc768) (c : ByteC)
    (hwf : WellFormedDK dkM)
    (hbudget : MLKEM.Concrete.matrixSampleWithinBudget 3 dkM.ekPKE.rho)
    (hsk : sk.val = u8ListOfDK dkM)
    (hc1 : c.1.length = 960) (hc2 : c.2.length = 128) :
    (decapsRun sk c).map (fun v => v.val) =
      some (u8ListOfBytes (MLKEM.decapsInternal Ring768 Enc768 Prims768 dkM
        (ciphertextOfU8Lists c.1.val c.2.val))) := by
  obtain ⟨ss, hcall, hval⟩ := WP.spec_imp_exists
    (decaps_correct_spec codec hcore dkM sk c.1 c.2 hwf hbudget hsk hc1 hc2)
  unfold decapsRun
  rw [hcall]
  simp only [Option.map, hval]

end

end Spqr.IncrementalMlkem768
