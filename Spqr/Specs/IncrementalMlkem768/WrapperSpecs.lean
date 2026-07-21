/-
Copyright 2026 The Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Alessandro D'Angelo
-/
import SrcTranslated.Funs
import Spqr.Specs.IncrementalMlkem768.CoreSpec
import Spqr.Specs.IncrementalMlkem768.SeedRng

/-! # Extracted incremental ML-KEM-768 wrapper specifications

These are deterministic symbolic-execution specifications of the transparent wrappers from
`src/incremental_mlkem768.rs`, under the assumed `CoreSpec` contract on the opaque libcrux
core.  `SeedDispenser` serves the model-sampled randomness.  The `⦃ … ⦄` triples are
Aeneas weakest-precondition specifications, marked `@[step]` so the step tactic chains them.
The results strengthen `generate_spec`'s layout-only facts to equations with the exact byte
encodings of model values.

`flip_endianness_of_encapsulation_state` is out of scope: it is dead code behind
`CoreSpec.fixer_ok_none_of_encoded`, which assumes the issue-1275 helper returns `ok none` on
codec images.
-/

open Aeneas Aeneas.Std Result
open spqr

namespace Spqr.IncrementalMlkem768

/-- Running extracted `generate` with `d ‖ z` returns the exact byte encoding of model keygen:
header `ρ ‖ H(ek)`, encoded `t̂`, and the 2400-byte compressed dk, while consuming all 64
seed bytes.  The contract is guarded by the sampling budget at `ρ = (G(d)).1`. -/
@[step]
theorem generate_correct_spec (codec : StateCodec) (hcore : CoreSpec codec)
    (d z : MLKEM.Seed32)
    (hbudget : MLKEM.Concrete.matrixSampleWithinBudget 3 (Prims768.gKeygen d).1) :
    incremental_mlkem768.generate SeedDispenser.rng SeedDispenser.cryptoRng
      ⟨u8ListOfBytes d ++ u8ListOfBytes z⟩
      ⦃ (result : incremental_mlkem768.Keys × SeedDispenser) =>
      result.1.hdr.val = u8ListOfHeader (MLKEM.incrementalHeader Prims768
        (MLKEM.keygenInternal Ring768 Enc768 Prims768 d z).1) ∧
      result.1.ek.val =
        u8ListOfTHat (MLKEM.keygenInternal Ring768 Enc768 Prims768 d z).1.tHatEncoded ∧
      result.1.dk.val = u8ListOfDK (MLKEM.keygenInternal Ring768 Enc768 Prims768 d z).2 ∧
      result.2.bytes = [] ⦄ := by
  unfold incremental_mlkem768.generate
  step
  rw [SeedDispenser.rng_fill_bytes_eq]
  step
  case h => simp_all
  case a =>
    rw [result_post2]
    have hs : ↑((Array.repeat 64#usize 0#u8).from_slice s1) =
        u8ListOfBytes d ++ u8ListOfBytes z := by
      simp_all [Array.from_slice]
    obtain ⟨kp, hkp, hval⟩ :=
      hcore.from_seed_eq_keygenInternal d z _ hs hbudget
    rw [hkp]
    step*
    have hwf := wellFormedDK_keygenInternal d z
    refine ⟨?_, ?_, ?_, ?_⟩
    · simp only [← v_post, s2_post, Array.val_to_slice, a_post2, hval]
      norm_num [Mlkem.mlkem768Params, Mlkem.headerBytes, Mlkem.seedBytes,
        Mlkem.MlkemParams.encapsulationKeyBytes, Mlkem.MlkemParams.serializedPolyBytes]
      rw [slice_u8ListOfDK_hdr _ hwf.sHat_len hwf.tHat_len]
      simp [MLKEM.incrementalHeader, MLKEM.keygenInternal]
    · simp only [← v1_post, s3_post, Array.val_to_slice, a1_post2, hval]
      norm_num [Mlkem.mlkem768Params, Mlkem.MlkemParams.encapsulationKeyBytes,
        Mlkem.MlkemParams.serializedPolyBytes]
      rw [slice_u8ListOfDK_ek _ hwf.sHat_len hwf.tHat_len]
      simp [MLKEM.keygenInternal]
    · simp only [← v2_post, s4_post, Array.val_to_slice, a2_post2, hval]
    · simp_all

/-- The header-only stage returns the exact byte encodings of `incrementalEncaps1`'s ct1,
state, and shared secret with the dispenser drained.  The header carries the hash because
encapsulation
derives its key and coins from `G(m ‖ H(ek))`, so this stage needs no vector; see the
[ML-KEM Braid specification §1.2](https://signal.org/docs/specifications/mlkembraid/).
Agreement is guarded by the sampling budget at the header's seed. -/
@[step]
theorem encaps1_correct_spec (codec : StateCodec) (hcore : CoreSpec codec)
    (hdrM : MLKEM.Seed32 × MLKEM.PublicKeyHash) (m : MLKEM.Message)
    (hdr : alloc.vec.Vec Std.U8) (hhdr : hdr.val = u8ListOfHeader hdrM)
    (hbudget : MLKEM.Concrete.matrixSampleWithinBudget 3 hdrM.1) :
    incremental_mlkem768.encaps1 SeedDispenser.rng SeedDispenser.cryptoRng hdr
      ⟨u8ListOfBytes m⟩
      ⦃ (result : (alloc.vec.Vec Std.U8 × alloc.vec.Vec Std.U8 × alloc.vec.Vec Std.U8)
          × SeedDispenser) =>
      result.1.1.val =
        u8ListOfEncodedU (MLKEM.incrementalEncaps1 Ring768 Prims768 hdrM m).2.1 ∧
      result.1.2.1.val =
        codec.encodeState (MLKEM.incrementalEncaps1 Ring768 Prims768 hdrM m).1 ∧
      result.1.2.2.val =
        u8ListOfBytes (MLKEM.incrementalEncaps1 Ring768 Prims768 hdrM m).2.2 ∧
      result.2.bytes = [] ⦄ := by
  unfold incremental_mlkem768.encaps1
  simp only [hcore.encaps_state_len, hcore.shared_secret_size]
  rw [SeedDispenser.rng_fill_bytes_eq]
  step*
  · simp_all
  · have hslen : s.length = 32 := by simp_all
    have hstate : state.length = 2080 := state_post2
    have hsslen : ss.length = 32 := ss_post2
    have hrng : rng1.bytes = [] := by simpa [hslen] using rng1_post1
    have hhdr' : s2.val = u8ListOfHeader hdrM := s2_post.trans hhdr
    have hrnd : (to_slice_mut_back s1).val = u8ListOfBytes m := by
      rw [s_post2]
      simp [Array.from_slice, rng1_post2, hslen]
    obtain ⟨ct1, stOut, ssOut, hcall, hct, hst, hss⟩ :=
      hcore.encapsulate1_eq_incrementalEncaps1 hdrM m s2 _ state ss
        hhdr' hbudget hrnd hstate hsslen
    rw [s_post2] at hcall ⊢
    simp only [alloc.vec.Vec.deref_mut, lift, bind_tc_ok]
    simp only [Subtype.coe_eta, uncurry_apply_pair]
    rw [hcall]
    simp only [core.result.Result.expect]
    step*
    refine ⟨?_, hst, hss, hrng⟩
    simpa only [← v_post, Array.val_to_slice] using hct

/-- The wrapper first runs the issue-1275 fixer on `es`; `hcore` yields `ok none`,
`as_ref` preserves `none`, and `unwrap_or` therefore gives back `es`.  The following source
inspection motivates that hypothesis for the intended libcrux layout.  The fixer scans only
`es[1536..2048]`, the `error2` segment of the `r-hat(1536) || e2(512) || m(32)` layout,
as 256 little-endian `i16` chunks.
Source: [FIPS 203](https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.203.pdf).
Table 2 (p. 39) fixes ML-KEM-768's `η₂ = 2`; `e₂` is drawn by Algorithm 14, line 17
(p. 30).  CBD `η₂` therefore bounds every coefficient in `[-2, 2]`
by construction for any input bytes (a difference of two 2-bit-weight sums), not merely
distributionally.  The correct little-endian encodings are
`{0x0000, 0x0001, 0x0002, 0xFFFE, 0xFFFF}`.  In the fixer's match, `0x0000` and
`0xFFFF` continue the loop; `0x0001`, `0x0002`, and `0xFFFE` return `None`; the flip
triggers `0x0100`, `0x0200`, and `0xFEFF` denote 256, 512, and -257, all strictly
outside `[-2, 2]`; every other value returns `None`; and loop exhaustion returns
`None`.  Thus every arm reachable from a correctly encoded `e₂` returns `None`, for
any coins.

The `result.length = 128` conjunct is not derivable from the model alone because its
byte-encoding size lemma is private in VCV-io.  Under `hcore`, it follows from the wrapper's
`Ciphertext2 128` return type and supplies exactly the downstream decapsulation precondition.
A public upstream size lemma remains a VCV-io follow-up. -/
@[step]
theorem encaps2_correct_spec (codec : StateCodec) (hcore : CoreSpec codec)
    (st : MLKEM.Message × MLKEM.Coins) (vecM : Enc768.EncodedTHat)
    (ek es : alloc.vec.Vec Std.U8)
    (hek : ek.val = u8ListOfTHat vecM)
    (hlen : (u8ListOfTHat vecM).length = 1152)
    (hes : es.val = codec.encodeState st) :
    incremental_mlkem768.encaps2 ek es
      ⦃ (result : alloc.vec.Vec Std.U8) =>
      result.val =
        u8ListOfEncodedV (MLKEM.incrementalEncaps2 Ring768 Prims768 st vecM) ∧
      result.length = 128 ⦄ := by
  unfold incremental_mlkem768.encaps2
  rw [hcore.fixer_ok_none_of_encoded st es hes]
  step*
  simp only [o_post, core.option.Option.unwrap_or] at es1_post s_post
  simp only [es1_post, hes] at s_post
  have hslen : s.len = 2080#usize := by
    apply UScalar.eq_of_val_eq
    simp [s_post, codec.length_encodeState]
  simp only [core.array.TryFromSharedArraySlice.try_from, hslen]
  simp only [dif_pos, core.result.Result.expect, bind_tc_ok]
  step*
  have hs1len : s1.len = 1152#usize := by
    apply UScalar.eq_of_val_eq
    simp [s1_post, hek, hlen]
  simp only [hs1len, dif_pos, bind_tc_ok]
  obtain ⟨ct2, hcall, hct⟩ :=
    hcore.encapsulate2_eq_incrementalEncaps2 st
      ⟨s.val, by rw [s_post]; exact codec.length_encodeState st⟩
      ⟨s1.val, by rw [s1_post, hek]; exact hlen⟩ s_post
  rw [hcall]
  step*
  constructor
  · simp only [← result_post, s2_post, Array.val_to_slice, hct, s1_post, hek,
      tHatOfU8List_u8ListOfTHat]
  · simp only [← result_post, s2_post, Array.length_to_slice]
    norm_num

/-- On any 960/128-byte ciphertext pair, extracted `decaps` returns the exact byte encoding
of `decapsInternal`, including the re-encryption check and implicit rejection, under
`WellFormedDK` and the matrix-sampling guard. -/
@[step]
theorem decaps_correct_spec (codec : StateCodec) (hcore : CoreSpec codec)
    (dkM : MLKEM.DecapsulationKey P768 Enc768) (dk ct1 ct2 : alloc.vec.Vec Std.U8)
    (hwf : WellFormedDK dkM)
    (hbudget : MLKEM.Concrete.matrixSampleWithinBudget 3 dkM.ekPKE.rho)
    (hdk : dk.val = u8ListOfDK dkM)
    (hct1 : ct1.length = 960) (hct2 : ct2.length = 128) :
    incremental_mlkem768.decaps dk ct1 ct2
      ⦃ (result : alloc.vec.Vec Std.U8) =>
      result.val = u8ListOfBytes (MLKEM.decapsInternal Ring768 Enc768 Prims768 dkM
        (ciphertextOfU8Lists ct1.val ct2.val)) ⦄ := by
  unfold incremental_mlkem768.decaps
  step
  have hslen : s.length = 960 := by
    simpa only [Slice.length, s_post] using hct1
  step
  cases r with
  | Err e => simp_all
  | Ok a =>
    simp only at r_post
    simp only [core.result.Result.expect, bind_tc_ok]
    step
    have hs1len : s1.length = 128 := by
      simpa only [Slice.length, s1_post] using hct2
    step
    cases r1 with
    | Err e => simp_all
    | Ok a1 =>
      simp only at r1_post
      simp only [bind_tc_ok]
      step
      have hs2len : s2.len = 2400#usize := by
        apply UScalar.eq_of_val_eq
        simp [s2_post, hdk, length_u8ListOfDK, hwf.sHat_len, hwf.tHat_len]
      simp only [core.array.TryFromSharedArraySlice.try_from, hs2len, dif_pos,
        bind_tc_ok]
      obtain ⟨ss, hcall, hss⟩ :=
        hcore.decapsulate_eq_decapsInternal dkM
          ⟨s2.val, by
            rw [s2_post, hdk, length_u8ListOfDK, hwf.sHat_len, hwf.tHat_len]
            norm_num⟩
          { value := a } { value := a1 } hwf hbudget
          (by simpa only [s2_post] using hdk)
      rw [hcall]
      step*
      simp only [← result_post, s3_post, Array.val_to_slice, hss, r_post.1,
        s_post, r1_post.1, s1_post]

/-- The shipped validator decides hash match and canonicity of the received pair: byte-level
`validPK`.  Its Rust call order is `validate_pk_bytes(hdr, ek)`; no sampling guard is needed
because validation performs no matrix sampling. -/
@[step]
theorem ek_matches_header_correct_spec (codec : StateCodec) (hcore : CoreSpec codec)
    (hdrM : MLKEM.Seed32 × MLKEM.PublicKeyHash) (ek hdr : alloc.vec.Vec Std.U8)
    (hhdr : hdr.val = u8ListOfHeader hdrM) (heklen : ek.length = 1152) :
    incremental_mlkem768.ek_matches_header ek hdr
      ⦃ (result : Bool) =>
      (result = true ↔
        (MLKEM.encapsulationKeyHash Enc768 Prims768
            { tHatEncoded := tHatOfU8List ek.val, rho := hdrM.1 } = hdrM.2 ∧
          Enc768.publicKeyCanonical (tHatOfU8List ek.val) = true)) ⦄ := by
  unfold incremental_mlkem768.ek_matches_header
  simp only
  obtain ⟨vr, hcall, hr⟩ :=
    hcore.validate_pk_bytes_ok_iff hdrM hdr.deref ek.deref
      (by simpa using hhdr) (by simpa using heklen)
  rw [hcall]
  simp only [bind_tc_ok, core.result.Result.is_ok]
  cases vr with
  | Ok u =>
    cases u
    simp only [WP.spec_ok, true_iff]
    simpa using hr.mp rfl
  | Err e =>
    simp only [WP.spec_ok, Bool.false_eq_true, false_iff]
    intro hp
    have heq : core.result.Result.Err e = core.result.Result.Ok () :=
      hr.mpr (by simpa using hp)
    cases heq

end Spqr.IncrementalMlkem768
