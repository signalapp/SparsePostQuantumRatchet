/-
Copyright 2026 The Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Alessandro D'Angelo
-/
import Spqr.Specs.IncrementalMlkem768.Marshalling
import SpqrToVCVio.LatticeCrypto.MLKEM.Concrete.SampleNTTBudget

/-! # The assumed contract on the opaque libcrux incremental ML-KEM-768 core

The libcrux mathematical core is opaque to this extraction: Aeneas emitted names and types,
but no Lean bodies, for `from_seed`, `encapsulate1`, `encapsulate2`,
`decapsulate_compressed_key`, `validate_pk_bytes`, and the six length constants.
`CoreSpec` is a `Prop`-valued hypothesis collecting the equations that a
future implementation proof must establish: those external functions compute the
[FIPS 203](https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.203.pdf) / ML-KEM model functions
of `SecureMessaging.KEM.MLKEM.Incremental` after the explicit byte conversions in
`Spqr.Specs.IncrementalMlkem768.Marshalling`.

The encapsulation-state byte layout is deliberately abstracted as `StateCodec`
(intended instantiation: libcrux's `r̂ ‖ e₂ ‖ m` i16-little-endian serialization,
`src/ind_cca/incremental/types.rs:180-239`); every consumer quantifies over the codec.

`decapsulate_eq_decapsInternal` quantifies over ALL ciphertext pairs of the right lengths —
not only honest ones — so a core that skipped the FO re-encryption check could not satisfy it.
`fixer_ok_none_of_encoded` concerns SPQR's own (visible, `#[hax_lib::opaque]`) issue-1275
workaround, `src/incremental_mlkem768.rs:92-138`: on well-formed encodings every match arm
returns `None`, so the wrapper passes the original state through.  Its raison d'être is
LEGACY persisted states predating libcrux PR#1276; those are outside this correctness
experiment, which exercises freshly generated states only.  Normalizing legacy persisted
states would be separate future work.

The three matrix-sampling fields are premise-guarded by
`MLKEM.Concrete.matrixSampleWithinBudget` (staged for upstream VCV-io in `SpqrToVCVio/`):
the model's
`concreteSampleNTT` is 840-byte-budgeted while shipped implementations stream past the
budget, and the two agree exactly on the guard.  The decapsulation field additionally
requires `WellFormedDK` so a variable-width model key cannot misalign libcrux's fixed
parse boundaries. -/

open Aeneas Aeneas.Std Result
open spqr

namespace Spqr.IncrementalMlkem768

/-- Byte codec for the libcrux encapsulation-state buffer (`encaps_state_len = 2080`).  The
model state is `(m, r)`; the buffer stores values derived from it, so the codec is carried as
data and everything downstream quantifies over it. -/
structure StateCodec where
  /-- Serialize a model state `(m, r)` to the 2080-byte buffer contents. -/
  encodeState : MLKEM.Message × MLKEM.Coins → List Std.U8
  /-- The buffer is always exactly `encaps_state_len = 2080` bytes. -/
  length_encodeState : ∀ st, (encodeState st).length = 2080

/-- The assumed contract on the opaque libcrux incremental core (and the SPQR state fixer),
relative to a state codec.  See the module docstring for the trust story. -/
structure CoreSpec (codec : StateCodec) : Prop where
  /-- The shipped API's shared-secret-size constant is the 32-byte ML-KEM secret length used
  to size the wrapper's output buffer. -/
  shared_secret_size :
    libcrux_ml_kem.constants.SHARED_SECRET_SIZE = ok 32#usize
  /-- The shipped API's first-ciphertext length is 960 bytes, the encoded `u` buffer size the
  wrapper reads. -/
  ciphertext1_len :
    libcrux_ml_kem.ind_cca.incremental.types.Ciphertext1.len 960#usize = ok 960#usize
  /-- The shipped API's second-ciphertext length is 128 bytes, the encoded `v` buffer size the
  wrapper reads. -/
  ciphertext2_len :
    libcrux_ml_kem.ind_cca.incremental.types.Ciphertext2.len 128#usize = ok 128#usize
  /-- The shipped API's 64-byte header length covers `ρ ‖ H(ek)` and sizes the wrapper slice. -/
  pk1_len :
    libcrux_ml_kem.mlkem768.incremental.pk1_len = ok 64#usize
  /-- The shipped API's 1152-byte public-key vector length covers encoded `t̂` and sizes the
  wrapper slice. -/
  pk2_len :
    libcrux_ml_kem.mlkem768.incremental.pk2_len = ok 1152#usize
  /-- The shipped API's 2080-byte encapsulation-state length sizes the wrapper's state buffer. -/
  encaps_state_len :
    libcrux_ml_kem.mlkem768.incremental.encaps_state_len = ok 2080#usize
  /-- On a 64-byte seed `d ‖ z`, shipped key generation returns the exact byte encoding of
  `keygenInternal` (FIPS 203 Algorithm 16), guarded by the sampling budget at `ρ = (G(d)).1`. -/
  from_seed_eq_keygenInternal :
    ∀ (d z : MLKEM.Seed32) (seed : Array Std.U8 64#usize),
      seed.val = u8ListOfBytes d ++ u8ListOfBytes z →
      MLKEM.Concrete.matrixSampleWithinBudget 3 (Prims768.gKeygen d).1 →
      ∃ kp,
        libcrux_ml_kem.mlkem768.incremental.KeyPairCompressedBytes.from_seed seed = ok kp ∧
        kp.value.val = u8ListOfDK (MLKEM.keygenInternal Ring768 Enc768 Prims768 d z).2
  /-- The header-only stage returns the exact byte encodings of `incrementalEncaps1`'s state,
  ct1, and shared secret, guarded by the sampling budget at the header's seed. -/
  encapsulate1_eq_incrementalEncaps1 :
    ∀ (hdrM : MLKEM.Seed32 × MLKEM.PublicKeyHash) (m : MLKEM.Message)
      (hdr : Slice Std.U8) (rnd : Array Std.U8 32#usize) (stIn ssIn : Slice Std.U8),
      hdr.val = u8ListOfHeader hdrM →
      MLKEM.Concrete.matrixSampleWithinBudget 3 hdrM.1 →
      rnd.val = u8ListOfBytes m →
      stIn.length = 2080 → ssIn.length = 32 →
      ∃ ct1 stOut ssOut,
        libcrux_ml_kem.mlkem768.incremental.encapsulate1 hdr rnd stIn ssIn =
          ok (core.result.Result.Ok ct1, stOut, ssOut) ∧
        ct1.value.val =
          u8ListOfEncodedU (MLKEM.incrementalEncaps1 Ring768 Prims768 hdrM m).2.1 ∧
        stOut.val = codec.encodeState (MLKEM.incrementalEncaps1 Ring768 Prims768 hdrM m).1 ∧
        ssOut.val = u8ListOfBytes (MLKEM.incrementalEncaps1 Ring768 Prims768 hdrM m).2.2
  /-- The vector stage returns the exact byte encoding of `incrementalEncaps2` for every state
  represented by the codec. -/
  encapsulate2_eq_incrementalEncaps2 :
    ∀ (st : MLKEM.Message × MLKEM.Coins) (es : Array Std.U8 2080#usize)
      (vec : Array Std.U8 1152#usize),
      es.val = codec.encodeState st →
      ∃ ct2,
        libcrux_ml_kem.mlkem768.incremental.encapsulate2 es vec = ok ct2 ∧
        ct2.value.val =
          u8ListOfEncodedV
            (MLKEM.incrementalEncaps2 Ring768 Prims768 st (tHatOfU8List vec.val))
  /-- On every well-sized ciphertext pair, not merely honest ones, shipped decapsulation
  computes `decapsInternal`, including FIPS 203 Algorithm 18's FO re-encryption check.  It
  requires `WellFormedDK` and the matrix-sampling guard. -/
  decapsulate_eq_decapsInternal :
    ∀ (dkM : MLKEM.DecapsulationKey P768 Enc768) (dk : Array Std.U8 2400#usize)
      (ct1 : libcrux_ml_kem.ind_cca.incremental.types.Ciphertext1 960#usize)
      (ct2 : libcrux_ml_kem.ind_cca.incremental.types.Ciphertext2 128#usize),
      WellFormedDK dkM →
      MLKEM.Concrete.matrixSampleWithinBudget 3 dkM.ekPKE.rho →
      dk.val = u8ListOfDK dkM →
      ∃ ss,
        libcrux_ml_kem.mlkem768.incremental.decapsulate_compressed_key dk ct1 ct2 = ok ss ∧
        ss.val = u8ListOfBytes (MLKEM.decapsInternal Ring768 Enc768 Prims768 dkM
          (ciphertextOfU8Lists ct1.value.val ct2.value.val))
  /-- The shipped validator accepts exactly when the header hash matches and the 12-bit
  public-key encoding is canonical. -/
  validate_pk_bytes_ok_iff :
    ∀ (hdrM : MLKEM.Seed32 × MLKEM.PublicKeyHash) (hdr vec : Slice Std.U8),
      hdr.val = u8ListOfHeader hdrM →
      vec.length = 1152 →
      ∃ r,
        libcrux_ml_kem.mlkem768.incremental.validate_pk_bytes hdr vec = ok r ∧
        (r = core.result.Result.Ok () ↔
          (MLKEM.encapsulationKeyHash Enc768 Prims768
              { tHatEncoded := tHatOfU8List vec.val, rho := hdrM.1 } = hdrM.2 ∧
            Enc768.publicKeyCanonical (tHatOfU8List vec.val) = true))
  /-- The shipped validator rejects every header/vector pair with a bad length. -/
  validate_pk_bytes_err_of_bad_length :
    ∀ (hdr vec : Slice Std.U8),
      hdr.length ≠ 64 ∨ vec.length ≠ 1152 →
      ∃ e, libcrux_ml_kem.mlkem768.incremental.validate_pk_bytes hdr vec =
        ok (core.result.Result.Err e)
  /-- On every exact codec image, the issue-1275 workaround returns `ok none`, leaving the
  state unchanged; this follows by inspection of `src/incremental_mlkem768.rs:92–138`. -/
  fixer_ok_none_of_encoded :
    ∀ (st : MLKEM.Message × MLKEM.Coins) (es : alloc.vec.Vec Std.U8),
      es.val = codec.encodeState st →
      _root_.incremental_mlkem768.potentially_fix_state_incorrectly_encoded_by_libcrux_issue_1275
        es = ok none

end Spqr.IncrementalMlkem768
