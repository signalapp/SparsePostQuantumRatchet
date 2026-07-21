/-
Copyright 2026 The Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Alessandro D'Angelo
-/
import SrcTranslated.FunsExternal
import SecureMessaging.KEM.MLKEM.Incremental

/-! # Byte representation conversions for incremental ML-KEM-768

Conversions between `Aeneas.Std` byte types (the Aeneas extraction of the SPQR crate,
`src/incremental_mlkem768.rs`) and the secure-messaging / VCV-io ML-KEM model types at the
ML-KEM-768 parameter set, at the byte layouts of libcrux-ml-kem 0.0.7:

Extracted-side bytes are `List Std.U8` / `alloc.vec.Vec Std.U8`, Aeneas's Rust model;
model-side bytes are `ByteArray` / `MLKEM.Bytes n`, the VCV-io / secure-messaging model.
This file defines the byte-for-byte conversions and proves that conversion in either
direction recovers the original value.  The header/vector split follows the
[ML-KEM Braid specification §1.2](https://signal.org/docs/specifications/mlkembraid/).

* header (libcrux `pk1`, 64 bytes) = `ρ (32) ‖ H(ek) (32)` — the
  [FIPS 203](https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.203.pdf) order
  `H(ek) = SHA3-256(t̂enc ‖ ρ)`; see libcrux `src/ind_cca/incremental.rs:297-340` and the model's
  `MLKEM.Concrete.concretePrimitives.hEncapsulationKey`;
* compressed decapsulation key (2400 bytes) = `ŝenc (1152) ‖ t̂enc (1152) ‖ ρ (32) ‖ H(ek) (32) ‖
  z (32)` — libcrux `to_bytes_compressed`, `src/ind_cca/incremental/types.rs:417-434`;
* vector = `t̂enc` (1152 bytes), ct1 = encoded `u` (960 bytes), ct2 = encoded `v` (128 bytes).

The slice lemmas at the bottom line up with the containments proved in
`Spqr.Specs.IncrementalMlkem768.Generate` (`ek = dk[1152..2304]`, `hdr = dk[2304..2368]`).
-/

open Aeneas Aeneas.Std Result

namespace Spqr.IncrementalMlkem768

/-- The ML-KEM-768 parameter record, spelled as in `MLKEM.mlkemIncremental`. -/
abbrev P768 : MLKEM.Params := MLKEM.ParameterSet.params .MLKEM768

/-- The concrete FIPS 203 codec at ML-KEM-768 (`EncodedTHat/EncodedU/EncodedV` are `ByteArray`). -/
abbrev Enc768 : MLKEM.Encoding P768 := MLKEM.Concrete.concreteEncoding P768

/-- The concrete NTT operations. -/
abbrev Ring768 : MLKEM.NTTRingOps := MLKEM.Concrete.concreteNTTRingOps

/-- The concrete SHA-3/SHAKE primitive bundle at ML-KEM-768. -/
abbrev Prims768 : MLKEM.Primitives P768 Enc768 := MLKEM.Concrete.mlkem768Primitives

private theorem byteArray_toList_eq_data_toList (b : ByteArray) :
    b.toList = b.data.toList := by
  have loop_eq :
      ∀ (i : Nat) (r : List UInt8), i ≤ b.size →
        ByteArray.toList.loop b i r = r.reverse ++ b.data.toList.drop i := by
    intro i r hi
    fun_induction ByteArray.toList.loop b i r with
    | case1 i r h ih =>
      rw [ih (by omega)]
      have hdata : i < b.data.toList.length := by
        simpa [← ByteArray.size_data] using h
      rw [List.drop_eq_getElem_cons hdata]
      simp only [List.reverse_cons, List.singleton_append, List.append_assoc]
      congr 2
      change b.data[i]! = b.data.toList[i]
      rw [← Array.getElem!_toList]
      exact (List.Inhabited_getElem_eq_getElem! _ _ hdata).symm
    | case2 i r h =>
      have hi_eq : i = b.size := by omega
      subst i
      simp [← ByteArray.size_data]
  unfold ByteArray.toList
  rw [loop_eq 0 [] (Nat.zero_le _)]
  simp

/-- One extracted byte as one model byte (both are 8-bit words over `BitVec 8`). -/
def byteOfU8 (b : Std.U8) : UInt8 := UInt8.ofBitVec b.bv

/-- One model byte as one extracted byte. -/
def u8OfByte (b : UInt8) : Std.U8 := ⟨b.toBitVec⟩

@[simp] theorem byteOfU8_u8OfByte (b : UInt8) : byteOfU8 (u8OfByte b) = b := by
  cases b
  rfl

@[simp] theorem u8OfByte_byteOfU8 (b : Std.U8) : u8OfByte (byteOfU8 b) = b := by
  cases b
  rfl

/-- Extracted byte list → model `ByteArray` (the concrete encoding's carrier). -/
def byteArrayOfU8List (l : List Std.U8) : ByteArray := ⟨⟨l.map byteOfU8⟩⟩

/-- Model `ByteArray` → extracted byte list. -/
def u8ListOfByteArray (b : ByteArray) : List Std.U8 := b.toList.map u8OfByte

@[simp] theorem size_byteArrayOfU8List (l : List Std.U8) :
    (byteArrayOfU8List l).size = l.length := by
  rw [← ByteArray.size_data]
  simp [byteArrayOfU8List]

@[simp] theorem length_u8ListOfByteArray (b : ByteArray) :
    (u8ListOfByteArray b).length = b.size := by
  simp [u8ListOfByteArray, ByteArray.length_toList]

@[simp] theorem u8ListOfByteArray_byteArrayOfU8List (l : List Std.U8) :
    u8ListOfByteArray (byteArrayOfU8List l) = l := by
  simp [u8ListOfByteArray, byteArrayOfU8List, byteArray_toList_eq_data_toList,
    List.map_map, Function.comp_def]

@[simp] theorem byteArrayOfU8List_u8ListOfByteArray (b : ByteArray) :
    byteArrayOfU8List (u8ListOfByteArray b) = b := by
  cases b with
  | mk data =>
    cases data
    simp [u8ListOfByteArray, byteArrayOfU8List, byteArray_toList_eq_data_toList,
      List.map_map, Function.comp_def]

theorem u8ListOfByteArray_injective : Function.Injective u8ListOfByteArray := by
  intro a b h
  simpa using congrArg byteArrayOfU8List h

theorem byteArrayOfU8List_injective : Function.Injective byteArrayOfU8List := by
  intro a b h
  simpa using congrArg u8ListOfByteArray h

/-- Extracted byte list of known length `n` → model `MLKEM.Bytes n`. -/
def bytesOfU8List (n : ℕ) (l : List Std.U8) (h : l.length = n) : MLKEM.Bytes n :=
  ⟨⟨l.map byteOfU8⟩, by simp [h]⟩

/-- Model `MLKEM.Bytes n` → extracted byte list. -/
def u8ListOfBytes {n : ℕ} (v : MLKEM.Bytes n) : List Std.U8 := v.toList.map u8OfByte

@[simp] theorem length_u8ListOfBytes {n : ℕ} (v : MLKEM.Bytes n) :
    (u8ListOfBytes v).length = n := by
  simp [u8ListOfBytes]

@[simp] theorem u8ListOfBytes_bytesOfU8List (n : ℕ) (l : List Std.U8) (h : l.length = n) :
    u8ListOfBytes (bytesOfU8List n l h) = l := by
  simp [u8ListOfBytes, bytesOfU8List, List.map_map, Function.comp_def]

@[simp] theorem bytesOfU8List_u8ListOfBytes {n : ℕ} (v : MLKEM.Bytes n)
    (h : (u8ListOfBytes v).length = n) : bytesOfU8List n (u8ListOfBytes v) h = v := by
  apply Vector.ext
  intro i
  simp [u8ListOfBytes, bytesOfU8List]

theorem u8ListOfBytes_injective {n : ℕ} :
    Function.Injective (u8ListOfBytes (n := n)) := by
  intro v w h
  rw [← bytesOfU8List_u8ListOfBytes v (length_u8ListOfBytes v),
    ← bytesOfU8List_u8ListOfBytes w (length_u8ListOfBytes w)]
  congr

/-- Serialized `t̂` (the braid vector / libcrux `pk2`) as extracted bytes. -/
def u8ListOfTHat (t : Enc768.EncodedTHat) : List Std.U8 := u8ListOfByteArray t

/-- Extracted bytes as a serialized `t̂`. -/
def tHatOfU8List (l : List Std.U8) : Enc768.EncodedTHat := byteArrayOfU8List l

/-- Encoded `u` (ct1 payload) as extracted bytes. -/
def u8ListOfEncodedU (u : Enc768.EncodedU) : List Std.U8 := u8ListOfByteArray u

/-- Encoded `v` (ct2 payload) as extracted bytes. -/
def u8ListOfEncodedV (v : Enc768.EncodedV) : List Std.U8 := u8ListOfByteArray v

@[simp] theorem u8ListOfTHat_tHatOfU8List (l : List Std.U8) :
    u8ListOfTHat (tHatOfU8List l) = l := by
  simp [u8ListOfTHat, tHatOfU8List]

@[simp] theorem tHatOfU8List_u8ListOfTHat (t : Enc768.EncodedTHat) :
    tHatOfU8List (u8ListOfTHat t) = t := by
  simp [u8ListOfTHat, tHatOfU8List]

/-- Model ciphertext from the two extracted ciphertext-component byte lists. -/
def ciphertextOfU8Lists (c1 c2 : List Std.U8) : MLKEM.Ciphertext P768 Enc768 :=
  { uEncoded := byteArrayOfU8List c1, vEncoded := byteArrayOfU8List c2 }

/-- The 64-byte libcrux `pk1` header of a model header pair: `ρ (32) ‖ H(ek) (32)`. -/
def u8ListOfHeader (hdr : MLKEM.Seed32 × MLKEM.PublicKeyHash) : List Std.U8 :=
  u8ListOfBytes hdr.1 ++ u8ListOfBytes hdr.2

/-- Read a model header pair off a 64-byte header: seed from `[0..32)`, hash from `[32..64)`. -/
def headerOfU8List (l : List Std.U8) (h : l.length = 64) :
    MLKEM.Seed32 × MLKEM.PublicKeyHash :=
  (bytesOfU8List 32 (l.take 32) (by simp [h]), bytesOfU8List 32 (l.drop 32) (by simp [h]))

@[simp] theorem length_u8ListOfHeader (hdr : MLKEM.Seed32 × MLKEM.PublicKeyHash) :
    (u8ListOfHeader hdr).length = 64 := by
  simp [u8ListOfHeader]

theorem take_u8ListOfHeader (hdr : MLKEM.Seed32 × MLKEM.PublicKeyHash) :
    (u8ListOfHeader hdr).take 32 = u8ListOfBytes hdr.1 := by
  simp [u8ListOfHeader]

theorem drop_u8ListOfHeader (hdr : MLKEM.Seed32 × MLKEM.PublicKeyHash) :
    (u8ListOfHeader hdr).drop 32 = u8ListOfBytes hdr.2 := by
  simp [u8ListOfHeader]

@[simp] theorem headerOfU8List_u8ListOfHeader (hdr : MLKEM.Seed32 × MLKEM.PublicKeyHash)
    (h : (u8ListOfHeader hdr).length = 64) : headerOfU8List (u8ListOfHeader hdr) h = hdr := by
  cases hdr
  simp [headerOfU8List, u8ListOfHeader]

theorem u8ListOfHeader_headerOfU8List (l : List Std.U8) (h : l.length = 64) :
    u8ListOfHeader (headerOfU8List l h) = l := by
  simp [headerOfU8List, u8ListOfHeader]

theorem u8ListOfHeader_injective : Function.Injective u8ListOfHeader := by
  intro a b h
  rw [← headerOfU8List_u8ListOfHeader a (length_u8ListOfHeader a),
    ← headerOfU8List_u8ListOfHeader b (length_u8ListOfHeader b)]
  congr

theorem take_append_u8ListOfBytes (d z : MLKEM.Bytes 32) :
    (u8ListOfBytes d ++ u8ListOfBytes z).take 32 = u8ListOfBytes d := by
  simp

theorem drop_append_u8ListOfBytes (d z : MLKEM.Bytes 32) :
    (u8ListOfBytes d ++ u8ListOfBytes z).drop 32 = u8ListOfBytes z := by
  simp

/-- Serialize a model ML-KEM-768 decapsulation key in libcrux's compressed 2400-byte layout
`ŝenc ‖ t̂enc ‖ ρ ‖ H(ek) ‖ z` (libcrux `to_bytes_compressed`,
`src/ind_cca/incremental/types.rs:417-434`). -/
def u8ListOfDK (dk : MLKEM.DecapsulationKey P768 Enc768) : List Std.U8 :=
  u8ListOfTHat dk.dkPKE.sHatEncoded ++ u8ListOfTHat dk.ekPKE.tHatEncoded ++
    u8ListOfBytes dk.ekPKE.rho ++ u8ListOfBytes dk.ekHash ++ u8ListOfBytes dk.z

theorem length_u8ListOfDK (dk : MLKEM.DecapsulationKey P768 Enc768) :
    (u8ListOfDK dk).length =
      (u8ListOfTHat dk.dkPKE.sHatEncoded).length +
        (u8ListOfTHat dk.ekPKE.tHatEncoded).length + 96 := by
  simp [u8ListOfDK]
  omega

/-- The vector sub-range of the serialized key: bytes `[1152..2304)` are `t̂enc` —
matches `ek = dk[1152..2304]` proved in `generate_spec`. -/
theorem slice_u8ListOfDK_ek (dk : MLKEM.DecapsulationKey P768 Enc768)
    (hs : (u8ListOfTHat dk.dkPKE.sHatEncoded).length = 1152)
    (ht : (u8ListOfTHat dk.ekPKE.tHatEncoded).length = 1152) :
    (u8ListOfDK dk).slice 1152 2304 = u8ListOfTHat dk.ekPKE.tHatEncoded := by
  simp [u8ListOfDK, List.slice, hs, ht]

/-- The header sub-range of the serialized key: bytes `[2304..2368)` are `ρ ‖ H(ek)` —
matches `hdr = dk[2304..2368]` proved in `generate_spec`. -/
theorem slice_u8ListOfDK_hdr (dk : MLKEM.DecapsulationKey P768 Enc768)
    (hs : (u8ListOfTHat dk.dkPKE.sHatEncoded).length = 1152)
    (ht : (u8ListOfTHat dk.ekPKE.tHatEncoded).length = 1152) :
    (u8ListOfDK dk).slice 2304 2368 = u8ListOfHeader (dk.ekPKE.rho, dk.ekHash) := by
  simp [u8ListOfDK, u8ListOfHeader, List.slice, List.drop_append, List.take_append, hs, ht]

/-- Well-formedness of a model decapsulation key for libcrux's fixed-offset 2400-byte
serialization: both encoded-vector components carry exactly `k · 384 = 1152` bytes, so the
five segments of `u8ListOfDK` land on libcrux's fixed parse boundaries (the model's
`EncodedTHat` carrier is an unconstrained `ByteArray`, so total length 2400 alone does not
force the split).  Keygen images satisfy it: `wellFormedDK_keygenInternal`. -/
structure WellFormedDK (dk : MLKEM.DecapsulationKey P768 Enc768) : Prop where
  sHat_len : (u8ListOfTHat dk.dkPKE.sHatEncoded).length = 1152
  tHat_len : (u8ListOfTHat dk.ekPKE.tHatEncoded).length = 1152

/-- The concrete 12-bit vector encoder always produces `k · 384` bytes. -/
theorem size_byteEncode12Vec {k : ℕ} (v : MLKEM.TqVec k) :
    (MLKEM.Concrete.byteEncode12Vec v).size = k * 384 := by
  rw [← ByteArray.size_data]
  simp [MLKEM.Concrete.byteEncode12Vec]
  omega

/-- The concrete `d`-bit vector encoder always produces `32 · d · k` bytes. -/
theorem size_byteEncodeVec (d : ℕ) {k : ℕ} (v : MLKEM.RqVec k) :
    (MLKEM.Concrete.byteEncodeVec d v).size = 32 * d * k := by
  rw [← ByteArray.size_data]
  simp [MLKEM.Concrete.byteEncodeVec]

/-- Witness: `CoreSpec.from_seed_eq_keygenInternal` is length-consistent — model keygen
serializes to exactly 2400 bytes, the length forced by `KeyPairCompressedBytes.value`. -/
theorem length_u8ListOfDK_keygenInternal (d z : MLKEM.Seed32) :
    (u8ListOfDK (MLKEM.keygenInternal Ring768 Enc768 Prims768 d z).2).length = 2400 := by
  simp only [u8ListOfDK, List.length_append, u8ListOfTHat, length_u8ListOfByteArray,
    length_u8ListOfBytes, MLKEM.keygenInternal, MLKEM.KPKE.keygenFromSeed,
    MLKEM.Concrete.concreteEncoding, size_byteEncode12Vec]
  norm_num [P768, MLKEM.ParameterSet.params]

/-- Witness: keygen images are `WellFormedDK` — both encoded vectors are
`byteEncode12Vec` outputs of size `3 · 384 = 1152` (route: unfold `keygenInternal` to its
`byteEncode12Vec` components, then `size_byteEncode12Vec` at `k = 3` and
`length_u8ListOfTHat`). -/
theorem wellFormedDK_keygenInternal (d z : MLKEM.Seed32) :
    WellFormedDK (MLKEM.keygenInternal Ring768 Enc768 Prims768 d z).2 := by
  constructor <;>
    simp only [u8ListOfTHat, length_u8ListOfByteArray, MLKEM.keygenInternal,
      MLKEM.KPKE.keygenFromSeed, MLKEM.Concrete.concreteEncoding, size_byteEncode12Vec]
  all_goals norm_num [P768, MLKEM.ParameterSet.params]

/-- Witness: `CoreSpec.encapsulate1_eq_incrementalEncaps1` is length-consistent — the model's
encoded `u` is exactly 960 bytes, the length forced by `Ciphertext1 960`. -/
theorem length_u8ListOfEncodedU_incrementalEncaps1
    (hdr : MLKEM.Seed32 × MLKEM.PublicKeyHash) (m : MLKEM.Message) :
    (u8ListOfEncodedU (MLKEM.incrementalEncaps1 Ring768 Prims768 hdr m).2.1).length = 960 := by
  simp [u8ListOfEncodedU, MLKEM.incrementalEncaps1, MLKEM.Concrete.concreteEncoding,
    size_byteEncodeVec]
  norm_num [P768, MLKEM.ParameterSet.params]

end Spqr.IncrementalMlkem768
