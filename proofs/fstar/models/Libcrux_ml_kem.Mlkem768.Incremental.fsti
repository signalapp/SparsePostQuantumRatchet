module Libcrux_ml_kem.Mlkem768.Incremental
#set-options "--fuel 0 --ifuel 1 --z3rlimit 80"
open Core
open FStar.Mul

let _ =
  (* This module has implicit dependencies, here we make them explicit. *)
  (* The implicit dependencies arise from typeclasses instances. *)
  let open Libcrux_ml_kem.Ind_cca.Incremental.Types in
  let open Rand_core in
  ()

/// Get the size of the first public key in bytes.
val pk1_len: Prims.unit -> Prims.Pure usize Prims.l_True 
  (ensures fun res -> let res:usize = res in res =. mk_usize 64)

/// Get the size of the second public key in bytes.
val pk2_len: Prims.unit -> Prims.Pure usize Prims.l_True (fun _ -> Prims.l_True)

/// The size of a compressed key pair in bytes.
let v_COMPRESSED_KEYPAIR_LEN: usize = Libcrux_ml_kem.Mlkem768.v_SECRET_KEY_SIZE

/// The size of the key pair in bytes.
val key_pair_len: Prims.unit -> Prims.Pure usize Prims.l_True (fun _ -> Prims.l_True)

/// The size of the compressed key pair in bytes.
val key_pair_compressed_len: Prims.unit -> Prims.Pure usize Prims.l_True (fun _ -> Prims.l_True)

/// The size of the encaps state in bytes.
val encaps_state_len: Prims.unit -> Prims.Pure usize Prims.l_True (fun _ -> Prims.l_True)

/// The size of the shared secret.
val shared_secret_size: Prims.unit -> Prims.Pure usize Prims.l_True (fun _ -> Prims.l_True)

/// An encoded, incremental key pair.
type t_KeyPairBytes = { f_value:t_Array u8 (mk_usize 7392) }

/// Get the raw bytes.
val impl_KeyPairBytes__to_bytes (self: t_KeyPairBytes)
    : Prims.Pure (t_Array u8 (mk_usize 7392)) Prims.l_True (fun _ -> Prims.l_True)

/// Get the PK1 bytes from the serialized key pair bytes
val impl_KeyPairBytes__pk1 (self: t_KeyPairBytes)
    : Prims.Pure (t_Array u8 (mk_usize 64)) Prims.l_True (fun _ -> Prims.l_True)

/// Get the PK2 bytes from the serialized key pair bytes
val impl_KeyPairBytes__pk2 (self: t_KeyPairBytes)
    : Prims.Pure (t_Array u8 (mk_usize 1152)) Prims.l_True (fun _ -> Prims.l_True)

[@@ FStar.Tactics.Typeclasses.tcinstance]
val impl_1:Core.Convert.t_AsRef t_KeyPairBytes (t_Slice u8)

/// Generate a key pair and write it into `key_pair`.
/// This uses unpacked keys and does not compress the keys.
/// `key_pair.len()` must be of size `key_pair_len()`.
/// The function returns an error if this is not the case.
val generate_key_pair (randomness: t_Array u8 (mk_usize 64)) (key_pair: t_Slice u8)
    : Prims.Pure
      (t_Slice u8 & Core.Result.t_Result Prims.unit Libcrux_ml_kem.Ind_cca.Incremental.Types.t_Error
      ) Prims.l_True (fun _ -> Prims.l_True)

/// Generate a new key pair.
/// This uses unpacked keys and does not compress the keys.
val impl_KeyPairBytes__from_seed (randomness: t_Array u8 (mk_usize 64))
    : Prims.Pure t_KeyPairBytes Prims.l_True (fun _ -> Prims.l_True)

/// Generate a new key pair.
/// This uses unpacked keys and does not compress the keys.
val impl_KeyPairBytes__generate
      (#iimpl_277843321_: Type0)
      {| i1: Rand_core.t_RngCore iimpl_277843321_ |}
      {| i2: Rand_core.t_CryptoRng iimpl_277843321_ |}
      (rng: iimpl_277843321_)
    : Prims.Pure (iimpl_277843321_ & t_KeyPairBytes) Prims.l_True (fun _ -> Prims.l_True)

/// An encoded, compressed, incremental key pair.
/// Layout: dk | (t | ⍴) | H(ek) | z
type t_KeyPairCompressedBytes = { f_value:t_Array u8 (mk_usize 2400) }

/// Get the raw bytes.
val impl_KeyPairCompressedBytes__to_bytes (self: t_KeyPairCompressedBytes)
    : Prims.Pure (t_Array u8 (mk_usize 2400)) Prims.l_True (fun _ -> Prims.l_True)

/// Get the serialized private for decapsulation.
val impl_KeyPairCompressedBytes__sk (self: t_KeyPairCompressedBytes)
    : Prims.Pure (t_Array u8 (mk_usize 2400)) Prims.l_True (fun _ -> Prims.l_True)

let impl_KeyPairCompressedBytes__pk1__v_START: usize =
  mk_usize 2 *! Libcrux_ml_kem.Mlkem768.v_RANKED_BYTES_PER_RING_ELEMENT

/// Get the PK1 bytes from the serialized key pair bytes
val impl_KeyPairCompressedBytes__pk1 (self: t_KeyPairCompressedBytes)
    : Prims.Pure (t_Array u8 (mk_usize 64)) Prims.l_True (fun _ -> Prims.l_True)

let impl_KeyPairCompressedBytes__pk2__v_START: usize =
  Libcrux_ml_kem.Mlkem768.v_RANKED_BYTES_PER_RING_ELEMENT

/// Get the PK2 bytes from the serialized key pair bytes
val impl_KeyPairCompressedBytes__pk2 (self: t_KeyPairCompressedBytes)
    : Prims.Pure (t_Array u8 (mk_usize 1152)) Prims.l_True (fun _ -> Prims.l_True)

[@@ FStar.Tactics.Typeclasses.tcinstance]
val impl_3:Core.Convert.t_AsRef t_KeyPairCompressedBytes (t_Slice u8)

/// Generate a key pair and write it into `key_pair`.
/// This compresses the keys.
val generate_key_pair_compressed
      (randomness: t_Array u8 (mk_usize 64))
      (key_pair: t_Array u8 (mk_usize 2400))
    : Prims.Pure (t_Array u8 (mk_usize 2400)) Prims.l_True (fun _ -> Prims.l_True)

/// Generate a new key pair.
/// This uses unpacked keys and does not compress the keys.
val impl_KeyPairCompressedBytes__from_seed (randomness: t_Array u8 (mk_usize 64))
    : Prims.Pure t_KeyPairCompressedBytes Prims.l_True (fun _ -> Prims.l_True)

/// Generate a new key pair.
/// This uses unpacked keys and does not compress the keys.
val impl_KeyPairCompressedBytes__generate
      (#iimpl_277843321_: Type0)
      {| i1: Rand_core.t_RngCore iimpl_277843321_ |}
      {| i2: Rand_core.t_CryptoRng iimpl_277843321_ |}
      (rng: iimpl_277843321_)
    : Prims.Pure (iimpl_277843321_ & t_KeyPairCompressedBytes) Prims.l_True (fun _ -> Prims.l_True)

/// Get the PK1 bytes from the serialized key pair bytes
val pk1 (keypair: t_Array u8 (mk_usize 7392))
    : Prims.Pure (t_Slice u8) Prims.l_True (fun _ -> Prims.l_True)

/// Get the PK2 bytes from the serialized key pair bytes
val pk2 (keypair: t_Array u8 (mk_usize 7392))
    : Prims.Pure (t_Slice u8) Prims.l_True (fun _ -> Prims.l_True)

/// Validate that the two parts `pk1` and `pk2` are consistent.
val validate_pk (pk1: Libcrux_ml_kem.Ind_cca.Incremental.Types.t_PublicKey1) (pk2: t_Slice u8)
    : Prims.Pure (Core.Result.t_Result Prims.unit Libcrux_ml_kem.Ind_cca.Incremental.Types.t_Error)
      Prims.l_True
      (fun _ -> Prims.l_True)

/// Validate that the two parts `pk1` and `pk2` are consistent.
val validate_pk_bytes (pk1 pk2: t_Slice u8)
    : Prims.Pure (Core.Result.t_Result Prims.unit Libcrux_ml_kem.Ind_cca.Incremental.Types.t_Error)
      Prims.l_True
      (fun _ -> Prims.l_True)

/// Encapsulate the first part of the ciphertext.
/// Returns an [`Error`] if the provided input or output don't have
/// the appropriate sizes.
val encapsulate1
      (pk1: t_Slice u8)
      (randomness: t_Array u8 (mk_usize 32))
      (state shared_secret: t_Slice u8)
    : Prims.Pure
      (t_Slice u8 & t_Slice u8 &
        Core.Result.t_Result (Libcrux_ml_kem.Ind_cca.Incremental.Types.t_Ciphertext1 (mk_usize 960))
          Libcrux_ml_kem.Ind_cca.Incremental.Types.t_Error) Prims.l_True (fun _ -> Prims.l_True)

/// Encapsulate the second part of the ciphertext.
/// The second part of the public key is passed in as byte slice.
/// [`Error::InvalidInputLength`] is returned if `public_key_part` is too
/// short.
val encapsulate2 (state: t_Array u8 (mk_usize 2080)) (public_key_part: t_Array u8 (mk_usize 1152))
    : Prims.Pure (Libcrux_ml_kem.Ind_cca.Incremental.Types.t_Ciphertext2 (mk_usize 128))
      Prims.l_True
      (fun _ -> Prims.l_True)

/// Decapsulate incremental ciphertexts.
val decapsulate_incremental_key
      (private_key: t_Slice u8)
      (ciphertext1: Libcrux_ml_kem.Ind_cca.Incremental.Types.t_Ciphertext1 (mk_usize 960))
      (ciphertext2: Libcrux_ml_kem.Ind_cca.Incremental.Types.t_Ciphertext2 (mk_usize 128))
    : Prims.Pure
      (Core.Result.t_Result (t_Array u8 (mk_usize 32))
          Libcrux_ml_kem.Ind_cca.Incremental.Types.t_Error) Prims.l_True (fun _ -> Prims.l_True)

/// Decapsulate incremental ciphertexts.
val decapsulate_compressed_key
      (private_key: t_Array u8 (mk_usize 2400))
      (ciphertext1: Libcrux_ml_kem.Ind_cca.Incremental.Types.t_Ciphertext1 (mk_usize 960))
      (ciphertext2: Libcrux_ml_kem.Ind_cca.Incremental.Types.t_Ciphertext2 (mk_usize 128))
    : Prims.Pure (t_Array u8 (mk_usize 32)) Prims.l_True (fun _ -> Prims.l_True)
