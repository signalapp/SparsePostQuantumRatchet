module Libcrux_ml_kem.Mlkem768.Incremental
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open Core_models
open FStar.Mul

/// Model of `libcrux_ml_kem::mlkem768::incremental` (libcrux-ml-kem 0.0.10).
/// <https://docs.rs/libcrux-ml-kem/0.0.10/libcrux_ml_kem/mlkem768/incremental/>
///
/// This is the whole ML-KEM surface `src/incremental_mlkem768.rs` uses. The
/// postconditions below are size and success facts taken from the crate's own
/// documentation and const-generic declarations; nothing here states that
/// encapsulation and decapsulation agree, or anything else about the *values*
/// produced. ML-KEM's correctness and IND-CCA security are verified in libcrux
/// and trusted here -- but note that they are trusted *without being written
/// down*, so no SPQR proof depends on them.

/// `pk1_len()`
/// <https://docs.rs/libcrux-ml-kem/0.0.10/libcrux_ml_kem/mlkem768/incremental/fn.pk1_len.html>
///
/// The first public-key part of ML-KEM-768 is the 32-byte seed plus a 32-byte
/// hash. `src/incremental_mlkem768.rs` defines `HEADER_SIZE` from this and its
/// `generate` postcondition asserts the header has that length, so the exact
/// value has to be visible.
val pk1_len: Prims.unit -> Prims.Pure usize Prims.l_True
  (ensures fun res -> res =. mk_usize 64)

/// `pk2_len()`
/// <https://docs.rs/libcrux-ml-kem/0.0.10/libcrux_ml_kem/mlkem768/incremental/fn.pk2_len.html>
///
/// The second public-key part is the serialised rank-3 ring element:
/// 3 * 384 = 1152 bytes. Feeds `ENCAPSULATION_KEY_SIZE`.
val pk2_len: Prims.unit -> Prims.Pure usize Prims.l_True
  (ensures fun res -> res =. mk_usize 1152)

/// `encaps_state_len()`
/// <https://docs.rs/libcrux-ml-kem/0.0.10/libcrux_ml_kem/mlkem768/incremental/fn.encaps_state_len.html>
///
/// The size of the state `encapsulate1` writes and `encapsulate2` consumes.
/// `encaps1` allocates `vec![0u8; encaps_state_len()]` and its postcondition
/// claims the result is 2080 bytes, and `encapsulate2` below takes a
/// `[u8; 2080]`, so the two only line up if this value is exposed. 2080 is
/// `EncapsState::num_bytes()`: `r_as_ntt` (1536 bytes), `error2` (512) and the
/// randomness (32).
val encaps_state_len: Prims.unit -> Prims.Pure usize Prims.l_True
  (ensures fun res -> res =. mk_usize 2080)

/// `KeyPairCompressedBytes` -- a compressed ML-KEM-768 key pair.
/// <https://docs.rs/libcrux-ml-kem/0.0.10/libcrux_ml_kem/mlkem768/incremental/struct.KeyPairCompressedBytes.html>
///
/// Opaque: SPQR only ever builds one with `from_seed` and then reads the three
/// parts back out with `pk1`/`pk2`/`sk`, never touching the representation.
val t_KeyPairCompressedBytes: Type0

/// `KeyPairCompressedBytes::from_seed(randomness: [u8; 64])`
///
/// No postcondition: the accessors below fix the sizes of everything SPQR
/// subsequently reads, and SPQR makes no claim about the key material itself.
val impl_KeyPairCompressedBytes__from_seed (randomness: t_Array u8 (mk_usize 64))
    : Prims.Pure t_KeyPairCompressedBytes Prims.l_True (fun _ -> Prims.l_True)

/// `KeyPairCompressedBytes::sk()` -- the compressed private key, 2400 bytes for
/// ML-KEM-768. The return type carries the size, so no `ensures` is needed.
val impl_KeyPairCompressedBytes__sk (self: t_KeyPairCompressedBytes)
    : Prims.Pure (t_Array u8 (mk_usize 2400)) Prims.l_True (fun _ -> Prims.l_True)

/// `KeyPairCompressedBytes::pk1()` -- matches [`pk1_len`].
val impl_KeyPairCompressedBytes__pk1 (self: t_KeyPairCompressedBytes)
    : Prims.Pure (t_Array u8 (mk_usize 64)) Prims.l_True (fun _ -> Prims.l_True)

/// `KeyPairCompressedBytes::pk2()` -- matches [`pk2_len`].
val impl_KeyPairCompressedBytes__pk2 (self: t_KeyPairCompressedBytes)
    : Prims.Pure (t_Array u8 (mk_usize 1152)) Prims.l_True (fun _ -> Prims.l_True)

/// `validate_pk_bytes(pk1, pk2)`
/// <https://docs.rs/libcrux-ml-kem/0.0.10/libcrux_ml_kem/mlkem768/incremental/fn.validate_pk_bytes.html>
///
/// `Ok` requires three things, and none of them is stated. Nothing in SPQR
/// consumes a fact about this call -- `ek_matches_header`'s result only steers
/// a branch, and `recv_ek` takes `ek.len() == 1152` as its own precondition --
/// so any postcondition here would be granted for free and discharge nothing.
///
/// For the record, read off 0.0.10's `incremental.rs:297-339`, `Ok` implies:
/// `pk1.len() == 64 && pk2.len() == 1152` exactly (the test is `!=`, unlike
/// `PublicKey1::try_from`'s `<`); `H(pk2 || pk1[0..32]) == pk1[32..64]`, which
/// is the binding `ek_matches_header` exists to check and which would need a
/// SHA3-256 symbol here; and that `t` decodes and re-encodes to itself.
val validate_pk_bytes (pk1 pk2: t_Slice u8)
    : Prims.Pure
      (Core_models.Result.t_Result Prims.unit
          Libcrux_ml_kem.Ind_cca.Incremental.Types.t_Error)
      Prims.l_True
      (fun _ -> Prims.l_True)

/// error2's `j`th coefficient, built from its two stored bytes exactly as
/// `encapsulate2`'s deserialiser reads them. `from_le_bytes` is left
/// uninterpreted: what matters is that this and `incremental_mlkem768.rs`'s
/// range check apply the *same* function to the *same* bytes.
let error2_coefficient_of (lo hi: u8) : i16 =
  let l = [lo; hi] in
  FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length l) 2);
  Core_models.Num.impl_i16__from_le_bytes (Rust_primitives.Hax.array_of_list 2 l)

let error2_coefficient (state: t_Slice u8) (swap: bool) (j: nat{2 * j + 1537 < Seq.length state})
    : i16 =
  if swap
  then error2_coefficient_of (Seq.index state (1537 + 2 * j)) (Seq.index state (1536 + 2 * j))
  else error2_coefficient_of (Seq.index state (1536 + 2 * j)) (Seq.index state (1537 + 2 * j))

/// `EncapsState::try_from_bytes` reads error2 out of `state[1536..2048]` as 256
/// raw little-endian i16 lanes with no range check, then adds 0 or 1665 to
/// each; libcrux requires both operands bounded by 3328 (`polynomial.rs:306-309`).
/// `encapsulate1` writes CBD(eta2 = 2) samples, which lie in [-2, 2].
let error2_in_range (state: t_Slice u8) (swap: bool) : prop =
  Seq.length state == 2080 /\
  (forall (j: nat). j < 256 ==>
    (let c = error2_coefficient state swap j in v c >= -2 /\ v c <= 2))

/// `encapsulate1(pk1, randomness, state, shared_secret)`
/// <https://docs.rs/libcrux-ml-kem/0.0.10/libcrux_ml_kem/mlkem768/incremental/fn.encapsulate1.html>
///
/// The output sizes are checked by `debug_assert!` before returning
/// `InvalidOutputLength`, so they are the precondition. `pk1.len() >= 64`
/// implies `Ok`.
///
/// The length equalities hold because both out-params are `&mut [u8]` and a
/// callee cannot change a slice's length.
val encapsulate1
      (pk1: t_Slice u8)
      (randomness: t_Array u8 (mk_usize 32))
      (state shared_secret: t_Slice u8)
    : Prims.Pure
      (t_Slice u8 & t_Slice u8 &
        Core_models.Result.t_Result (Libcrux_ml_kem.Ind_cca.Incremental.Types.t_Ciphertext1 (mk_usize 960))
          Libcrux_ml_kem.Ind_cca.Incremental.Types.t_Error)
      (requires
        Core_models.Slice.impl__len #u8 state >=. mk_usize 2080 /\
        Core_models.Slice.impl__len #u8 shared_secret >=. mk_usize 32)
      (ensures
        fun temp_0_ ->
          let (state_future: t_Slice u8), (shared_secret_future: t_Slice u8),
            (res:
              Core_models.Result.t_Result
                (Libcrux_ml_kem.Ind_cca.Incremental.Types.t_Ciphertext1 (mk_usize 960))
                Libcrux_ml_kem.Ind_cca.Incremental.Types.t_Error) =
            temp_0_
          in
          (Core_models.Slice.impl__len #u8 state_future =. Core_models.Slice.impl__len #u8 state) /\
          (Core_models.Slice.impl__len #u8 shared_secret_future =.
            Core_models.Slice.impl__len #u8 shared_secret) /\
          (Core_models.Slice.impl__len #u8 pk1 >=. mk_usize 64 ==>
            Core_models.Result.impl__is_ok
              #(Libcrux_ml_kem.Ind_cca.Incremental.Types.t_Ciphertext1 (mk_usize 960))
              #Libcrux_ml_kem.Ind_cca.Incremental.Types.t_Error
              res) /\
          (Core_models.Result.Result_Ok? res /\ Core_models.Slice.impl__len #u8 state =. mk_usize 2080 ==>
            error2_in_range state_future false))

/// `encapsulate2(state, public_key_part)`
/// <https://docs.rs/libcrux-ml-kem/0.0.10/libcrux_ml_kem/mlkem768/incremental/fn.encapsulate2.html>
///
/// Assumed total: `r_as_ntt` (`state[0..1536]`) is not range-checked, although
/// libcrux's `ntt_multiply` requires it bounded by 3328 (`polynomial.rs:681-683`).
val encapsulate2 (state: t_Array u8 (mk_usize 2080)) (public_key_part: t_Array u8 (mk_usize 1152))
    : Prims.Pure (Libcrux_ml_kem.Ind_cca.Incremental.Types.t_Ciphertext2 (mk_usize 128))
      (requires error2_in_range state false)
      (fun _ -> Prims.l_True)

/// `decapsulate_compressed_key(private_key, ciphertext1, ciphertext2)`
/// <https://docs.rs/libcrux-ml-kem/0.0.10/libcrux_ml_kem/mlkem768/incremental/fn.decapsulate_compressed_key.html>
///
/// Total, and returns the 32-byte shared secret in its type. Like
/// `validate_pk_bytes`, the property SPQR's protocol actually leans on -- that
/// this returns the same secret `encapsulate1`/`encapsulate2` produced -- is
/// not stated. ML-KEM never fails decapsulation: on a malformed ciphertext it
/// returns the implicit-rejection secret rather than an error, which is why
/// there is no `Result` here.
val decapsulate_compressed_key
      (private_key: t_Array u8 (mk_usize 2400))
      (ciphertext1: Libcrux_ml_kem.Ind_cca.Incremental.Types.t_Ciphertext1 (mk_usize 960))
      (ciphertext2: Libcrux_ml_kem.Ind_cca.Incremental.Types.t_Ciphertext2 (mk_usize 128))
    : Prims.Pure (t_Array u8 (mk_usize 32)) Prims.l_True (fun _ -> Prims.l_True)
