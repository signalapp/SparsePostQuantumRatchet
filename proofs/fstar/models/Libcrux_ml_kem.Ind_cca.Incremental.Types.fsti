module Libcrux_ml_kem.Ind_cca.Incremental.Types
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open Core_models
open FStar.Mul

/// Model of `libcrux_ml_kem::ind_cca::incremental::types` (libcrux-ml-kem 0.0.10).
/// <https://docs.rs/libcrux-ml-kem/0.0.10/libcrux_ml_kem/mlkem768/incremental/>
///
/// Covers exactly the three types the extraction names. libcrux's own module
/// also carries `PublicKey1`, `PublicKey2`, `EncapsState`, `KeyPair` and their
/// `TryFrom`/`Debug`/`Clone` instances; SPQR reaches none of them -- it works in
/// raw byte slices and only materialises ciphertext values at the
/// `encapsulate`/`decapsulate` boundary.

/// `Error`
/// <https://docs.rs/libcrux-ml-kem/0.0.10/libcrux_ml_kem/mlkem768/incremental/enum.Error.html>
///
/// Opaque. libcrux distinguishes `InvalidInputLength`, `InvalidOutputLength`,
/// `InvalidPublicKey` and `InsufficientRandomness`, but SPQR never inspects
/// which one it got: `incremental_mlkem768.rs` either propagates a failure as
/// `Error::BadHeader` or is on a path where the contracts below rule failure
/// out. Keeping it opaque records that the discrimination is unused.
val t_Error: Type0

/// `Ciphertext1<LEN>` -- the first part of an incremental ciphertext.
///
/// NOT opaque, deliberately. libcrux declares it as a newtype over
/// `[u8; LEN]`, and SPQR depends on that layout in both directions: it projects
/// `.value` to get the bytes out (`encaps1`, `encaps2`) and constructs one from
/// bytes on the way in (`decaps`). Making the type abstract would need `value`
/// and a constructor exposed as functions with an axiom saying they are
/// inverse, which is the same assumption written less directly. The assumption
/// being made is that `Ciphertext1`'s public field stays a plain `[u8; LEN]`.
type t_Ciphertext1 (v_LEN: usize) = { f_value:t_Array u8 v_LEN }

/// `Ciphertext1::len()`
///
/// Returns the const generic. Justified by the declaration: the value is an
/// array of exactly `LEN` bytes, so its length is `LEN` and cannot depend on
/// anything else.
val impl_5__len: v_LEN: usize -> Prims.unit
  -> Prims.Pure usize Prims.l_True (ensures fun res -> res =. v_LEN)

/// `Ciphertext2<LEN>` -- the second part of an incremental ciphertext.
/// Same newtype-layout assumption as [`t_Ciphertext1`].
type t_Ciphertext2 (v_LEN: usize) = { f_value:t_Array u8 v_LEN }

/// `Ciphertext2::len()`. See [`impl_5__len`].
val impl_6__len: v_LEN: usize -> Prims.unit
  -> Prims.Pure usize Prims.l_True (ensures fun res -> res =. v_LEN)
