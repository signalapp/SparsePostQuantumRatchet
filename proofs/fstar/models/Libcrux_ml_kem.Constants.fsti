module Libcrux_ml_kem.Constants
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open Core_models
open FStar.Mul

/// `libcrux-ml-kem` 0.0.10, constants.
/// <https://docs.rs/libcrux-ml-kem/0.0.10/libcrux_ml_kem/>

/// The size of an ML-KEM shared secret, 32 bytes for every parameter set.
/// <https://docs.rs/libcrux-ml-kem/0.0.10/libcrux_ml_kem/constant.SHARED_SECRET_SIZE.html>
///
/// Concrete, because `incremental_mlkem768.rs` relies on the value.
let v_SHARED_SECRET_SIZE: usize = mk_usize 32
