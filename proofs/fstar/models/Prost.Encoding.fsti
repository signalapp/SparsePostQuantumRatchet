module Prost.Encoding
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open Core_models
open FStar.Mul

/// `prost` 0.14, decoding state.
/// <https://docs.rs/prost/0.14/prost/encoding/struct.DecodeContext.html>
///
/// Tracks nesting depth so that deeply nested messages are rejected.
type t_DecodeContext = { f_recurse_count:u32 }
