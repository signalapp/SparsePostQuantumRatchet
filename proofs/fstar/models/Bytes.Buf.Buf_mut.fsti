module Bytes.Buf.Buf_mut
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open Core_models
open FStar.Mul

/// `bytes` 1.x, the `BufMut` trait.
/// <https://docs.rs/bytes/1/bytes/trait.BufMut.html>
///
/// Write access to a byte buffer. Reaches the extraction only as a bound on
/// prost's encoding entry points; no instance is resolved and no method is
/// called, so the name is abstract.

val t_BufMut: Type0 -> Type0
