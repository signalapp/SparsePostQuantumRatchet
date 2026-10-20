module Bytes.Buf.Buf_impl
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open Core_models
open FStar.Mul

/// `bytes` 1.x, the `Buf` trait.
/// <https://docs.rs/bytes/1/bytes/trait.Buf.html>
///
/// Read access to a byte buffer. Reaches the extraction only as a bound on
/// prost's decoding entry points; no method is called and the type is never
/// projected, so the class is empty.

class t_Buf (v_T: Type0) = {
  dummy_field: Type0
}

/// `impl Buf for &[u8]`, for decoding from a slice.
[@@ FStar.Tactics.Typeclasses.tcinstance]
val impl_2:t_Buf (t_Slice u8)
