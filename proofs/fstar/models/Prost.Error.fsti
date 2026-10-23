module Prost.Error
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open Core_models
open FStar.Mul

/// `prost` 0.14, error types.
/// <https://docs.rs/prost/0.14/prost/>
///
/// Both types reach the extraction only as the error side of a `Result` that
/// SPQR maps into its own `Error`; neither is constructed or inspected here.

/// A protobuf message failed to decode.
/// <https://docs.rs/prost/0.14/prost/struct.DecodeError.html>
val t_DecodeError: Type0

/// A buffer was too small to encode a protobuf message into.
/// <https://docs.rs/prost/0.14/prost/struct.EncodeError.html>
val t_EncodeError: Type0

/// An integer did not name a variant of the enum being decoded.
/// <https://docs.rs/prost/0.14/prost/struct.UnknownEnumValue.html>
type t_UnknownEnumValue = | UnknownEnumValue : i32 -> t_UnknownEnumValue
