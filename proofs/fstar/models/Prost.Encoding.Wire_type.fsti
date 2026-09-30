module Prost.Encoding.Wire_type
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open Core_models
open FStar.Mul

/// `prost` 0.14, protobuf wire types.
/// <https://docs.rs/prost/0.14/prost/encoding/enum.WireType.html>
///
/// Appears in the extraction only as a field type on prost's decoding context.

type t_WireType =
  | WireType_Varint : t_WireType
  | WireType_SixtyFourBit : t_WireType
  | WireType_LengthDelimited : t_WireType
  | WireType_StartGroup : t_WireType
  | WireType_EndGroup : t_WireType
  | WireType_ThirtyTwoBit : t_WireType
