module Prost.Encoding.Wire_type
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open Core
open FStar.Mul

type t_WireType =
  | WireType_Varint : t_WireType
  | WireType_SixtyFourBit : t_WireType
  | WireType_LengthDelimited : t_WireType
  | WireType_StartGroup : t_WireType
  | WireType_EndGroup : t_WireType
  | WireType_ThirtyTwoBit : t_WireType

let discriminant_WireType_Varint: isize = mk_isize 0

let discriminant_WireType_SixtyFourBit: isize = mk_isize 1

let discriminant_WireType_LengthDelimited: isize = mk_isize 2

let discriminant_WireType_StartGroup: isize = mk_isize 3

let discriminant_WireType_EndGroup: isize = mk_isize 4

let discriminant_WireType_ThirtyTwoBit: isize = mk_isize 5

val t_WireType_cast_to_repr (x: t_WireType) : Prims.Pure isize Prims.l_True (fun _ -> Prims.l_True)
