module Prost.Error
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open Core
open FStar.Mul

type t_Inner = {
  f_description:Alloc.Borrow.t_Cow string;
  f_stack:Alloc.Vec.t_Vec (string & string) Alloc.Alloc.t_Global
}

/// A Protobuf message decoding error.
/// `DecodeError` indicates that the input buffer does not contain a valid
/// Protobuf message. The error details should be considered 'best effort': in
/// general it is not possible to exactly pinpoint why data is malformed.
type t_DecodeError = { f_inner:Alloc.Boxed.t_Box t_Inner Alloc.Alloc.t_Global }

[@@ FStar.Tactics.Typeclasses.tcinstance]
val impl:Core.Clone.t_Clone t_DecodeError

[@@ FStar.Tactics.Typeclasses.tcinstance]
val impl_1:Core.Marker.t_StructuralPartialEq t_DecodeError

[@@ FStar.Tactics.Typeclasses.tcinstance]
val impl_2:Core.Cmp.t_PartialEq t_DecodeError t_DecodeError

[@@ FStar.Tactics.Typeclasses.tcinstance]
val impl_3:Core.Cmp.t_Eq t_DecodeError

[@@ FStar.Tactics.Typeclasses.tcinstance]
val impl_4:Core.Clone.t_Clone t_Inner

[@@ FStar.Tactics.Typeclasses.tcinstance]
val impl_5:Core.Marker.t_StructuralPartialEq t_Inner

[@@ FStar.Tactics.Typeclasses.tcinstance]
val impl_6:Core.Cmp.t_PartialEq t_Inner t_Inner

[@@ FStar.Tactics.Typeclasses.tcinstance]
val impl_7:Core.Cmp.t_Eq t_Inner

/// A Protobuf message encoding error.
/// `EncodeError` always indicates that a message failed to encode because the
/// provided buffer had insufficient capacity. Message encoding is otherwise
/// infallible.
type t_EncodeError = {
  f_required:usize;
  f_remaining:usize
}

[@@ FStar.Tactics.Typeclasses.tcinstance]
val impl_9:Core.Clone.t_Clone t_EncodeError

[@@ FStar.Tactics.Typeclasses.tcinstance]
val impl_8:Core.Marker.t_Copy t_EncodeError

[@@ FStar.Tactics.Typeclasses.tcinstance]
val impl_10:Core.Fmt.t_Debug t_EncodeError

[@@ FStar.Tactics.Typeclasses.tcinstance]
val impl_11:Core.Marker.t_StructuralPartialEq t_EncodeError

[@@ FStar.Tactics.Typeclasses.tcinstance]
val impl_12:Core.Cmp.t_PartialEq t_EncodeError t_EncodeError

[@@ FStar.Tactics.Typeclasses.tcinstance]
val impl_13:Core.Cmp.t_Eq t_EncodeError
