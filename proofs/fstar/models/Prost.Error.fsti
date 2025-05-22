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

let impl_6: Core.Clone.t_Clone t_DecodeError = { f_clone = (fun x -> x) }

[@@ FStar.Tactics.Typeclasses.tcinstance]
val impl_7:Core.Marker.t_StructuralPartialEq t_DecodeError

[@@ FStar.Tactics.Typeclasses.tcinstance]
val impl_8:Core.Cmp.t_PartialEq t_DecodeError t_DecodeError

[@@ FStar.Tactics.Typeclasses.tcinstance]
val impl_9:Core.Cmp.t_Eq t_DecodeError

let impl_10: Core.Clone.t_Clone t_Inner = { f_clone = (fun x -> x) }

[@@ FStar.Tactics.Typeclasses.tcinstance]
val impl_11:Core.Marker.t_StructuralPartialEq t_Inner

[@@ FStar.Tactics.Typeclasses.tcinstance]
val impl_12:Core.Cmp.t_PartialEq t_Inner t_Inner

[@@ FStar.Tactics.Typeclasses.tcinstance]
val impl_13:Core.Cmp.t_Eq t_Inner

/// Creates a new `DecodeError` with a 'best effort' root cause description.
/// Meant to be used only by `Message` implementations.
val impl_DecodeError__new
      (#iimpl_270350286_: Type0)
      {| i1: Core.Convert.t_Into iimpl_270350286_ (Alloc.Borrow.t_Cow string) |}
      (description: iimpl_270350286_)
    : Prims.Pure t_DecodeError Prims.l_True (fun _ -> Prims.l_True)

/// Pushes a (message, field) name location pair on to the location stack.
/// Meant to be used only by `Message` implementations.
val impl_DecodeError__push (self: t_DecodeError) (message field: string)
    : Prims.Pure t_DecodeError Prims.l_True (fun _ -> Prims.l_True)

[@@ FStar.Tactics.Typeclasses.tcinstance]
val impl_1:Core.Fmt.t_Debug t_DecodeError

[@@ FStar.Tactics.Typeclasses.tcinstance]
val impl_2:Core.Fmt.t_Display t_DecodeError

/// A Protobuf message encoding error.
/// `EncodeError` always indicates that a message failed to encode because the
/// provided buffer had insufficient capacity. Message encoding is otherwise
/// infallible.
type t_EncodeError = {
  f_required:usize;
  f_remaining:usize
}

let impl_15: Core.Clone.t_Clone t_EncodeError = { f_clone = (fun x -> x) }

[@@ FStar.Tactics.Typeclasses.tcinstance]
val impl_14:Core.Marker.t_Copy t_EncodeError

[@@ FStar.Tactics.Typeclasses.tcinstance]
val impl_16:Core.Fmt.t_Debug t_EncodeError

[@@ FStar.Tactics.Typeclasses.tcinstance]
val impl_17:Core.Marker.t_StructuralPartialEq t_EncodeError

[@@ FStar.Tactics.Typeclasses.tcinstance]
val impl_18:Core.Cmp.t_PartialEq t_EncodeError t_EncodeError

[@@ FStar.Tactics.Typeclasses.tcinstance]
val impl_19:Core.Cmp.t_Eq t_EncodeError

/// Creates a new `EncodeError`.
val impl_EncodeError__new (required remaining: usize)
    : Prims.Pure t_EncodeError Prims.l_True (fun _ -> Prims.l_True)

/// Returns the required buffer capacity to encode the message.
val impl_EncodeError__required_capacity (self: t_EncodeError)
    : Prims.Pure usize Prims.l_True (fun _ -> Prims.l_True)

/// Returns the remaining length in the provided buffer at the time of encoding.
val impl_EncodeError__remaining (self: t_EncodeError)
    : Prims.Pure usize Prims.l_True (fun _ -> Prims.l_True)

[@@ FStar.Tactics.Typeclasses.tcinstance]
val impl_4:Core.Fmt.t_Display t_EncodeError

/// An error indicating that an unknown enumeration value was encountered.
/// The Protobuf spec mandates that enumeration value sets are ‘open’, so this
/// error's value represents an integer value unrecognized by the
/// presently used enum definition.
type t_UnknownEnumValue = | UnknownEnumValue : i32 -> t_UnknownEnumValue

let impl_21: Core.Clone.t_Clone t_UnknownEnumValue = { f_clone = (fun x -> x) }

[@@ FStar.Tactics.Typeclasses.tcinstance]
val impl_20:Core.Marker.t_Copy t_UnknownEnumValue

[@@ FStar.Tactics.Typeclasses.tcinstance]
val impl_22:Core.Fmt.t_Debug t_UnknownEnumValue

[@@ FStar.Tactics.Typeclasses.tcinstance]
val impl_23:Core.Marker.t_StructuralPartialEq t_UnknownEnumValue

[@@ FStar.Tactics.Typeclasses.tcinstance]
val impl_24:Core.Cmp.t_PartialEq t_UnknownEnumValue t_UnknownEnumValue

[@@ FStar.Tactics.Typeclasses.tcinstance]
val impl_25:Core.Cmp.t_Eq t_UnknownEnumValue

[@@ FStar.Tactics.Typeclasses.tcinstance]
val impl_5:Core.Fmt.t_Display t_UnknownEnumValue
