module Prost.Message
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open Core
open FStar.Mul

let _ =
  (* This module has implicit dependencies, here we make them explicit. *)
  (* The implicit dependencies arise from typeclasses instances. *)
  let open Bytes.Buf.Buf_impl in
  let open Bytes.Buf.Buf_mut in
  ()

/// A Protocol Buffers message.
class t_Message (v_Self: Type0) = {
  [@@@ FStar.Tactics.Typeclasses.no_method]_super_7459769351467436346:Core.Fmt.t_Debug v_Self;
  [@@@ FStar.Tactics.Typeclasses.no_method]_super_10374730180605511532:Core.Marker.t_Send v_Self;
  [@@@ FStar.Tactics.Typeclasses.no_method]_super_6360119584534035317:Core.Marker.t_Sync v_Self;
  f_encode_pre:
      #impl_806524398_: Type0 ->
      {| i2: Bytes.Buf.Buf_mut.t_BufMut impl_806524398_ |} ->
      v_Self ->
      impl_806524398_
    -> Type0;
  f_encode_post:
      #impl_806524398_: Type0 ->
      {| i2: Bytes.Buf.Buf_mut.t_BufMut impl_806524398_ |} ->
      v_Self ->
      impl_806524398_ ->
      (impl_806524398_ & Core.Result.t_Result Prims.unit Prost.Error.t_EncodeError)
    -> Type0;
  f_encode:
      #impl_806524398_: Type0 ->
      {| i2: Bytes.Buf.Buf_mut.t_BufMut impl_806524398_ |} ->
      x0: v_Self ->
      x1: impl_806524398_
    -> Prims.Pure
        (impl_806524398_ & Core.Result.t_Result Prims.unit Prost.Error.t_EncodeError)
        (f_encode_pre #impl_806524398_ #i2 x0 x1)
        (fun result -> f_encode_post #impl_806524398_ #i2 x0 x1 result);
  f_encode_to_vec_pre:v_Self -> Type0;
  f_encode_to_vec_post:v_Self -> Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global -> Type0;
  f_encode_to_vec:x0: v_Self
    -> Prims.Pure (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
        (f_encode_to_vec_pre x0)
        (fun result -> f_encode_to_vec_post x0 result);
  f_decode_pre:
      #impl_75985673_: Type0 ->
      {| i4: Core.Default.t_Default v_Self |} ->
      {| i5: Bytes.Buf.Buf_impl.t_Buf impl_75985673_ |} ->
      impl_75985673_
    -> Type0;
  f_decode_post:
      #impl_75985673_: Type0 ->
      {| i4: Core.Default.t_Default v_Self |} ->
      {| i5: Bytes.Buf.Buf_impl.t_Buf impl_75985673_ |} ->
      impl_75985673_ ->
      Core.Result.t_Result v_Self Prost.Error.t_DecodeError
    -> Type0;
  f_decode:
      #impl_75985673_: Type0 ->
      {| i4: Core.Default.t_Default v_Self |} ->
      {| i5: Bytes.Buf.Buf_impl.t_Buf impl_75985673_ |} ->
      x0: impl_75985673_
    -> Prims.Pure (Core.Result.t_Result v_Self Prost.Error.t_DecodeError)
        (f_decode_pre #impl_75985673_ #i4 #i5 x0)
        (fun result -> f_decode_post #impl_75985673_ #i4 #i5 x0 result);
  f_clear_pre:v_Self -> Type0;
  f_clear_post:v_Self -> v_Self -> Type0;
  f_clear:x0: v_Self -> Prims.Pure v_Self (f_clear_pre x0) (fun result -> f_clear_post x0 result)
}
