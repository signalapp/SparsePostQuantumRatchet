module Libcrux_hmac
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open Core_models
open FStar.Mul

/// `libcrux-hmac` 0.0.8.
/// <https://docs.rs/libcrux-hmac/0.0.8/libcrux_hmac/>
///
/// `authenticator.rs` calls `hmac` with `Algorithm::Sha256`.

/// The hash function an HMAC is taken over.
/// <https://docs.rs/libcrux-hmac/0.0.8/libcrux_hmac/enum.Algorithm.html>
///
/// Concrete, because `hmac`'s tag-length postcondition matches on the variants.
type t_Algorithm =
  | Algorithm_Sha256 : t_Algorithm
  | Algorithm_Sha384 : t_Algorithm
  | Algorithm_Sha512 : t_Algorithm

/// Compute an HMAC tag, truncated to `tag_length` if that is shorter than the
/// hash output.
/// <https://docs.rs/libcrux-hmac/0.0.8/libcrux_hmac/fn.hmac.html>
///
/// The postcondition covers the returned length only; nothing is stated about
/// the tag's value. The crate panics if `key` or `data` exceed `u32::MAX`,
/// which is not modelled as a precondition.
val hmac (alg: t_Algorithm) (key data: t_Slice u8) (tag_length: Core_models.Option.t_Option usize)
    : Prims.Pure (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
      Prims.l_True
      (ensures
        fun result ->
          let result:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global = result in
          let native_tag_length:usize =
            match alg <: t_Algorithm with
            | Algorithm_Sha256  -> mk_usize 32
            | Algorithm_Sha384  -> mk_usize 48
            | Algorithm_Sha512  -> mk_usize 64
          in
          match
            (match tag_length <: Core_models.Option.t_Option usize with
              | Core_models.Option.Option_Some l ->
                (match l <=. native_tag_length <: bool with
                  | true ->
                    Core_models.Option.Option_Some
                    ((Alloc.Vec.impl_1__len #u8 #Alloc.Alloc.t_Global result <: usize) =. l)
                    <:
                    Core_models.Option.t_Option bool
                  | _ -> Core_models.Option.Option_None <: Core_models.Option.t_Option bool)
              | _ -> Core_models.Option.Option_None <: Core_models.Option.t_Option bool)
            <:
            Core_models.Option.t_Option bool
          with
          | Core_models.Option.Option_Some x -> x
          | Core_models.Option.Option_None  ->
            (Alloc.Vec.impl_1__len #u8 #Alloc.Alloc.t_Global result <: usize) =. native_tag_length)
