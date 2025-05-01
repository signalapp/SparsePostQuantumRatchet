module Libcrux_hmac
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open Core
open FStar.Mul

/// The HMAC algorithm defining the used hash function.
type t_Algorithm =
  | Algorithm_Sha1 : t_Algorithm
  | Algorithm_Sha256 : t_Algorithm
  | Algorithm_Sha384 : t_Algorithm
  | Algorithm_Sha512 : t_Algorithm

val t_Algorithm_cast_to_repr (x: t_Algorithm)
    : Prims.Pure isize Prims.l_True (fun _ -> Prims.l_True)

[@@ FStar.Tactics.Typeclasses.tcinstance]
val impl_1:Core.Clone.t_Clone t_Algorithm

[@@ FStar.Tactics.Typeclasses.tcinstance]
val impl:Core.Marker.t_Copy t_Algorithm

[@@ FStar.Tactics.Typeclasses.tcinstance]
val impl_2:Core.Fmt.t_Debug t_Algorithm

[@@ FStar.Tactics.Typeclasses.tcinstance]
val impl_3:Core.Marker.t_StructuralPartialEq t_Algorithm

[@@ FStar.Tactics.Typeclasses.tcinstance]
val impl_4:Core.Cmp.t_PartialEq t_Algorithm t_Algorithm

/// Get the tag size for a given algorithm.
val tag_size (alg: t_Algorithm) : Prims.Pure usize Prims.l_True (fun _ -> Prims.l_True)

/// Compute the HMAC value with the given `alg` and `key` on `data` with an
/// output tag length of `tag_length`.
/// Returns a vector of length `tag_length`.
/// Panics if either `key` or `data` are longer than `u32::MAX`.
val hmac (alg: t_Algorithm) (key data: t_Slice u8) (tag_length: Core.Option.t_Option usize)
    : Prims.Pure (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
      Prims.l_True
      (ensures
        fun result ->
          let result:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global = result in
          let native_tag_length:usize =
            match alg <: t_Algorithm with
            | Algorithm_Sha1  -> mk_usize 20
            | Algorithm_Sha256  -> mk_usize 32
            | Algorithm_Sha384  -> mk_usize 48
            | Algorithm_Sha512  -> mk_usize 64
          in
          match
            (match tag_length <: Core.Option.t_Option usize with
              | Core.Option.Option_Some l ->
                (match l <=. native_tag_length <: bool with
                  | true ->
                    Core.Option.Option_Some
                    ((Alloc.Vec.impl_1__len #u8 #Alloc.Alloc.t_Global result <: usize) =. l)
                    <:
                    Core.Option.t_Option bool
                  | _ -> Core.Option.Option_None <: Core.Option.t_Option bool)
              | _ -> Core.Option.Option_None <: Core.Option.t_Option bool)
            <:
            Core.Option.t_Option bool
          with
          | Core.Option.Option_Some x -> x
          | Core.Option.Option_None  ->
            (Alloc.Vec.impl_1__len #u8 #Alloc.Alloc.t_Global result <: usize) =. native_tag_length)

(* item error backend: (DirectAndMut) The mutation of this [1m&mut[0m is not allowed here.
Last available AST for this item:

#[_hax::json("\"Erased\"")]
#[inline(always)]
#[no_std()]
#[feature(register_tool)]
#[register_tool(_hax)]
fn wrap_bufalloc<const N: int, F>(f: F) -> alloc::vec::t_Vec<int, alloc::alloc::t_Global>
where
    _: core::ops::function::t_Fn<F, tuple1<&mut [int; N]>>,
    F: core::ops::function::t_FnOnce<f_Output = tuple0>,
{
    rust_primitives::hax::dropped_body
}


Last AST:
/** print_rust: pitem: not implemented  (item: { Concrete_ident.T.def_id =
  { Concrete_ident.Imported.krate = "libcrux_hmac";
    path =
    [{ Concrete_ident.Imported.data =
       (Concrete_ident.Imported.ValueNs "wrap_bufalloc"); disambiguator = 0 }
      ]
    };
  kind = Concrete_ident.Kind.Value }) */
const _: () = ();
 *)
