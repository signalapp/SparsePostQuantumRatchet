module Num_enum
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open Core
open FStar.Mul

(* item error backend: (reject_TraitItemDefault) ExplicitRejection { reason: "a node of kind [Trait_item_default] have been found in the AST" }
Last available AST for this item:

#[feature(register_tool)]#[register_tool(_hax)]trait t_UnsafeFromPrimitive<Self_>{type f_Primitive: TodoPrintRustBoundsTyp;
fn f_from_unchecked((number: proj_asso_type!())) -> Self{num_enum::f_unchecked_transmute_from(number)}
#[_hax::json("\"TraitMethodNoPrePost\"")]fn f_unchecked_transmute_from_pre(_: proj_asso_type!()) -> bool;
#[_hax::json("\"TraitMethodNoPrePost\"")]fn f_unchecked_transmute_from_post(_: proj_asso_type!(),_: Self) -> bool;
fn f_unchecked_transmute_from(_: proj_asso_type!()) -> Self;}

Last AST:
/** print_rust: pitem: not implemented  (item: { Concrete_ident.T.def_id =
  { Explicit_def_id.T.is_constructor = false;
    def_id =
    { Types.index = (0, 0); is_local = true; kind = Types.Trait;
      krate = "num_enum";
      parent =
      (Some { Types.contents =
              { Types.id = 0;
                value =
                { Types.index = (0, 0); is_local = true; kind = Types.Mod;
                  krate = "num_enum"; parent = None; path = [] }
                }
              });
      path =
      [{ Types.data = (Types.TypeNs "UnsafeFromPrimitive"); disambiguator = 0
         }
        ]
      }
    };
  moved = None; suffix = None }) */
const _: () = ();
 *)

class t_CannotDeriveBothFromPrimitiveAndTryFromPrimitive (v_Self: Type0) = {
  __marker_trait:Prims.unit
}

(* class t_FromPrimitive (v_Self: Type0) = {
  f_Primitive:Type0;
  f_Primitive_8876061459599834537:Core.Marker.t_Copy f_Primitive;
  f_Primitive_17391871992276743015:Core.Cmp.t_Eq f_Primitive;
  f_from_primitive_pre:f_Primitive -> Type0;
  f_from_primitive_post:f_Primitive -> v_Self -> Type0;
  f_from_primitive:x0: f_Primitive
    -> Prims.Pure v_Self (f_from_primitive_pre x0) (fun result -> f_from_primitive_post x0 result)
} *)

class t_TryFromPrimitive (v_Self: Type0) = {
  f_Primitive:Type0;
  (* f_Primitive_12399228673407067350:Core.Marker.t_Copy f_Primitive;
  f_Primitive_5629480169667985622:Core.Cmp.t_Eq f_Primitive;
  f_Primitive_10837566226016321784:Core.Fmt.t_Debug f_Primitive; *)
  f_Error:Type0;
  f_NAME:string;
  f_try_from_primitive_pre:f_Primitive -> Type0;
  f_try_from_primitive_post:f_Primitive -> Core.Result.t_Result v_Self f_Error -> Type0;
  f_try_from_primitive:x0: f_Primitive
    -> Prims.Pure (Core.Result.t_Result v_Self f_Error)
        (f_try_from_primitive_pre x0)
        (fun result -> f_try_from_primitive_post x0 result)
}

type t_TryFromPrimitiveError (v_Enum: Type0) (* {| i1: t_TryFromPrimitive v_Enum |} *) = {
  f_number:(* i1.f_Primitive *) u8
}

[@@ FStar.Tactics.Typeclasses.tcinstance]
val impl_5
      (#v_Enum: Type0)
      {| i1: Core.Clone.t_Clone v_Enum |}
      {| i2: t_TryFromPrimitive v_Enum |}
      {| i3: Core.Clone.t_Clone i2.f_Primitive |}
    : Core.Clone.t_Clone (t_TryFromPrimitiveError v_Enum)

[@@ FStar.Tactics.Typeclasses.tcinstance]
val impl_4
      (#v_Enum: Type0)
      {| i1: Core.Marker.t_Copy v_Enum |}
      {| i2: t_TryFromPrimitive v_Enum |}
      {| i3: Core.Marker.t_Copy i2.f_Primitive |}
    : Core.Marker.t_Copy (t_TryFromPrimitiveError v_Enum)

[@@ FStar.Tactics.Typeclasses.tcinstance]
val impl_6 (#v_Enum: Type0) {| i1: t_TryFromPrimitive v_Enum |}
    : Core.Marker.t_StructuralPartialEq (t_TryFromPrimitiveError v_Enum)

[@@ FStar.Tactics.Typeclasses.tcinstance]
val impl_7
      (#v_Enum: Type0)
      {| i1: Core.Cmp.t_PartialEq v_Enum v_Enum |}
      {| i2: t_TryFromPrimitive v_Enum |}
      {| i3: Core.Cmp.t_PartialEq i2.f_Primitive i2.f_Primitive |}
    : Core.Cmp.t_PartialEq (t_TryFromPrimitiveError v_Enum) (t_TryFromPrimitiveError v_Enum)

[@@ FStar.Tactics.Typeclasses.tcinstance]
val impl_8
      (#v_Enum: Type0)
      {| i1: Core.Cmp.t_Eq v_Enum |}
      {| i2: t_TryFromPrimitive v_Enum |}
      {| i3: Core.Cmp.t_Eq i2.f_Primitive |}
    : Core.Cmp.t_Eq (t_TryFromPrimitiveError v_Enum)

val impl__new (#v_Enum: Type0) {| i1: t_TryFromPrimitive v_Enum |} (number: i1.f_Primitive)
    : Prims.Pure (t_TryFromPrimitiveError v_Enum) Prims.l_True (fun _ -> Prims.l_True)

[@@ FStar.Tactics.Typeclasses.tcinstance]
val impl_1 (#v_Enum: Type0) {| i1: t_TryFromPrimitive v_Enum |}
    : Core.Fmt.t_Debug (t_TryFromPrimitiveError v_Enum)

[@@ FStar.Tactics.Typeclasses.tcinstance]
val impl_2 (#v_Enum: Type0) {| i1: t_TryFromPrimitive v_Enum |}
    : Core.Fmt.t_Display (t_TryFromPrimitiveError v_Enum)

[@@ FStar.Tactics.Typeclasses.tcinstance]
val impl_3 (#v_Enum: Type0) {| i1: t_TryFromPrimitive v_Enum |}
    : Core.Error.t_Error (t_TryFromPrimitiveError v_Enum)
