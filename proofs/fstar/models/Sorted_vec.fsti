module Sorted_vec
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open Core
open FStar.Mul

/// Forward sorted vector
type t_SortedVec (v_T: Type0) {| i1: Core.Cmp.t_Ord v_T |} = {
  f_vec:Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global
}

[@@ FStar.Tactics.Typeclasses.tcinstance]
val impl_18 (#v_T: Type0) {| i1: Core.Clone.t_Clone v_T |} {| i2: Core.Cmp.t_Ord v_T |}
    : Core.Clone.t_Clone (t_SortedVec v_T)

[@@ FStar.Tactics.Typeclasses.tcinstance]
val impl_19 (#v_T: Type0) {| i1: Core.Fmt.t_Debug v_T |} {| i2: Core.Cmp.t_Ord v_T |}
    : Core.Fmt.t_Debug (t_SortedVec v_T)

[@@ FStar.Tactics.Typeclasses.tcinstance]
val impl_22 (#v_T: Type0) {| i1: Core.Cmp.t_Ord v_T |}
    : Core.Marker.t_StructuralPartialEq (t_SortedVec v_T)

[@@ FStar.Tactics.Typeclasses.tcinstance]
val impl_23 (#v_T: Type0) {| i1: Core.Cmp.t_PartialEq v_T v_T |} {| i2: Core.Cmp.t_Ord v_T |}
    : Core.Cmp.t_PartialEq (t_SortedVec v_T) (t_SortedVec v_T)

[@@ FStar.Tactics.Typeclasses.tcinstance]
val impl_20 (#v_T: Type0) {| i1: Core.Cmp.t_Eq v_T |} {| i2: Core.Cmp.t_Ord v_T |}
    : Core.Cmp.t_Eq (t_SortedVec v_T)

[@@ FStar.Tactics.Typeclasses.tcinstance]
val impl_24 (#v_T: Type0) {| i1: Core.Cmp.t_PartialOrd v_T v_T |} {| i2: Core.Cmp.t_Ord v_T |}
    : Core.Cmp.t_PartialOrd (t_SortedVec v_T) (t_SortedVec v_T)

[@@ FStar.Tactics.Typeclasses.tcinstance]
val impl_21 (#v_T: Type0) {| i1: Core.Cmp.t_Ord v_T |} : Core.Cmp.t_Ord (t_SortedVec v_T)

/// Forward sorted set
type t_SortedSet (v_T: Type0) {| i1: Core.Cmp.t_Ord v_T |} = { f_set:t_SortedVec v_T }

[@@ FStar.Tactics.Typeclasses.tcinstance]
val impl_25 (#v_T: Type0) {| i1: Core.Clone.t_Clone v_T |} {| i2: Core.Cmp.t_Ord v_T |}
    : Core.Clone.t_Clone (t_SortedSet v_T)

[@@ FStar.Tactics.Typeclasses.tcinstance]
val impl_26 (#v_T: Type0) {| i1: Core.Fmt.t_Debug v_T |} {| i2: Core.Cmp.t_Ord v_T |}
    : Core.Fmt.t_Debug (t_SortedSet v_T)

[@@ FStar.Tactics.Typeclasses.tcinstance]
val impl_29 (#v_T: Type0) {| i1: Core.Cmp.t_Ord v_T |}
    : Core.Marker.t_StructuralPartialEq (t_SortedSet v_T)

[@@ FStar.Tactics.Typeclasses.tcinstance]
val impl_30 (#v_T: Type0) {| i1: Core.Cmp.t_PartialEq v_T v_T |} {| i2: Core.Cmp.t_Ord v_T |}
    : Core.Cmp.t_PartialEq (t_SortedSet v_T) (t_SortedSet v_T)

[@@ FStar.Tactics.Typeclasses.tcinstance]
val impl_27 (#v_T: Type0) {| i1: Core.Cmp.t_Eq v_T |} {| i2: Core.Cmp.t_Ord v_T |}
    : Core.Cmp.t_Eq (t_SortedSet v_T)

[@@ FStar.Tactics.Typeclasses.tcinstance]
val impl_31 (#v_T: Type0) {| i1: Core.Cmp.t_PartialOrd v_T v_T |} {| i2: Core.Cmp.t_Ord v_T |}
    : Core.Cmp.t_PartialOrd (t_SortedSet v_T) (t_SortedSet v_T)

[@@ FStar.Tactics.Typeclasses.tcinstance]
val impl_28 (#v_T: Type0) {| i1: Core.Cmp.t_Ord v_T |} : Core.Cmp.t_Ord (t_SortedSet v_T)

/// Value returned when find_or_insert is used.
type t_FindOrInsert =
  | FindOrInsert_Found : usize -> t_FindOrInsert
  | FindOrInsert_Inserted : usize -> t_FindOrInsert

[@@ FStar.Tactics.Typeclasses.tcinstance]
val impl_32:Core.Marker.t_StructuralPartialEq t_FindOrInsert

[@@ FStar.Tactics.Typeclasses.tcinstance]
val impl_33:Core.Cmp.t_PartialEq t_FindOrInsert t_FindOrInsert

[@@ FStar.Tactics.Typeclasses.tcinstance]
val impl_34:Core.Cmp.t_PartialOrd t_FindOrInsert t_FindOrInsert

[@@ FStar.Tactics.Typeclasses.tcinstance]
val impl_35:Core.Cmp.t_Eq t_FindOrInsert

[@@ FStar.Tactics.Typeclasses.tcinstance]
val impl_36:Core.Cmp.t_Ord t_FindOrInsert

[@@ FStar.Tactics.Typeclasses.tcinstance]
val impl_37:Core.Fmt.t_Debug t_FindOrInsert

(* [@@ FStar.Tactics.Typeclasses.tcinstance]
val impl_38:Core.Hash.t_Hash t_FindOrInsert *)

/// Converts from the binary_search result type into the FindOrInsert type
[@@ FStar.Tactics.Typeclasses.tcinstance]
val impl:Core.Convert.t_From t_FindOrInsert (Core.Result.t_Result usize usize)

/// Get the index of the element that was either found or inserted.
val impl_FindOrInsert__index (self: t_FindOrInsert)
    : Prims.Pure usize Prims.l_True (fun _ -> Prims.l_True)

/// If an equivalent element was found in the container, get the value of
/// its index. Otherwise get None.
val impl_FindOrInsert__found (self: t_FindOrInsert)
    : Prims.Pure (Core.Option.t_Option usize) Prims.l_True (fun _ -> Prims.l_True)

/// If the provided element was inserted into the container, get the value
/// of its index. Otherwise get None.
val impl_FindOrInsert__inserted (self: t_FindOrInsert)
    : Prims.Pure (Core.Option.t_Option usize) Prims.l_True (fun _ -> Prims.l_True)

/// Returns true if the element was found.
val impl_FindOrInsert__is_found (self: t_FindOrInsert)
    : Prims.Pure bool Prims.l_True (fun _ -> Prims.l_True)

/// Returns true if the element was inserted.
val impl_FindOrInsert__is_inserted (self: t_FindOrInsert)
    : Prims.Pure bool Prims.l_True (fun _ -> Prims.l_True)

val impl_2__new: #v_T: Type0 -> {| i1: Core.Cmp.t_Ord v_T |} -> Prims.unit
  -> Prims.Pure (t_SortedVec v_T) Prims.l_True (fun _ -> Prims.l_True)

val impl_2__with_capacity (#v_T: Type0) {| i1: Core.Cmp.t_Ord v_T |} (capacity: usize)
    : Prims.Pure (t_SortedVec v_T) Prims.l_True (fun _ -> Prims.l_True)

/// Uses `sort_unstable()` to sort in place.
val impl_2__from_unsorted
      (#v_T: Type0)
      {| i1: Core.Cmp.t_Ord v_T |}
      (vec: Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global)
    : Prims.Pure (t_SortedVec v_T) Prims.l_True (fun _ -> Prims.l_True)

/// Insert an element into sorted position, returning the order index at which
/// it was placed.
val impl_2__insert (#v_T: Type0) {| i1: Core.Cmp.t_Ord v_T |} (self: t_SortedVec v_T) (element: v_T)
    : Prims.Pure (t_SortedVec v_T & usize) Prims.l_True (fun _ -> Prims.l_True)

/// Find the element and return the index with `Ok`, otherwise insert the
/// element and return the new element index with `Err`.
val impl_2__find_or_insert
      (#v_T: Type0)
      {| i1: Core.Cmp.t_Ord v_T |}
      (self: t_SortedVec v_T)
      (element: v_T)
    : Prims.Pure (t_SortedVec v_T & t_FindOrInsert) Prims.l_True (fun _ -> Prims.l_True)

/// Same as insert, except performance is O(1) when the element belongs at the
/// back of the container. This avoids an O(log(N)) search for inserting
/// elements at the back.
val impl_2__push (#v_T: Type0) {| i1: Core.Cmp.t_Ord v_T |} (self: t_SortedVec v_T) (element: v_T)
    : Prims.Pure (t_SortedVec v_T & usize) Prims.l_True (fun _ -> Prims.l_True)

/// Reserves additional capacity in the underlying vector.
/// See std::vec::Vec::reserve.
val impl_2__reserve
      (#v_T: Type0)
      {| i1: Core.Cmp.t_Ord v_T |}
      (self: t_SortedVec v_T)
      (additional: usize)
    : Prims.Pure (t_SortedVec v_T) Prims.l_True (fun _ -> Prims.l_True)

/// Same as find_or_insert, except performance is O(1) when the element
/// belongs at the back of the container.
val impl_2__find_or_push
      (#v_T: Type0)
      {| i1: Core.Cmp.t_Ord v_T |}
      (self: t_SortedVec v_T)
      (element: v_T)
    : Prims.Pure (t_SortedVec v_T & t_FindOrInsert) Prims.l_True (fun _ -> Prims.l_True)

val impl_2__remove_item
      (#v_T: Type0)
      {| i1: Core.Cmp.t_Ord v_T |}
      (self: t_SortedVec v_T)
      (item: v_T)
    : Prims.Pure (t_SortedVec v_T & Core.Option.t_Option v_T) Prims.l_True (fun _ -> Prims.l_True)

/// Panics if index is out of bounds
val impl_2__remove_index
      (#v_T: Type0)
      {| i1: Core.Cmp.t_Ord v_T |}
      (self: t_SortedVec v_T)
      (index: usize)
    : Prims.Pure (t_SortedVec v_T & v_T) Prims.l_True (fun _ -> Prims.l_True)

val impl_2__pop (#v_T: Type0) {| i1: Core.Cmp.t_Ord v_T |} (self: t_SortedVec v_T)
    : Prims.Pure (t_SortedVec v_T & Core.Option.t_Option v_T) Prims.l_True (fun _ -> Prims.l_True)

val impl_2__clear (#v_T: Type0) {| i1: Core.Cmp.t_Ord v_T |} (self: t_SortedVec v_T)
    : Prims.Pure (t_SortedVec v_T) Prims.l_True (fun _ -> Prims.l_True)

val impl_2__dedup (#v_T: Type0) {| i1: Core.Cmp.t_Ord v_T |} (self: t_SortedVec v_T)
    : Prims.Pure (t_SortedVec v_T) Prims.l_True (fun _ -> Prims.l_True)

(* item error backend: (DirectAndMut) The mutation of this [1m&mut[0m is not allowed here.
Last available AST for this item:

#[_hax::json("\"Erased\"")]
#[inline()]
#[feature(register_tool)]
#[register_tool(_hax)]
fn impl_2__dedup_by_key<Anonymous: 'unk, T, F, K>(
    mut self: sorted_vec::t_SortedVec<T>,
    key: F,
) -> tuple0
where
    _: core::cmp::t_Ord<T>,
    _: core::ops::function::t_FnMut<F, tuple1<&mut T>>,
    F: core::ops::function::t_FnOnce<f_Output = K>,
    _: core::cmp::t_PartialEq<K, K>,
{
    {
        let _: tuple0 = { rust_primitives::hax::dropped_body };
        self
    }
}


Last AST:
/** print_rust: pitem: not implemented  (item: { Concrete_ident.T.def_id =
  { Explicit_def_id.T.is_constructor = false;
    def_id =
    { Types.index = (0, 0); is_local = true; kind = Types.AssocFn;
      krate = "sorted_vec";
      parent =
      (Some { Types.contents =
              { Types.id = 0;
                value =
                { Types.index = (0, 0); is_local = true;
                  kind = Types.Impl {of_trait = false}; krate = "sorted_vec";
                  parent =
                  (Some { Types.contents =
                          { Types.id = 0;
                            value =
                            { Types.index = (0, 0); is_local = true;
                              kind = Types.Mod; krate = "sorted_vec";
                              parent = None; path = [] }
                            }
                          });
                  path = [{ Types.data = Types.Impl; disambiguator = 2 }] }
                }
              });
      path =
      [{ Types.data = Types.Impl; disambiguator = 2 };
        { Types.data = (Types.ValueNs "dedup_by_key"); disambiguator = 0 }]
      }
    };
  moved = None; suffix = None }) */
const _: () = ();
 *)

(* val impl_2__drain
      (#v_T #v_R: Type0)
      {| i1: Core.Cmp.t_Ord v_T |}
      {| i7: Core.Ops.Range.t_RangeBounds v_R usize |}
      (self: t_SortedVec v_T)
      (range: v_R)
    : Prims.Pure (t_SortedVec v_T & Alloc.Vec.Drain.t_Drain v_T Alloc.Alloc.t_Global)
      Prims.l_True
      (fun _ -> Prims.l_True) *)

(* val impl_2__retain
      (#v_T #v_F: Type0)
      {| i1: Core.Cmp.t_Ord v_T |}
      {| i8: Core.Ops.Function.t_FnMut v_F v_T |}
      (self: t_SortedVec v_T)
      (f: v_F)
    : Prims.Pure (t_SortedVec v_T) Prims.l_True (fun _ -> Prims.l_True) *)

/// NOTE: to_vec() is a slice method that is accessible through deref, use
/// this instead to avoid cloning
val impl_2__into_vec (#v_T: Type0) {| i1: Core.Cmp.t_Ord v_T |} (self: t_SortedVec v_T)
    : Prims.Pure (Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global) Prims.l_True (fun _ -> Prims.l_True)

(* item error backend: (DirectAndMut) The mutation of this [1m&mut[0m is not allowed here.
Last available AST for this item:

#[_hax::json("\"Erased\"")]
/// Apply a closure mutating the sorted vector and use `sort_unstable()`
/// to re-sort the mutated vector
#[feature(register_tool)]
#[register_tool(_hax)]
fn impl_2__mutate_vec<Anonymous: 'unk, T, F, O>(
    mut self: sorted_vec::t_SortedVec<T>,
    f: F,
) -> O
where
    _: core::cmp::t_Ord<T>,
    _: core::ops::function::t_FnOnce<
        F,
        tuple1<&mut alloc::vec::t_Vec<T, alloc::alloc::t_Global>>,
    >,
    F: core::ops::function::t_FnOnce<f_Output = O>,
{
    {
        let hax_temp_output: O = { rust_primitives::hax::dropped_body };
        Tuple2(self, hax_temp_output)
    }
}


Last AST:
/** print_rust: pitem: not implemented  (item: { Concrete_ident.T.def_id =
  { Explicit_def_id.T.is_constructor = false;
    def_id =
    { Types.index = (0, 0); is_local = true; kind = Types.AssocFn;
      krate = "sorted_vec";
      parent =
      (Some { Types.contents =
              { Types.id = 0;
                value =
                { Types.index = (0, 0); is_local = true;
                  kind = Types.Impl {of_trait = false}; krate = "sorted_vec";
                  parent =
                  (Some { Types.contents =
                          { Types.id = 0;
                            value =
                            { Types.index = (0, 0); is_local = true;
                              kind = Types.Mod; krate = "sorted_vec";
                              parent = None; path = [] }
                            }
                          });
                  path = [{ Types.data = Types.Impl; disambiguator = 2 }] }
                }
              });
      path =
      [{ Types.data = Types.Impl; disambiguator = 2 };
        { Types.data = (Types.ValueNs "mutate_vec"); disambiguator = 0 }]
      }
    };
  moved = None; suffix = None }) */
const _: () = ();
 *)

/// The caller must ensure that the provided vector is already sorted.
val impl_2__from_sorted
      (#v_T: Type0)
      {| i1: Core.Cmp.t_Ord v_T |}
      (vec: Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global)
    : Prims.Pure (t_SortedVec v_T) Prims.l_True (fun _ -> Prims.l_True)

/// Unsafe access to the underlying vector. The caller must ensure that any
/// changes to the values in the vector do not impact the ordering of the
/// elements inside, or else this container will misbehave.
(* val impl_2__get_unchecked_mut_vec (#v_T: Type0) {| i1: Core.Cmp.t_Ord v_T |} (self: t_SortedVec v_T)
    : Prims.Pure Rust_primitives.Hax.failure Prims.l_True (fun _ -> Prims.l_True) *)

[@@ FStar.Tactics.Typeclasses.tcinstance]
val impl_3 (#v_T: Type0) {| i1: Core.Cmp.t_Ord v_T |} : Core.Default.t_Default (t_SortedVec v_T)

[@@ FStar.Tactics.Typeclasses.tcinstance]
val impl_4 (#v_T: Type0) {| i1: Core.Cmp.t_Ord v_T |}
    : Core.Convert.t_From (t_SortedVec v_T) (Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global)

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_5 (#v_T: Type0) (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Core.Cmp.t_Ord v_T)
    : Core.Ops.Deref.t_Deref (t_SortedVec v_T) =
  {
    f_Target = Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global;(* 
    f_deref_pre = (fun (self: t_SortedVec v_T) -> true);
    f_deref_post
    =
    (fun (self: t_SortedVec v_T) (out: Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global) -> true); *)
    f_deref = fun (self: t_SortedVec v_T) -> self.f_vec
  }

(* [@@ FStar.Tactics.Typeclasses.tcinstance]
val impl_6 (#v_T: Type0) {| i1: Core.Cmp.t_Ord v_T |}
    : Core.Iter.Traits.Collect.t_Extend (t_SortedVec v_T) v_T *)

(* [@@ FStar.Tactics.Typeclasses.tcinstance]
val impl_7 (#v_T: Type0) {| i1: Core.Cmp.t_Ord v_T |} {| i2: Core.Hash.t_Hash v_T |}
    : Core.Hash.t_Hash (t_SortedVec v_T) *)

val impl_10__new: #v_T: Type0 -> {| i1: Core.Cmp.t_Ord v_T |} -> Prims.unit
  -> Prims.Pure (t_SortedSet v_T) Prims.l_True (fun _ -> Prims.l_True)

val impl_10__with_capacity (#v_T: Type0) {| i1: Core.Cmp.t_Ord v_T |} (capacity: usize)
    : Prims.Pure (t_SortedSet v_T) Prims.l_True (fun _ -> Prims.l_True)

/// Uses `sort_unstable()` to sort in place and `dedup()` to remove
/// duplicates.
val impl_10__from_unsorted
      (#v_T: Type0)
      {| i1: Core.Cmp.t_Ord v_T |}
      (vec: Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global)
    : Prims.Pure (t_SortedSet v_T) Prims.l_True (fun _ -> Prims.l_True)

/// Insert an element into sorted position, returning the order index at which
/// it was placed. If an existing item was found it will be returned.
val impl_10__replace
      (#v_T: Type0)
      {| i1: Core.Cmp.t_Ord v_T |}
      (self: t_SortedSet v_T)
      (element: v_T)
    : Prims.Pure (t_SortedSet v_T & (usize & Core.Option.t_Option v_T))
      Prims.l_True
      (fun _ -> Prims.l_True)

/// Find the element and return the index with `Ok`, otherwise insert the
/// element and return the new element index with `Err`.
val impl_10__find_or_insert
      (#v_T: Type0)
      {| i1: Core.Cmp.t_Ord v_T |}
      (self: t_SortedSet v_T)
      (element: v_T)
    : Prims.Pure (t_SortedSet v_T & t_FindOrInsert) Prims.l_True (fun _ -> Prims.l_True)

/// Same as replace, except performance is O(1) when the element belongs at
/// the back of the container. This avoids an O(log(N)) search for inserting
/// elements at the back.
val impl_10__push (#v_T: Type0) {| i1: Core.Cmp.t_Ord v_T |} (self: t_SortedSet v_T) (element: v_T)
    : Prims.Pure (t_SortedSet v_T & (usize & Core.Option.t_Option v_T))
      Prims.l_True
      (fun _ -> Prims.l_True)

/// Reserves additional capacity in the underlying vector.
/// See std::vec::Vec::reserve.
val impl_10__reserve
      (#v_T: Type0)
      {| i1: Core.Cmp.t_Ord v_T |}
      (self: t_SortedSet v_T)
      (additional: usize)
    : Prims.Pure (t_SortedSet v_T) Prims.l_True (fun _ -> Prims.l_True)

/// Same as find_or_insert, except performance is O(1) when the element
/// belongs at the back of the container.
val impl_10__find_or_push
      (#v_T: Type0)
      {| i1: Core.Cmp.t_Ord v_T |}
      (self: t_SortedSet v_T)
      (element: v_T)
    : Prims.Pure (t_SortedSet v_T & t_FindOrInsert) Prims.l_True (fun _ -> Prims.l_True)

val impl_10__remove_item
      (#v_T: Type0)
      {| i1: Core.Cmp.t_Ord v_T |}
      (self: t_SortedSet v_T)
      (item: v_T)
    : Prims.Pure (t_SortedSet v_T & Core.Option.t_Option v_T) Prims.l_True (fun _ -> Prims.l_True)

/// Panics if index is out of bounds
val impl_10__remove_index
      (#v_T: Type0)
      {| i1: Core.Cmp.t_Ord v_T |}
      (self: t_SortedSet v_T)
      (index: usize)
    : Prims.Pure (t_SortedSet v_T & v_T) Prims.l_True (fun _ -> Prims.l_True)

val impl_10__pop (#v_T: Type0) {| i1: Core.Cmp.t_Ord v_T |} (self: t_SortedSet v_T)
    : Prims.Pure (t_SortedSet v_T & Core.Option.t_Option v_T) Prims.l_True (fun _ -> Prims.l_True)

val impl_10__clear (#v_T: Type0) {| i1: Core.Cmp.t_Ord v_T |} (self: t_SortedSet v_T)
    : Prims.Pure (t_SortedSet v_T) Prims.l_True (fun _ -> Prims.l_True)

(* val impl_10__drain
      (#v_T #v_R: Type0)
      {| i1: Core.Cmp.t_Ord v_T |}
      {| i3: Core.Ops.Range.t_RangeBounds v_R usize |}
      (self: t_SortedSet v_T)
      (range: v_R)
    : Prims.Pure (t_SortedSet v_T & Alloc.Vec.Drain.t_Drain v_T Alloc.Alloc.t_Global)
      Prims.l_True
      (fun _ -> Prims.l_True) *)

(* val impl_10__retain
      (#v_T #v_F: Type0)
      {| i1: Core.Cmp.t_Ord v_T |}
      {| i5: Core.Ops.Function.t_FnMut v_F v_T |}
      (self: t_SortedSet v_T)
      (f: v_F)
    : Prims.Pure (t_SortedSet v_T) Prims.l_True (fun _ -> Prims.l_True) *)

/// NOTE: to_vec() is a slice method that is accessible through deref, use
/// this instead to avoid cloning
val impl_10__into_vec (#v_T: Type0) {| i1: Core.Cmp.t_Ord v_T |} (self: t_SortedSet v_T)
    : Prims.Pure (Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global) Prims.l_True (fun _ -> Prims.l_True)

(* item error backend: (DirectAndMut) The mutation of this [1m&mut[0m is not allowed here.
Last available AST for this item:

#[_hax::json("\"Erased\"")]
/// Apply a closure mutating the sorted vector and use `sort_unstable()`
/// to re-sort the mutated vector and `dedup()` to remove any duplicate
/// values
#[feature(register_tool)]
#[register_tool(_hax)]
fn impl_10__mutate_vec<Anonymous: 'unk, T, F, O>(
    mut self: sorted_vec::t_SortedSet<T>,
    f: F,
) -> O
where
    _: core::cmp::t_Ord<T>,
    _: core::ops::function::t_FnOnce<
        F,
        tuple1<&mut alloc::vec::t_Vec<T, alloc::alloc::t_Global>>,
    >,
    F: core::ops::function::t_FnOnce<f_Output = O>,
{
    {
        let hax_temp_output: O = { rust_primitives::hax::dropped_body };
        Tuple2(self, hax_temp_output)
    }
}


Last AST:
/** print_rust: pitem: not implemented  (item: { Concrete_ident.T.def_id =
  { Explicit_def_id.T.is_constructor = false;
    def_id =
    { Types.index = (0, 0); is_local = true; kind = Types.AssocFn;
      krate = "sorted_vec";
      parent =
      (Some { Types.contents =
              { Types.id = 0;
                value =
                { Types.index = (0, 0); is_local = true;
                  kind = Types.Impl {of_trait = false}; krate = "sorted_vec";
                  parent =
                  (Some { Types.contents =
                          { Types.id = 0;
                            value =
                            { Types.index = (0, 0); is_local = true;
                              kind = Types.Mod; krate = "sorted_vec";
                              parent = None; path = [] }
                            }
                          });
                  path = [{ Types.data = Types.Impl; disambiguator = 10 }] }
                }
              });
      path =
      [{ Types.data = Types.Impl; disambiguator = 10 };
        { Types.data = (Types.ValueNs "mutate_vec"); disambiguator = 0 }]
      }
    };
  moved = None; suffix = None }) */
const _: () = ();
 *)

/// The caller must ensure that the provided vector is already sorted and
/// deduped.
val impl_10__from_sorted
      (#v_T: Type0)
      {| i1: Core.Cmp.t_Ord v_T |}
      (vec: Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global)
    : Prims.Pure (t_SortedSet v_T) Prims.l_True (fun _ -> Prims.l_True)

/// Unsafe access to the underlying vector. The caller must ensure that any
/// changes to the values in the vector do not impact the ordering of the
/// elements inside, or else this container will misbehave.
(* val impl_10__get_unchecked_mut_vec
      (#v_T: Type0)
      {| i1: Core.Cmp.t_Ord v_T |}
      (self: t_SortedSet v_T)
    : Prims.Pure Rust_primitives.Hax.failure Prims.l_True (fun _ -> Prims.l_True) *)

[@@ FStar.Tactics.Typeclasses.tcinstance]
val impl_11 (#v_T: Type0) {| i1: Core.Cmp.t_Ord v_T |} : Core.Default.t_Default (t_SortedSet v_T)

[@@ FStar.Tactics.Typeclasses.tcinstance]
val impl_12 (#v_T: Type0) {| i1: Core.Cmp.t_Ord v_T |}
    : Core.Convert.t_From (t_SortedSet v_T) (Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global)

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_13 (#v_T: Type0) (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Core.Cmp.t_Ord v_T)
    : Core.Ops.Deref.t_Deref (t_SortedSet v_T) =
  {
    f_Target = t_SortedVec v_T;
    (* f_deref_pre = (fun (self: t_SortedSet v_T) -> true);
    f_deref_post = (fun (self: t_SortedSet v_T) (out: t_SortedVec v_T) -> true); *)
    f_deref = fun (self: t_SortedSet v_T) -> self.f_set
  }

(* [@@ FStar.Tactics.Typeclasses.tcinstance]
val impl_14 (#v_T: Type0) {| i1: Core.Cmp.t_Ord v_T |}
    : Core.Iter.Traits.Collect.t_Extend (t_SortedSet v_T) v_T *)

(* [@@ FStar.Tactics.Typeclasses.tcinstance]
val impl_15 (#v_T: Type0) {| i1: Core.Cmp.t_Ord v_T |} {| i2: Core.Hash.t_Hash v_T |}
    : Core.Hash.t_Hash (t_SortedSet v_T) *)

(* [@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_8 (#v_T: Type0) (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Core.Cmp.t_Ord v_T)
    : Core.Iter.Traits.Collect.t_IntoIterator (t_SortedVec v_T) =
  {
    f_Item = v_T;
    f_IntoIter = Alloc.Vec.Into_iter.t_IntoIter v_T Alloc.Alloc.t_Global;
    f_IntoIter_8492263130362933403 = FStar.Tactics.Typeclasses.solve;
    f_into_iter_pre = (fun (self: t_SortedVec v_T) -> true);
    f_into_iter_post
    =
    (fun (self: t_SortedVec v_T) (out: Alloc.Vec.Into_iter.t_IntoIter v_T Alloc.Alloc.t_Global) ->
        true);
    f_into_iter
    =
    fun (self: t_SortedVec v_T) ->
      Core.Iter.Traits.Collect.f_into_iter #(Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global)
        #FStar.Tactics.Typeclasses.solve
        self.f_vec
  } *)

(* [@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_9 (#v_T: Type0) (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Core.Cmp.t_Ord v_T)
    : Core.Iter.Traits.Collect.t_IntoIterator (t_SortedVec v_T) =
  {
    f_Item = v_T;
    f_IntoIter = Core.Slice.Iter.t_Iter v_T;
    f_IntoIter_8492263130362933403 = FStar.Tactics.Typeclasses.solve;
    f_into_iter_pre = (fun (self: t_SortedVec v_T) -> true);
    f_into_iter_post = (fun (self: t_SortedVec v_T) (out: Core.Slice.Iter.t_Iter v_T) -> true);
    f_into_iter
    =
    fun (self: t_SortedVec v_T) ->
      Core.Slice.impl__iter #v_T
        (Core.Ops.Deref.f_deref #(Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global)
            #FStar.Tactics.Typeclasses.solve
            self.f_vec
          <:
          t_Slice v_T)
  } *)

(* [@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_17 (#v_T: Type0) (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Core.Cmp.t_Ord v_T)
    : Core.Iter.Traits.Collect.t_IntoIterator (t_SortedSet v_T) =
  {
    f_Item = v_T;
    f_IntoIter = Core.Slice.Iter.t_Iter v_T;
    f_IntoIter_8492263130362933403 = FStar.Tactics.Typeclasses.solve;
    f_into_iter_pre = (fun (self: t_SortedSet v_T) -> true);
    f_into_iter_post = (fun (self: t_SortedSet v_T) (out: Core.Slice.Iter.t_Iter v_T) -> true);
    f_into_iter
    =
    fun (self: t_SortedSet v_T) ->
      Core.Slice.impl__iter #v_T
        (Core.Ops.Deref.f_deref #(Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global)
            #FStar.Tactics.Typeclasses.solve
            (Core.Ops.Deref.f_deref #(t_SortedVec v_T) #FStar.Tactics.Typeclasses.solve self.f_set
              <:
              Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global)
          <:
          t_Slice v_T)
  } *)

(* [@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_16 (#v_T: Type0) (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Core.Cmp.t_Ord v_T)
    : Core.Iter.Traits.Collect.t_IntoIterator (t_SortedSet v_T) =
  {
    f_Item = v_T;
    f_IntoIter = Alloc.Vec.Into_iter.t_IntoIter v_T Alloc.Alloc.t_Global;
    f_IntoIter_8492263130362933403 = FStar.Tactics.Typeclasses.solve;
    f_into_iter_pre = (fun (self: t_SortedSet v_T) -> true);
    f_into_iter_post
    =
    (fun (self: t_SortedSet v_T) (out: Alloc.Vec.Into_iter.t_IntoIter v_T Alloc.Alloc.t_Global) ->
        true);
    f_into_iter
    =
    fun (self: t_SortedSet v_T) ->
      Core.Iter.Traits.Collect.f_into_iter #(t_SortedVec v_T)
        #FStar.Tactics.Typeclasses.solve
        self.f_set
  } *)
