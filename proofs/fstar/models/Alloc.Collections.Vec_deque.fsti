module Alloc.Collections.Vec_deque
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Rust_primitives

// Overlay hax-lib 0.3.7's incomplete VecDeque model.  It omits the constructor
// and update instance, and its index instance has an invalid unconditional
// precondition.
type t_VecDeque (v_T: Type0) (v_A: Type0) =
  | VecDeque : Rust_primitives.Sequence.t_Seq v_T -> Core_models.Marker.t_PhantomData v_A
    -> t_VecDeque v_T v_A

let impl_4__new (#v_T: Type0) (_: Prims.unit) : t_VecDeque v_T Alloc.Alloc.t_Global =
  VecDeque (Rust_primitives.Sequence.seq_empty #v_T ())
    (Core_models.Marker.PhantomData <: Core_models.Marker.t_PhantomData Alloc.Alloc.t_Global)
  <:
  t_VecDeque v_T Alloc.Alloc.t_Global

val impl_5__push_back (#v_T #v_A: Type0) (self: t_VecDeque v_T v_A) (x: v_T)
    : Prims.Pure (t_VecDeque v_T v_A) Prims.l_True (fun _ -> Prims.l_True)

val impl_5__len (#v_T #v_A: Type0) (self: t_VecDeque v_T v_A)
    : Prims.Pure usize Prims.l_True (fun _ -> Prims.l_True)

val impl_5__pop_front (#v_T #v_A: Type0) (self: t_VecDeque v_T v_A)
    : Prims.Pure (t_VecDeque v_T v_A & Core_models.Option.t_Option v_T)
      Prims.l_True
      (fun _ -> Prims.l_True)

// hax-lib 0.3.7 declares this precondition as true, but seq_index requires a
// valid index.  Expose the actual bound to callers and to the implementation.
[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_6 (#v_T #v_A: Type0) : Core_models.Ops.Index.t_Index (t_VecDeque v_T v_A) usize =
  {
    f_Output = v_T;
    f_index_pre =
      (fun (self: t_VecDeque v_T v_A) (i: usize) ->
        i <. Rust_primitives.Sequence.seq_len self._0);
    f_index_post = (fun (self: t_VecDeque v_T v_A) (i: usize) (out: v_T) -> true);
    f_index
    =
    fun (self: t_VecDeque v_T v_A) (i: usize) -> Rust_primitives.Sequence.seq_index #v_T self._0 i
  }

val update_at_index_default (#v_T #v_A: Type0)
    (self: t_VecDeque v_T v_A) (i: usize) : v_T

[@@ FStar.Tactics.Typeclasses.tcinstance]
let update_at_index (#v_T #v_A: Type0)
    : Core_models.Ops.Index.t_Index (t_VecDeque v_T v_A) usize =
  {
    f_Output = v_T;
    f_index_pre = (fun _ _ -> true);
    f_index_post = (fun _ _ _ -> true);
    // Mutation expressions resolve indexing through this inherited instance.
    // Totalize the out-of-bounds branch, while preserving real VecDeque reads
    // whenever the source-level hax assumption holds.
    f_index =
      (fun (self: t_VecDeque v_T v_A) (i: usize) ->
        if i <. Rust_primitives.Sequence.seq_len self._0
        then Rust_primitives.Sequence.seq_index #v_T self._0 i
        else update_at_index_default #v_T #v_A self i)
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let update_at_usize (#v_T #v_A: Type0)
    : Rust_primitives.Hax.update_at_tc (t_VecDeque v_T v_A) usize =
  {
    super_index = update_at_index #v_T #v_A;
    update_at =
      (fun (self: t_VecDeque v_T v_A) (i: usize) (x: v_T) ->
        if i <. Rust_primitives.Sequence.seq_len self._0
        then VecDeque (FStar.Seq.upd self._0 (v i) x) self._1
        else self)
  }
