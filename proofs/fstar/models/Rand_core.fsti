module Rand_core
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Rust_primitives

// hax-lib 0.3.7 gives the safe RngCore methods arbitrary preconditions and
// postconditions.  Model their actual Rust contract: they are always callable,
// and fill_bytes preserves the length of the supplied buffer.
class t_RngCore (v_Self: Type0) = {
  f_next_u32:x0: v_Self
    -> Prims.Pure (v_Self & u32) Prims.l_True (fun _ -> Prims.l_True);
  f_next_u64:x0: v_Self
    -> Prims.Pure (v_Self & u64) Prims.l_True (fun _ -> Prims.l_True);
  f_fill_bytes:x0: v_Self -> x1: t_Slice u8
    -> Prims.Pure (v_Self & t_Slice u8)
        Prims.l_True
        (fun result ->
          let _, x1' = result in
          Seq.length x1' == Seq.length x1)
}

class t_CryptoRng (v_Self: Type0) = {
  [@@@ FStar.Tactics.Typeclasses.no_method]_super_i0:t_RngCore v_Self
}

[@@ FStar.Tactics.Typeclasses.tcinstance]
let _ = fun (v_Self:Type0) {|i: t_CryptoRng v_Self|} -> i._super_i0
