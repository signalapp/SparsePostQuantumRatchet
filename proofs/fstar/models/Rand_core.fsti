module Rand_core
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open Core_models
open FStar.Mul

/// `rand_core` 0.9.
/// <https://docs.rs/rand_core/0.9/rand_core/>

/// `RngCore::fill_bytes(&mut self, dst: &mut [u8])` fills the whole of `dst`.
/// <https://docs.rs/rand_core/0.9/rand_core/trait.RngCore.html#tymethod.fill_bytes>
///
/// The postcondition states only that `dst`'s length is preserved; nothing is
/// assumed about the values written. Implementations may panic when they
/// cannot produce output; that is not modelled. `next_u32`/`next_u64` are not
/// referenced and are not declared.
class t_RngCore (v_Self: Type0) = {
  f_fill_bytes_pre:self_: v_Self -> dst: t_Slice u8 -> pred: Type0{true ==> pred};
  f_fill_bytes_post:self_: v_Self -> dst: t_Slice u8 -> x: (v_Self & t_Slice u8)
    -> pred:
      Type0
        { pred ==>
          (let (self_e_future: v_Self), (dst_future: t_Slice u8) = x in
            (Core_models.Slice.impl__len #u8 dst_future <: usize) =.
            (Core_models.Slice.impl__len #u8 dst <: usize)) };
  f_fill_bytes:x0: v_Self -> x1: t_Slice u8
    -> Prims.Pure (v_Self & t_Slice u8)
        (f_fill_bytes_pre x0 x1)
        (fun result -> f_fill_bytes_post x0 x1 result)
}

/// `CryptoRng`, a marker subtrait of `RngCore` asserting cryptographic quality.
/// <https://docs.rs/rand_core/0.9/rand_core/trait.CryptoRng.html>
///
/// Declares no methods of its own.
class t_CryptoRng (v_Self: Type0) = {
  [@@@ FStar.Tactics.Typeclasses.no_method]_super_i0:t_RngCore v_Self
}

[@@ FStar.Tactics.Typeclasses.tcinstance]
let _ = fun (v_Self: Type0) {| i: t_CryptoRng v_Self |} -> i._super_i0
