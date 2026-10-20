module Rand.Rng
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open Core_models
open FStar.Mul

/// `rand` 0.9, the `Rng` extension trait.
/// <https://docs.rs/rand/0.9/rand/trait.Rng.html>
///
/// Used purely as a bound: every method has a default implementation and SPQR
/// calls none of them, reaching randomness through `RngCore::fill_bytes` in
/// [`Rand_core`] instead. The `RngCore` supertrait is not declared, which would
/// make `f_fill_bytes` resolvable through two paths.
class t_Rng (t: Type) = {
  dummy: unit
}
