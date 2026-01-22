module Rand.Rng
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open Core_models
open FStar.Mul

class t_Rng (t: Type) = {
  dummy: unit
}
