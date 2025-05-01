module Prost.Encoding
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open Core
open FStar.Mul

type t_DecodeContext = { f_recurse_count:u32 }
