module Spec.GF16
open Core

(** Boolean Operations **)

let bool_xor (x:bool) (y:bool) : bool = 
  match (x,y) with
  | (true, true) -> false
  | (false, false) -> false
  | (true, false) -> true
  | (false, true) -> true

let bool_or (x:bool) (y:bool) : bool = x || y

let bool_and (x:bool) (y:bool) : bool = x && y

let bool_not (x:bool) : bool = not x

(** Sequence Operations **)

(* The basic definition of a sequence as equivalent to a map function *)
assume val createi #a (len:nat) (f: (i:nat{i < len}) -> a)
  : x:Seq.seq a{Seq.length x == len /\ (forall i. Seq.index x i == f i)}

let (.[]) #a (x:Seq.seq a) (i:nat{i < Seq.length x}) = Seq.index x i

let map2 #a #b #c (f: a -> b -> c) (x: Seq.seq a) (y: Seq.seq b{Seq.length x == Seq.length y})
  : r:Seq.seq c{Seq.length r == Seq.length x} = 
  createi (Seq.length x) (fun i -> f x.[i] y.[i])

(** Bit Vectors **)

type bv (n:nat) = x:Seq.seq bool{Seq.length x == n}

let zero (#n:nat) : bv n = createi n (fun i -> false)

let lift (#n:nat) (x: bv n) (k:nat{k >= n}) : bv k =
  createi k (fun i -> if i < n then x.[i] else false)
  
let lower1 (#n:pos) (x: bv n{x.[n-1] = false}) : bv (n-1) =
  createi (n-1) (fun i -> x.[i])

let rec lower (#n:nat) (x: bv n) (k:nat{k <= n /\ (forall j. (j >= k /\ j < n) ==> x.[j] = false)}) : bv k =
    if n = k then x
    else lower (lower1 x) k
  
let bv_eq_intro #n (x y: bv n) :
  Lemma (requires (forall (i:nat). i < n ==> x.[i] = y.[i]))
        (ensures x == y) =
  Seq.lemma_eq_intro x y

(** Galois Field Arithmetic **)

(* Addition and Subtraction *)

let max i j = if i < j then j else i

let gf_add #n #m (x: bv n) (y: bv m) : bv (max n m) = 
  map2 bool_xor (lift x (max n m)) (lift y (max n m))

let gf_sub #n #m (x: bv n) (y: bv m) : bv (max n m) = 
  gf_add x y

let lemma_add_zero (#n:nat) (x: bv n):
  Lemma (gf_add x (zero #n) == x /\ gf_add (zero #n) x == x) =
    bv_eq_intro (gf_add x (zero #n)) x;
    bv_eq_intro (gf_add (zero #n) x) x

let lemma_add_lift (#n:nat) (#k:nat{k >= n}) (x: bv n) (y:bv k):
  Lemma (gf_add x y == gf_add (lift x k) y /\
         gf_add y x == gf_add y (lift x k)) =
    bv_eq_intro (gf_add x y) (gf_add (lift x k) y);
    bv_eq_intro (gf_add y x) (gf_add y (lift x k))

(* Polynomial (carry-less) Multiplication *)

let poly_mul_x_k #n (x: bv n) (k:nat) : bv (n+k) = 
  createi (n+k) (fun i -> if i < k then false else x.[i-k])

let rec poly_mul_i #n (x: bv n) (y: bv n) (i: nat{i <= n}) 
  : Tot (bv (n+n)) (decreases i) =
  if i = 0 then zero #(n+n)
  else
    let prev = poly_mul_i x y (i-1) in
    if y.[i-1] then
       gf_add prev (poly_mul_x_k x (i-1))
    else prev

let poly_mul #n (x y: bv n) : bv (n+n) =
  poly_mul_i x y n

(* Galois Field Assumptions *)

class galois_field = {
      n: nat;
      norm: #k:nat -> bv k -> bv n;
      irred: p:bv (n+1){p.[n] /\ norm p == zero #n};
      lemma_norm_lower1: #m:pos -> (x: bv m) -> Lemma(x.[m-1] = false ==> norm x == norm (lower1 x));
      lemma_norm_lift: (#m:nat{m <= n}) -> (x: bv m) -> Lemma(norm x == lift x n);
      lemma_norm_add: (#m: nat) -> (#o: nat) -> (x: bv m) -> (y: bv o) -> Lemma(norm (gf_add x y) = gf_add (norm x) (norm y));
      lemma_norm_mul_x_k: (#m: nat) -> (x: bv m) -> (k:nat) -> Lemma(norm (poly_mul_x_k x k) == norm (poly_mul_x_k (norm x) k));
}

(* Reduction *)

assume val poly_reduce (#gf: galois_field) (#m:nat) (x:bv m)
           : y:bv n{y == norm x}

let gf_mul (#gf: galois_field) (x:bv n) (y: bv n) : bv n =
  poly_reduce (poly_mul x y)
  
(* Lemmas *)
let rec lemma_norm_zero (#gf: galois_field) (k:nat):
  Lemma (gf.norm (zero #k) == zero #gf.n) = 
    if k <= gf.n then (
      gf.lemma_norm_lift (zero #k);
      bv_eq_intro (lift (zero #k) n) (zero #n))
    else (
      assert (k > 0);
      let zero_k_minus_1 = lower1 (zero #k) in
      gf.lemma_norm_lower1 (zero #k);
      lemma_norm_zero #gf (k-1);
      bv_eq_intro (lower1 (zero #k)) (zero #(k-1))
    )

let lemma_norm_irred_mul_x_k (#gf: galois_field) (k:nat):
  Lemma (gf.norm (poly_mul_x_k irred k) == zero #gf.n) = 
    lemma_norm_mul_x_k irred k;
    bv_eq_intro (poly_mul_x_k zero k) (zero #(n+k));
    lemma_norm_zero #gf (n+k)

let rec lemma_norm_lower (#gf: galois_field) (m:nat) (x:bv m):
  Lemma 
    (requires (m >= gf.n /\ (forall j. (j >= n /\ j < m) ==> x.[j] = false)))
    (ensures (gf.norm (lower x n) == gf.norm x)) =
    if n = m then ()
    else (
      lemma_norm_lower1 x;
      lemma_norm_lower #gf (m-1) (lower1 x)
    )

(** Integers as Bit Vectors **)

(* Mappings between machine integers and int ops to bit vectors *)

assume val to_bv #t (u: int_t t) : bv (bits t)
// Concretely: to_bv u -> createi (bits t) (fun i -> (v u / pow2 i) % 2 = 0)

(* Axioms about integer operations *)

assume val zero_lemma #t:
  Lemma (to_bv ( mk_int #t 0 ) == zero #(bits t))

assume val xor_lemma #t (x: int_t t) (y: int_t t):
  Lemma (to_bv ( x  ^. y) == map2 bool_xor (to_bv x) (to_bv y))

assume val or_lemma #t (x: int_t t) (y: int_t t):
  Lemma (to_bv ( x  |. y) == map2 bool_or (to_bv x) (to_bv y))

assume val and_lemma #t (x: int_t t) (y: int_t t):
  Lemma (to_bv ( x  &. y) == map2 bool_and (to_bv x) (to_bv y))

assume val shift_left_lemma #t #t' (x: int_t t) (y: int_t t'):
  Lemma 
    (requires (v y >= 0 /\ v y < bits t))
    (ensures to_bv ( x  <<! y) ==
             createi (bits t) (fun i -> if i < v y then false else (to_bv x).[i - v y]))

assume val up_cast_lemma #t (#t':inttype{bits t' >= bits t}) (x:int_t t):
  Lemma (to_bv (cast (x <: int_t t) <: int_t t') == lift (to_bv x) (bits t'))


(* Lemmas lining integer arithmetic to bit-vector operations *)

assume val shift_left_bit_select_lemma #t #t' (x: int_t t) (i: int_t t'{v i >= 0 /\ v i < bits t}):
  Lemma (((x &. (mk_int #t 1 <<! i)) == mk_int #t 0) <==> 
         ((to_bv x).[v i] == false))

(* GF16 Lemmas *)

assume val up_cast_shift_left_lemma (x: u16) (shift: u32{v shift < 16}):
  Lemma (to_bv ((cast x <: u32) <<! shift) ==
         lift (poly_mul_x_k (to_bv x) (v shift)) 32)

let xor_is_gf_add_lemma #t (x y: int_t t):
    Lemma (to_bv (x ^. y) == gf_add (to_bv x) (to_bv y)) =
    xor_lemma x y;
    bv_eq_intro (to_bv (x ^. y)) (gf_add (to_bv x) (to_bv y))


(* GF16 Implementation *)

instance gf16: galois_field = {
  n = 16;
  irred = to_bv (mk_i16 0x1100b);
  norm = admit();
  lemma_norm_lower1 = (fun x -> admit());
  lemma_norm_lift = (fun x -> admit());
  lemma_norm_add = (fun x -> fun y -> admit());
  lemma_norm_mul_x_k = (fun x -> fun k -> admit())
}

let gf16_mul = gf_mul #gf16

(*
let rec clmul_aux #n1 #n2 (x: bv n1) (y: bv n2) (i: nat{i <= n2}): 
  Tot (bv (n1+n2)) (decreases (n2 - i)) =
  if i = n2 then zero
  else 
    let next = clmul_aux x y (i+1) in
    if y.[i] then
      add (mul_x_k x i) next
    else next
 *)
  

  
(*  
    bv_intro (add x (zero #n)) x;
    bv_intro (add (zero #n) x) x
*)
