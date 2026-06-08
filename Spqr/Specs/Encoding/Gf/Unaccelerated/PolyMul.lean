/-
Copyright 2026 The Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE-APACHE.
Authors: Hoang Le Truong
-/
import Spqr.Code.Funs
import Spqr.Math.Gf16.Field

/-! # Spec theorem for `spqr::encoding::gf::unaccelerated::poly_mul`

In GF(2¹⁶) — the Galois field with 65 536 elements — multiplication begins with carry-less
polynomial multiplication: given two polynomials of degree < 16 (represented as 16-bit
integers), their product is a polynomial of degree ≤ 30, which fits in a 32-bit integer.

The function proceeds by long multiplication over GF(2):
  1. Cast `a` to `u32` (`me`).
  2. Initialise the accumulator `acc = 0` and loop `shift` from 0 to 15.
  3. For each `shift`, if bit `shift` of `b` is set, XOR `me << shift` into `acc`.
  4. Return `acc` — the unreduced 32-bit polynomial product.

The result is an unreduced 32-bit product; to obtain a GF(2¹⁶) element, it must subsequently be
reduced modulo the irreducible polynomial POLY = x¹⁶ + x¹² + x³ + x + 1 (0x1100b) via
`poly_reduce`.

The core polynomial-library definitions and lemmas (`natToBinaryPoly`, `polyGF2`, and the basic
coefficient/XOR/shift identities) are now gathered once in `Spqr.Math.Gf`; this file imports
them rather than re-proving them.

**Source**: spqr/src/encoding/gf.rs (lines 381:4-427:5)
-/

open Aeneas Aeneas.Std Result
open Polynomial
open spqr.math.gf
namespace spqr.encoding.gf.unaccelerated

/-- Spec-level carry-less (XOR-based) polynomial multiplication.

Computes the GF(2) polynomial product of `a` and `b` by iterating over the first `n` bit
positions of `b`, accumulating `a <<< i` (XOR'd) for each set bit `i < n`.  This is the pure
recursive definition corresponding to the loop in `poly_mul`. -/
def clmul (a b : Nat) : (n : Nat) → Nat
  | 0     => 0
  | n + 1 =>
    let acc := clmul a b n
    if b.testBit n then acc ^^^ (a <<< n) else acc

/-!
## Algebraic (GF(2)[X]) formulation of carry-less multiplication

The following definition expresses `clmul` in terms of the polynomial ring GF(2)[X] = BinaryPoly,
making the algebraic structure explicit:
- XOR (`^^^`) becomes polynomial addition (`+`) over GF(2)
- Shift-left by n (`<<< n`) becomes multiplication by `X ^ n`
- `Nat.testBit n` becomes checking if the n-th coefficient is nonzero

The final GF(2¹⁶) product is obtained by reducing the polynomial product modulo the irreducible
polynomial
  POLY = X¹⁶ + X¹² + X³ + X + 1   (0x1100b).
-/

/-- Carry-less multiplication in the polynomial ring BinaryPoly.

    This is the algebraic equivalent of `clmul` on `Nat`:
    - XOR becomes polynomial addition over GF(2)
    - Left-shift by `n` becomes multiplication by `X ^ n`
    - `testBit n` becomes checking if `coeff b n ≠ 0`

    Morally, `clmul_poly a b n = a * (b mod X^n)` in BinaryPoly. -/
noncomputable def clmul_poly (a b : BinaryPoly) : (n : Nat) → BinaryPoly
  | 0     => 0
  | n + 1 =>
    let acc := clmul_poly a b n
    if b.coeff n ≠ 0 then acc + a * X ^ n else acc

/-- **Correspondence between `clmul` on `Nat` and `clmul_poly` on GF(2)[X]**:

    Interpreting the natural-number inputs as GF(2) polynomials via `natToBinaryPoly`, the
    `Nat`-level `clmul` and the algebraic `clmul_poly` agree:

      `natToBinaryPoly (clmul a b n) = clmul_poly (natToBinaryPoly a) (natToBinaryPoly b) n`

    This justifies reasoning about the XOR/shift implementation in terms of polynomial algebra
    over GF(2). -/
theorem clmul_eq_clmul_poly (a b n : Nat) :
    natToBinaryPoly (clmul a b n) =
      clmul_poly (natToBinaryPoly a) (natToBinaryPoly b) n := by
  induction n with
  | zero => simp [clmul, clmul_poly, natToBinaryPoly_zero]
  | succ n ih =>
    cases htb : b.testBit n with
    | false =>
      have hcoeff : (natToBinaryPoly b).coeff n = 0 := by
        rw [natToBinaryPoly_coeff]; simp [htb]
      have h1 : clmul a b (n + 1) = clmul a b n := by
        simp (config := { zeta := true }) [clmul, htb]
      rw [h1, ih]; symm
      simp (config := { zeta := true }) [clmul_poly, hcoeff]
    | true =>
      have hcoeff : (natToBinaryPoly b).coeff n ≠ 0 := by
        rw [natToBinaryPoly_coeff]; simp [htb]
      have h1 : clmul a b (n + 1) = clmul a b n ^^^ (a <<< n) := by
        simp (config := { zeta := true }) [clmul, htb]
      rw [h1, natToBinaryPoly_xor, natToBinaryPoly_shiftLeft, ih]; symm
      simp (config := { zeta := true }) [clmul_poly, hcoeff]


private lemma clmul_poly_b_zero (a : BinaryPoly) : ∀ n, clmul_poly a 0 n = 0
  | 0 => rfl
  | n + 1 => by dsimp [clmul_poly]; simp [clmul_poly_b_zero a n]

private lemma clmul_poly_coeff_eq (a b c : BinaryPoly) :
    ∀ n, (∀ i, i < n → b.coeff i = c.coeff i) → clmul_poly a b n = clmul_poly a c n
  | 0, _ => rfl
  | n + 1, h => by
      dsimp [clmul_poly]
      rw [clmul_poly_coeff_eq a b c n (fun i hi => h i (by omega)), h n (by omega)]

/-- **`clmul_poly` computes polynomial multiplication**:

    For any polynomials `a, b ∈ GF(2)[X]` with `natDegree b < n`, iterating `clmul_poly` for `n`
    steps yields the full product:

      `clmul_poly a b n = a * b`   (when `natDegree b < n`)

    In particular, for 16-bit inputs (degree < 16):
      `clmul_poly a b 16 = a * b` -/
theorem clmul_poly_eq_mul (a b : BinaryPoly) (n : Nat)
    (hb : b.natDegree < n) :
    clmul_poly a b n = a * b := by
  induction n generalizing b with
  | zero => omega
  | succ n ih =>
    dsimp [clmul_poly]
    by_cases hcoeff : b.coeff n ≠ 0
    · rw [if_pos hcoeff]
      have hc1 : b.coeff n = 1 := by
        have hlt := (b.coeff n).isLt
        have hne : (b.coeff n).val ≠ 0 := fun h => hcoeff (Fin.ext h)
        have hval : (b.coeff n).val = 1 := by grind
        exact Fin.ext hval
      have hind : clmul_poly a b n = clmul_poly a (b - X ^ n) n :=
        clmul_poly_coeff_eq a b (b - X ^ n) n fun i hi => by
          have : i ≠ n := by omega
          simp [coeff_sub, coeff_X_pow, this]
      rw [hind]
      rcases eq_or_ne (b - X ^ n) 0 with hzero | hne
      · rw [hzero, clmul_poly_b_zero, zero_add, sub_eq_zero.mp hzero]
      · have hdeg : (b - X ^ n).natDegree < n := by
          by_contra hge; push Not at hge
          have hlc := leadingCoeff_ne_zero.mpr hne
          unfold leadingCoeff at hlc
          have : (b - X ^ n).coeff (b - X ^ n).natDegree = 0 := by
            simp only [coeff_sub, coeff_X_pow]
            rcases eq_or_lt_of_le hge with heq | hgt
            · simp only [heq.symm, ite_true]; rw [hc1, sub_self]
            · simp only [show (b - X ^ n).natDegree ≠ n from by omega, ite_false, sub_zero]
              exact coeff_eq_zero_of_natDegree_lt (by omega)
          exact hlc this
        rw [ih (b - X ^ n) hdeg]; ring
    · rw [if_neg hcoeff]; push Not at hcoeff
      rcases eq_or_ne b 0 with rfl | hb0
      · simp [clmul_poly_b_zero]
      · have hlt : b.natDegree < n := by
          have hle := Nat.lt_succ_iff.mp hb
          have : b.natDegree ≠ n := by
            intro heq
            have := leadingCoeff_ne_zero.mpr hb0
            unfold leadingCoeff at this; rw [heq] at this
            exact this hcoeff
          omega
        exact ih b hlt

lemma degree_lt (a : U16) :
  (natToBinaryPoly a).natDegree < 16 := by
  rcases eq_or_ne (natToBinaryPoly (a : Nat)) 0 with h | h
  · simp [h]
  · rw [natDegree_lt_iff_degree_lt h, degree_lt_iff_coeff_zero]
    intro m hm
    rw [natToBinaryPoly_coeff]
    simp [Nat.testBit_eq_false_of_lt (calc
      (a : Nat) < 2 ^ 16 := by scalar_tac
      _ ≤ 2 ^ m := Nat.pow_le_pow_right (by omega) hm)]

lemma poly_u16_eq_u32 (a : U16) (me : U32) (h : me = UScalar.cast UScalarTy.U32 a) :
  (natToBinaryPoly a) =(natToBinaryPoly me)  := by
  congr 1
  subst h
  exact (UScalar.cast_val_mod_pow_greater_numBits_eq UScalarTy.U32 a (by simp)).symm

private theorem testBit_of_and_one_shiftLeft_ne_zero {n k : Nat}
    (h : n &&& (1 <<< k) ≠ 0) : n.testBit k = true := by
  rw [Nat.one_shiftLeft] at h
  cases htb : n.testBit k with
  | true => rfl
  | false =>
    exfalso; exact h (Nat.eq_of_testBit_eq fun i => by
      simp only [Nat.testBit_and, Nat.testBit_two_pow, Nat.zero_testBit]
      by_cases hi : k = i <;> simp_all)

private theorem and_one_shiftLeft_eq_zero_of_not_testBit {n k : Nat}
    (h : n.testBit k = false) : n &&& (1 <<< k) = 0 := by
  rw [Nat.one_shiftLeft]
  exact Nat.eq_of_testBit_eq fun i => by
    simp only [Nat.testBit_and, Nat.testBit_two_pow, Nat.zero_testBit]
    by_cases hi : k = i <;> simp_all

private theorem not_testBit_of_and_one_shiftLeft_eq_zero {n k : Nat}
    (h : n &&& (1 <<< k) = 0) : n.testBit k = false := by
  rw [Nat.one_shiftLeft] at h
  cases htb : n.testBit k with
  | false => rfl
  | true =>
    exfalso
    have : (n &&& 2 ^ k).testBit k = true := by
      simp [Nat.testBit_and,  htb]
    rw [h] at this
    simp at this


/-- **Postcondition theorem for `encoding.gf.unaccelerated.poly_mul_loop`**:

Carry-less (XOR-based) polynomial multiplication loop, the inner loop of `poly_mul`.  Starting
from accumulator `acc` at bit position `shift`, the loop iterates through bit positions `shift`
to 15 of `b`, XOR-ing `me <<< i` into the accumulator for each set bit `i`.

The loop body (extracted from Rust source lines 394:8-425:9) performs:
  1. If `shift < 16`: test bit `shift` of `b` via `b & (1 << shift)`; if set, XOR `me << shift`
     into `acc`; increment `shift`; continue.
  2. If `shift ≥ 16`: return `acc` (loop terminates).

Given the loop invariant preconditions — `shift ≤ 16`, `acc = clmul me b shift`, and
`me < 2^16` (since `me` is a cast of a `u16`) — the loop always succeeds and returns a `u32`
whose value equals the full spec-level carry-less product `clmul me.val b.val 16`.


**Source**: spqr/src/encoding/gf.rs (lines 394:8-425:9)
-/
@[step]
theorem poly_mul_loop_spec (b : Std.U16) (acc : Std.U32) (me : Std.U32)
    (shift : Std.U32)
    (h_shift : shift.val ≤ 16)
    (h_me : me.val < 2 ^ 16)
    (h_inv : acc.val = clmul me.val b.val shift.val) :
    poly_mul_loop b acc me shift ⦃ result =>
      result.val = clmul me.val b.val 16 ⦄ := by
  unfold poly_mul_loop
  apply loop.spec_decr_nat
    (measure := fun (p : Std.U32 × Std.U32) => 16 - p.2.val)
    (inv := fun (p : Std.U32 × Std.U32) =>
      p.2.val ≤ 16 ∧ p.1.val = clmul me.val b.val p.2.val ∧
        me.val < 2 ^ 16)
  · intro ⟨acc', shift'⟩ ⟨hShift', hInv', hMe'⟩
    simp only []
    unfold poly_mul_loop.body
    -- simp only []
    by_cases hLt : shift'.val < 16
    · simp only [UScalar.lt_equiv, UScalar.ofNatCore_val_eq, hLt,
      ↓reduceIte, bne_iff_ne, ne_eq, UScalar.neq_to_neq_val,
      ReduceNat.reduceNatEq, ite_not, Nat.reducePow, and_assoc]
      step*
      split
      · step*
        · have : b.val.testBit shift'.val = False := by
            have hmod : 1 <<< shift'.val % U16.size = 1 <<< shift'.val :=
              Nat.mod_eq_of_lt (by
                rw [Nat.one_shiftLeft, show U16.size = 2 ^ 16 from by simp [U16.size, U16.numBits]]
                exact Nat.pow_lt_pow_right (by omega) hLt)
            have h := not_testBit_of_and_one_shiftLeft_eq_zero
              (n := b.val) (k := shift'.val) (by rw [← hmod]; simp_all)
            simp [h]
          constructor
          · grind
          · constructor
            · simp [shift1_post, clmul, this]
              simp_all
            · grind
      · step*
        have : b.val.testBit shift'.val = True := by
          have hmod : 1 <<< shift'.val % U16.size = 1 <<< shift'.val :=
            Nat.mod_eq_of_lt (by
              rw [Nat.one_shiftLeft, show U16.size = 2 ^ 16 from by simp [U16.size, U16.numBits]]
              exact Nat.pow_lt_pow_right (by omega) hLt)
          have h := testBit_of_and_one_shiftLeft_ne_zero
            (n := b.val) (k := shift'.val) (by rw [← hmod]; simp_all)
          simp [h]
        constructor
        · grind
        · constructor
          · simp only [UScalar.val_xor, shift1_post, clmul, this, ↓reduceIte]
            simp_all only [Nat.reducePow, UScalarTy.U16_numBits_eq, Bvify.U16.UScalar_bv,
            U16.ofNat_bv, UScalar.val_and, UScalarTy.U32_numBits_eq, Bvify.U32.UScalar_bv,
            eq_iff_iff, iff_true, Nat.xor_right_inj]
            apply Nat.mod_eq_of_lt
            simp only [Nat.shiftLeft_eq]
            have : 2 ^ shift'.val ≤ 2 ^ 16 :=
              (Nat.pow_le_pow_iff_right (by omega : 1 < 2)).mpr hShift'
            have : me.val * 2 ^ shift'.val < 65536 * 2 ^16 := by grind
            scalar_tac
          · grind
    · have hEq : shift'.val = 16 := by grind
      have hNotLt : ¬ (shift' < 16#u32) := by scalar_tac
      simp only [hNotLt, ↓reduceIte]
      simp_all
  · exact ⟨h_shift, h_inv, h_me⟩

/-- **Postcondition theorem for `encoding.gf.unaccelerated.poly_mul`**:

Carry-less (XOR-based) polynomial multiplication of two `u16` values, producing a `u32` result
representing the unreduced GF(2) polynomial product.

The function casts `a` to `u32`, then delegates to `poly_mul_loop` with initial accumulator
`acc = 0` and shift counter `shift = 0`.  The result equals the spec-level carry-less product
`clmul a.val b.val 16`.

**Source**: spqr/src/encoding/gf.rs (lines 381:4-427:5)
-/
theorem poly_mul_spec' (a b : Std.U16) :
    poly_mul a b ⦃ result =>
      result.val = clmul a.val b.val 16 ⦄ := by
  unfold poly_mul
  step*
  simp[clmul]

@[step]
theorem poly_mul_spec (a b : Std.U16) :
    poly_mul a b ⦃ result =>
      natToBinaryPoly result.val = natToBinaryPoly a.val * natToBinaryPoly b.val ⦄ := by
  unfold poly_mul
  step*
  · simp only [UScalar.ofNatCore_val_eq, clmul]
  rw[result_post, clmul_eq_clmul_poly,
  clmul_poly_eq_mul (natToBinaryPoly me.val) (natToBinaryPoly b.val) 16 (degree_lt b)]
  simp only [me_post, UScalarTy.U16_numBits_eq, UScalarTy.U32_numBits_eq, Nat.reduceLeDiff,
    UScalar.cast_val_mod_pow_greater_numBits_eq, poly_u16_eq_u32]

end spqr.encoding.gf.unaccelerated
