/-
Copyright 2026 The Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE-APACHE.
Authors: Hoang Le Truong
-/
import SrcTranslated.Funs
import Spqr.Math.Gf16.Field
import Spqr.Specs.Encoding.Gf.Unaccelerated.PolyMul

/-! # Spec theorem for `spqr::encoding::gf::reduce::reduce_from_byte` — loop body


One call to the body with state `(a, out, i)` (where `i.val ≤ 8`) performs the following
computation:

  1. **Termination guard** — if `i = 0`, the loop is exhausted: return `done out` (the
     accumulated 32-bit XOR mask).
  2. **Active step** — if `i > 0`, let `i' = i − 1` (the *next* bit position to process,
     zero-indexed):
       a. Compute the bit-test mask `(1 : u8) << i'` and AND it with `a`.  This tests whether
          bit `i'` of `a` is set.
       b. **Bit set** (`(1 << i') & a ≠ 0`):
            - `poly_shifted = POLY << i'`  (`POLY = 0x1100b`).
            - `out' = out ⊕ poly_shifted`  (accumulate reduction).
            - `carry = ((poly_shifted >> 16) as u8)` (8-bit carry).
            - `a'  = a ⊕ carry`             (feed carry back into `a`).
            - Return `cont (a', out', i')`.
       c. **Bit not set** (`(1 << i') & a = 0`):
            - Return `cont (a, out, i')` (state unchanged, counter decremented).

The central invariant maintained by every step:
```
  reduceFromByteLoopSpec a'.val out'.val i'.val
    = reduceFromByteLoopSpec a.val out.val i.val
```
This is the one-step unfolding of `reduceFromByteLoopSpec`, which mirrors the Rust loop
structure exactly.

**Source**: spqr/src/encoding/gf.rs (lines 505:8–513:9)
-/

open Aeneas Aeneas.Std Result Polynomial spqr.encoding.gf.unaccelerated spqr.math.gf

namespace spqr.encoding.gf.reduce


/-- Spec-level high-to-low loop for `reduce_from_byte`.

Starting from byte `a`, accumulator `out`, and decrement counter `i`, processes bit positions
`i-1, i-2, …, 0` in that order (high to low), directly mirroring the Rust
`while i > 0 { i -= 1; … }` structure.

For each bit position `n` (from `i-1` down to `0`):
  - If bit `n` of the current `a` is set:
      • XOR `POLY << n` (= `0x1100b <<< n`) into `out`.
      • XOR `((POLY << n) >> 16)` — truncated to 8 bits via `% 256` to match the `as u8` cast in
        Rust — back into `a`.
  - Otherwise: leave `(a, out)` unchanged and continue.

The return value is the final `out` accumulator after all `i` steps.

Starting with `(a₀, 0, 8)` gives the full 32-bit return value of `reduce_from_byte(a₀)`:
  `reduce_from_byte_loop a₀ 0#u32 8#u32 = ok (reduceFromByteLoopSpec a₀.val 0 8)` -/
def reduceFromByteLoopSpec (a out : Nat) : (i : Nat) → Nat
  | 0     => out
  | i + 1 =>
    if a.testBit i then
      let poly_shifted := 0x1100b <<< i
      reduceFromByteLoopSpec ((a ^^^ (poly_shifted >>> 16)) % 256) (out ^^^ poly_shifted) i
    else
      reduceFromByteLoopSpec a out i


/-- One-step unfolding of `reduceFromByteLoopSpec` for the successor case.

`reduceFromByteLoopSpec a out (n + 1)` unfolds to a conditional on `a.testBit n`, which is
exactly the body computation:
  - **Bit set**: recurse with updated `a` and `out`.
  - **Bit not set**: recurse with unchanged `a` and `out`. -/
theorem reduce_from_byte_loop_body_spec1
    (a out n : Nat) :
    reduceFromByteLoopSpec a out (n + 1) =
    if a.testBit n then
      let poly_shifted := 0x1100b <<< n
      reduceFromByteLoopSpec ((a ^^^ (poly_shifted >>> 16)) % 256) (out ^^^ poly_shifted) n
    else
      reduceFromByteLoopSpec a out n := by
  rfl

private lemma and_shiftLeft_one_eq_zero_iff_testBit_false
    (a n : Nat) (hn : n ≤ 7) :
    (1 <<< n % 256 &&& a = 0) ↔ (a.testBit n = false) := by
  have hmod : 1 <<< n % 256 = 1 <<< n := by
    apply Nat.mod_eq_of_lt; interval_cases n <;> norm_num [Nat.one_shiftLeft]
  rw [hmod, Nat.one_shiftLeft, Nat.two_pow_and]
  simp only [mul_eq_zero]
  constructor
  · intro h
    rcases h with hp | ht
    · exact absurd hp (by positivity)
    · cases hb : a.testBit n <;> simp_all
  · intro h
    right
    simp [h]

private lemma nat_xor_lt {a b n : Nat} (ha : a < 2 ^ n) (hb : b < 2 ^ n) :
    a ^^^ b < 2 ^ n := by
  apply Nat.lt_of_testBit n
  · simp [Nat.testBit_xor, Nat.testBit_eq_false_of_lt ha, Nat.testBit_eq_false_of_lt hb]
  · rw [← Nat.one_shiftLeft, Nat.testBit_shiftLeft]
    simp
  · intro j hj
    have haj := Nat.testBit_eq_false_of_lt (lt_trans ha (Nat.pow_lt_pow_right (by norm_num) hj))
    have hbj := Nat.testBit_eq_false_of_lt (lt_trans hb (Nat.pow_lt_pow_right (by norm_num) hj))
    have h1lt : 1 < 2 ^ (j - n) := Nat.one_lt_pow (by omega) (by norm_num)
    simp [Nat.testBit_xor, haj, hbj, ← Nat.one_shiftLeft, Nat.testBit_shiftLeft,
          Nat.testBit_eq_false_of_lt h1lt, show n ≤ j from by omega]

/-- **Spec theorem for `encoding.gf.reduce.reduce_from_byte_loop.body`**:

• The function always succeeds (returns `ok`) for all inputs with `i.val ≤ 8`, since:
    - `(1 : u8) <<< i1` is valid for `i1 ≤ 7` (left shift of a u8 by at most 7 bits never
      overflows).
    - `POLY <<< i1` for `i1 ≤ 7` is at most `0x880580 < 2^24 < 2^32`, so the u32 shift never
      overflows.
    - `(u8)(i4 >>> 16)` for `i4 ≤ 0x880580` has the value `(0x1100b <<< i1) >>> 16 ≤ 0x88 < 256`,
      so the `UScalar.cast .U8` always succeeds.
    - `a ^^^ i6` stays within u8 arithmetic.
• The step is terminating: when `i.val > 0`, the returned `i'.val` satisfies
  `i'.val = i.val - 1 < i.val`, strictly decreasing the measure.  When `i.val = 0`, the loop
  returns `done`, ending iteration.
• **Loop invariant** — for every call with `i.val ≤ 8`:
    `reduceFromByteLoopSpec (result_a).val (result_out).val (result_i).val
       = reduceFromByteLoopSpec a.val out.val i.val`
-/
@[step]
theorem reduce_from_byte_loop_body_spec
    (a : Std.U8) (out : Std.U32) (i : Std.U32)
    (hi : i.val ≤ 8) :
    reduce_from_byte_loop.body a out i ⦃ cf =>
      match cf with
      | ControlFlow.done result =>
          i.val = 0 ∧ result.val = out.val
      | ControlFlow.cont (a', out', i') =>
          i.val > 0 ∧
          i'.val = i.val - 1 ∧
          reduceFromByteLoopSpec a'.val out'.val i'.val =
            reduceFromByteLoopSpec a.val out.val i.val ⦄ := by
  unfold reduce_from_byte_loop.body
  simp only [encoding.gf.POLY]
  by_cases hgt : i > 0#u32
  · simp only [hgt, ↓reduceIte]
    step*
    · constructor
      · scalar_tac
      · constructor
        · scalar_tac
        · simp_all only [gt_iff_lt, UScalar.lt_equiv, UScalar.ofNatCore_val_eq,
          UScalarTy.U8_numBits_eq, Bvify.U8.UScalar_bv, U8.ofNat_bv, UScalar.val_and,
          bne_iff_ne, ne_eq, UScalar.neq_to_neq_val, UScalarTy.U32_numBits_eq,
          Bvify.U32.UScalar_bv, U32.ofNat_bv, UScalar.val_xor, UScalar.cast_bv_eq]
          have : (i.val - 1) + 1 = i.val := by omega
          conv_rhs =>
            rw [← this, reduce_from_byte_loop_body_spec1]
          have h_bound : i.val - 1 ≤ 7 := by omega
          have h_tb : (a.val).testBit (i.val - 1) = true := by
            by_contra h_neg
            have hf : (a.val).testBit (i.val - 1) = false := by
              revert h_neg; cases (a.val).testBit (i.val - 1) <;> simp
            have := (and_shiftLeft_one_eq_zero_iff_testBit_false a.val (i.val - 1) h_bound).mpr hf
            simp only [Nat.shiftLeft_eq, one_mul] at this
            rw [← Nat.one_shiftLeft,
            show (256 : Nat) = U8.size from by simp [U8.size, U8.numBits]] at this
            exact absurd this ‹_›
          simp only [h_tb, ↓reduceIte]
          have h_poly_lt : 69643 <<< (i.val - 1) < U32.size := by
            interval_cases i.val <;> simp_all [U32.size, U32.numBits]
          have h_mod_u32 : 69643 <<< (i.val - 1) % U32.size = 69643 <<< (i.val - 1) :=
            Nat.mod_eq_of_lt h_poly_lt
          rw [h_mod_u32]
          have h_shr_lt : 69643 <<< (i.val - 1) >>> 16 < 256 := by
            interval_cases i.val <;> simp_all
          have h_cast : (UScalar.cast UScalarTy.U8 i5).val =
              69643 <<< (i.val - 1) >>> 16 := by
            rw [UScalar.cast_val_eq, i5_post1, h_mod_u32]
            exact Nat.mod_eq_of_lt (by
              simp only [UScalarTy.numBits, Nat.reducePow];
              exact h_shr_lt)
          rw [h_cast]
          congr 1
          symm
          apply Nat.mod_eq_of_lt
          rw [(by norm_num : 256 = 2 ^ 8)]
          apply nat_xor_lt
          · grind
          · grind
    · constructor
      · scalar_tac
      · simp_all only [gt_iff_lt, UScalar.lt_equiv, UScalar.ofNatCore_val_eq,
        UScalarTy.U8_numBits_eq, Bvify.U8.UScalar_bv, U8.ofNat_bv, UScalar.val_and,
        bne_iff_ne, ne_eq, UScalar.neq_to_neq_val, Decidable.not_not, true_and]
        have : (i.val - 1) + 1 = i.val := by omega
        conv_rhs =>
            rw [← this, reduce_from_byte_loop_body_spec1]
        have h_bound : i.val - 1 ≤ 7 := by omega
        have h_mask_zero : 1 <<< (i.val - 1) % U8.size &&& a.val = 0 := by assumption
        have h_tb : (a.val).testBit (i.val - 1) = false := by
          rw [show (U8.size : Nat) = 256 from by simp [U8.size, U8.numBits]] at h_mask_zero
          exact (and_shiftLeft_one_eq_zero_iff_testBit_false a.val
          (i.val - 1) h_bound).mp h_mask_zero
        simp [h_tb, ↓reduceIte]
  · simp only [show ¬(i > 0#u32) from hgt, ↓reduceIte]
    constructor
    · scalar_tac
    · rfl


/-! # Spec theorem for `spqr::encoding::gf::reduce::reduce_from_byte`

The function iterates over the 8 bits of `a` from bit 7 down to bit 0 (high to low).  For each
set bit `i`, it:
  1. XORs `POLY << i` into the 32-bit output accumulator `out`.
  2. Updates `a` by XOR-ing `((POLY << i) >> 16) as u8` into it, feeding the high-bit carry back
     into the lower bits of `a`.

The low 16 bits of the returned `u32` represent the canonical GF(2¹⁶) element obtained by
reducing `a · x¹⁶` modulo POLY:

  `(reduce_from_byte(a) as u16)  =  (a · X¹⁶) mod polyGF2`

This value is subsequently stored as `REDUCE_BYTES[a]` in the precomputed lookup table used by
`poly_reduce`.

**Source**: spqr/src/encoding/gf.rs (lines 502:4-515:5)
-/



/-- Spec-level table entry: the 16-bit reduction mask for byte `k`.

Given a byte value `k` (0 ≤ k < 256), `reduceByteTable k` is the 16-bit XOR mask obtained by the
high-to-low loop spec `reduceFromByteLoopSpec` (which matches the Rust `while i > 0` loop order)
retaining the low 16 bits of the 32-bit accumulator.

  `reduceByteTable k = reduceFromByteLoopSpec k 0 8 % 2 ^ 16`
-/
def reduceByteTable (k : Nat) : Nat :=
  reduceFromByteLoopSpec k 0 8 % 2 ^ 16

/-!
## Algebraic (GF(2)[X]) formulation of the reduction table

The following definition expresses `reduceByteTable` in terms of the polynomial ring
GF(2)[X] = BinaryPoly, making the algebraic structure explicit:
- Each byte `k` represents a polynomial of degree < 8 in GF(2)[X].
- `REDUCE_BYTES[k]` represents the remainder of `k · X¹⁶` divided by
  polyGF2 = X¹⁶ + X¹² + X³ + X + 1.
- The table entry is the canonical 16-bit representative of this remainder, which has degree
  < 16 since polyGF2 is monic of degree 16.
-/


/-- Spec-level polynomial table entry in BinaryPoly.

Given a polynomial `p ∈ GF(2)[X]` (representing a byte value of degree < 8),
`reduceByteTable_poly p` is the canonical remainder of `p * X¹⁶` modulo polyGF2:

  `reduceByteTable_poly p = (p * X ^ 16) %ₘ polyGF2` -/
noncomputable def reduceByteTable_poly (p : BinaryPoly) : BinaryPoly :=
  (p * X ^ 16) %ₘ polyGF2


/-- **Spec theorem for `encoding.gf.reduce.reduce_from_byte`**:

• The function always succeeds (no panic) for any `u8` input.
• The full 32-bit result satisfies:
    `(reduce_from_byte a).val  =  reduceFromByteLoopSpec a.val 0 8`
• The low 16 bits equal the precomputed table entry:
    `(reduce_from_byte a).val % 2^16  =  reduceByteTable a.val`
-/
@[step]
theorem reduce_from_byte_loop_spec
    (a : Std.U8) (out : Std.U32) (i : Std.U32)
    (hi : i.val ≤ 8) :
    reduce_from_byte_loop a out i ⦃ result =>
      result.val = reduceFromByteLoopSpec a.val out.val i.val ⦄ := by
  unfold reduce_from_byte_loop
  apply loop.spec_decr_nat
    (measure := fun (p : Std.U8 × Std.U32 × Std.U32) => p.2.2.val)
    (inv := fun (p : Std.U8 × Std.U32 × Std.U32) =>
      p.2.2.val ≤ 8 ∧
      reduceFromByteLoopSpec p.1.val p.2.1.val p.2.2.val =
        reduceFromByteLoopSpec a.val out.val i.val)
  · intro ⟨a', out', i'⟩ ⟨hi'_bound, hi'_spec⟩
    simp only []
    step*
    split
    · simp_all [reduceFromByteLoopSpec]
    · obtain ⟨h_gt, h_eq, h_spec⟩ := r_post
      simp_all
      grind
  · exact ⟨hi, rfl⟩

@[step]
theorem reduce_from_byte_spec (a : Std.U8) :
    reduce_from_byte a ⦃ result =>
      result.val % 2 ^ 16 = reduceByteTable a.val ⦄ := by
  unfold reduce_from_byte
  apply WP.spec_mono (reduce_from_byte_loop_spec a 0#u32 8#u32 (by scalar_tac))
  intro result hres
  simp [hres, reduceByteTable]

end spqr.encoding.gf.reduce
