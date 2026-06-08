/-
Copyright 2026 The Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE-APACHE.
Authors: Hoang Le Truong
-/
import Spqr.Math.Gf16.Field
import Spqr.Specs.Encoding.Gf.Reduce.ReduceBytes

/-!
**Spec theorem for `spqr::encoding::gf::reduce::poly_reduce`**:

Given a natural number `v` (representing a polynomial in GF(2)[X] via its binary expansion),
reduces it modulo `polyGF2 = X¹⁶ + X¹² + X³ + X + 1` (0x1100b) using the precomputed
`REDUCE_BYTES` table, yielding the canonical degree-< 16 representative in GF(2¹⁶).

The reduction processes the input byte-by-byte from high to low:
  1. Extract bits 24–31 (`v >>> 24`), look up `reduceByteTable`, XOR the shifted result back:
     `v₁ := v ⊕ (reduceByteTable(v >> 24) << 8)`.
  2. Extract bits 16–23 (`(v₁ >>> 16) &&& 0xFF`), look up `reduceByteTable`, XOR result back:
     `result := (v₁ ⊕ reduceByteTable((v₁ >> 16) & 0xFF)) mod 2¹⁶`.
  3. Return the remaining 16 bits.

Each table lookup replaces a degree-≥ 16 contribution with its residue modulo `polyGF2`:
  `reduceByteTable(k)` satisfies
    `natToBinaryPoly (reduceByteTable k) = (natToBinaryPoly k * X¹⁶) %ₘ polyGF2`
so XOR-ing the table entry effectively subtracts the high byte's contribution modulo `polyGF2`.

### Algebraic context

This definition is the **optimised (table-based)** counterpart of the iterative bit-by-bit
reduction `polyMod_poly`, which processes one coefficient at a time:

  `polyMod_poly p 0     = p`
  `polyMod_poly p (n+1) = if (polyMod_poly p n).coeff (n+16) ≠ 0`
  `                        then polyMod_poly p n + polyGF2 * X^n`
  `                        else polyMod_poly p n`

The key algebraic properties of `polyMod_poly` that justify this reduction are:

  1. **Nat ↔ Poly correspondence** (`polyMod_eq_polyMod_poly`):
     `natToBinaryPoly (polyMod v n) = polyMod_poly (natToBinaryPoly v) n`
     — the XOR/shift implementation on `Nat` agrees with the algebraic formulation on GF(2)[X].

  2. **Congruence preservation** (`polyMod_poly_dvd_sub`):
     `polyGF2 ∣ (p − polyMod_poly p n)`
     — each step adds a multiple of `polyGF2`, so the result is always congruent to `p`.

  3. **Modular equivalence** (`polyMod_poly_eq_modByMonic`):
     `(polyMod_poly p n) %ₘ polyGF2 = p %ₘ polyGF2`
     — the partially-reduced polynomial has the same residue as `p` modulo `polyGF2`.

Note: because `polyGF2` has a sub-leading term `X¹²` (degree gap of only 4), reducing a
coefficient at position `k + 16` (for `k ≥ 4`) re-introduces a coefficient at position
`k + 12 ≥ 16` that has already been processed. Hence the iterative `polyMod_poly` may not be
fully reduced after a single pass. The table-based `polyReduce` handles this by processing full
bytes (8 bits at a time) through the precomputed table, which accounts for all carry
propagation within each byte.

### `polyReduce_eq`

The main theorem `polyReduce_eq` establishes:
  `natToBinaryPoly (polyReduce v) = (natToBinaryPoly v) %ₘ polyGF2`
for all `v < 2³²`, confirming that the table-lookup implementation computes the canonical
degree-< 16 representative modulo `polyGF2`.

### Connection to GF(2¹⁶) multiplication

The combined specification for `mul(a, b) = poly_reduce(poly_mul(a, b))` follows from:

  1. `poly_mul_spec`:
     `natToBinaryPoly (poly_mul a b).val = natToBinaryPoly a.val * natToBinaryPoly b.val`

  2. `poly_reduce_spec` (proved via `polyReduce_eq`):
     `natToBinaryPoly (poly_reduce v).val = (natToBinaryPoly v.val) %ₘ polyGF2`

Together (`poly_reduce_spec_poly_mul`):
  `natToBinaryPoly (mul a b).val
     = (natToBinaryPoly a.val * natToBinaryPoly b.val) %ₘ polyGF2`

This is exactly multiplication in the quotient ring `GF(2¹⁶) ≅ GF(2)[X] / (polyGF2)`.

The remaining bridge to `GaloisField 2 16` (Mathlib's abstract construction) requires
an explicit isomorphism `GaloisField 2 16 ≅ (ZMod 2)[X] / (polyGF2)`, showing that `polyGF2`
is irreducible over GF(2), and connecting the natural-number ↔ polynomial ↔ quotient-ring chain.
This algebraic bridge is developed in `Spqr.Math.Gf16.Field` and used by `Mul.lean`.

**Source**: spqr/src/encoding/gf.rs (lines 489:4-498:5)
-/

open Aeneas Aeneas.Std Result Polynomial spqr.encoding.gf.unaccelerated spqr.math.gf

namespace spqr.encoding.gf.reduce

/-- Reduce a 32-bit value modulo the GF(2^16) irreducible polynomial using the lookup table. -/
def polyReduce (v : Nat) : Nat :=
  let t1 := reduceByteTable (v >>> 24)
  let v1 := v ^^^ (t1 <<< 8)
  let t2 := reduceByteTable ((v1 >>> 16) &&& 255)
  (v1 ^^^ t2) % 2 ^ 16

private lemma nat_and_255_lt_256 (n : Nat) : n &&& 255 < 256 := by
  have : (255 : Nat) = 2 ^ 8 - 1 := by norm_num
  rw [this, Nat.and_two_pow_sub_one_eq_mod]
  exact Nat.mod_lt _ (by norm_num)


theorem xor_table_shift_dvd (k n : Nat)
    (htable : natToBinaryPoly (reduceByteTable k) =
      (natToBinaryPoly k * X ^ 16) %ₘ polyGF2) :
    polyGF2 ∣ (natToBinaryPoly k * X ^ (n + 16) +
      natToBinaryPoly (reduceByteTable k) * X ^ n) := by
  rw [show natToBinaryPoly k * X ^ (n + 16) + natToBinaryPoly (reduceByteTable k) * X ^ n =
    (natToBinaryPoly k * X ^ 16 + natToBinaryPoly (reduceByteTable k)) * X ^ n from by ring,
    htable]
  apply dvd_mul_of_dvd_left
  have h := polyGF2_dvd_modByMonic_sub (natToBinaryPoly k * X ^ 16)
  rwa [BinaryPoly.sub_eq_add, add_comm] at h

theorem polyReduce_eq (v : Nat) (hv : v < 2 ^ 32)
    (htable : ∀ k, k < 256 → natToBinaryPoly (reduceByteTable k) =
      (natToBinaryPoly k * X ^ 16) %ₘ polyGF2) :
    natToBinaryPoly (polyReduce v) = (natToBinaryPoly v) %ₘ polyGF2 := by
  have hk1_lt : v >>> 24 < 256 := by omega
  have ht1_lt : reduceByteTable (v >>> 24) < 2 ^ 16 := by
    unfold reduceByteTable
    grind
  unfold polyReduce
  set k1 := v >>> 24 with hk1_def
  set t1 := reduceByteTable k1 with ht1_def
  set v1 := v ^^^ (t1 <<< 8) with hv1_def
  set k2 := (v1 >>> 16) &&& 255 with hk2_def
  set t2 := reduceByteTable k2 with ht2_def
  have hk2_lt : k2 < 256 := nat_and_255_lt_256 _
  have ht2_lt : t2 < 2 ^ 16 := by
    rw [ht2_def]
    unfold reduceByteTable
    exact Nat.mod_lt _ (by positivity)
  have hhigh : (v1 ^^^ t2) >>> 16 = k2 ^^^ (k1 <<< 8) := by
    apply Nat.eq_of_testBit_eq
    intro i
    have ht2_high : ∀ j, 16 ≤ j → t2.testBit j = false := fun j hj =>
      Nat.testBit_eq_false_of_lt
        (lt_of_lt_of_le ht2_lt (Nat.pow_le_pow_right (by norm_num) hj))
    have ht1_high : ∀ j, 16 ≤ j → t1.testBit j = false := fun j hj =>
      Nat.testBit_eq_false_of_lt
        (lt_of_lt_of_le ht1_lt (Nat.pow_le_pow_right (by norm_num) hj))
    have hv_high : ∀ j, 32 ≤ j → v.testBit j = false := fun j hj =>
      Nat.testBit_eq_false_of_lt
        (lt_of_lt_of_le hv (Nat.pow_le_pow_right (by norm_num) hj))
    have hk1_high : ∀ j, 8 ≤ j → k1.testBit j = false := fun j hj =>
      Nat.testBit_eq_false_of_lt
        (lt_of_lt_of_le hk1_lt
          (calc (256 : Nat) = 2 ^ 8 := by norm_num
            _ ≤ 2 ^ j := Nat.pow_le_pow_right (by norm_num) hj))
    rw [hv1_def, hk2_def]
    simp only [Nat.testBit_shiftRight, Nat.testBit_xor, Nat.testBit_shiftLeft,
               Nat.testBit_and]
    rw [show 16 + i = i + 16 from by ring, ht2_high (i + 16) (by omega)]
    have h255_lt : ∀ j, j < 8 → (255 : Nat).testBit j = true := by
      intro j hj; interval_cases j <;> decide
    have h255_ge : ∀ j, 8 ≤ j → (255 : Nat).testBit j = false := fun j hj =>
      Nat.testBit_eq_false_of_lt
        (lt_of_lt_of_le (by norm_num : (255 : Nat) < 2 ^ 8)
          (Nat.pow_le_pow_right (by norm_num) hj))
    rcases lt_or_ge i 8 with hi8 | hi8
    · simp only [h255_lt i hi8, Bool.and_true]
      have h8le : (8 : Nat) ≤ i + 16 := by omega
      have hk1shift_i_false : (decide (8 ≤ i)) = false := by
        simp only [decide_eq_false_iff_not, not_le]; omega
      have h8le_i16 : decide ((8 : Nat) ≤ i + 16) = true := by
        simp only [decide_eq_true_eq]; omega
      simp only [hk1shift_i_false, Bool.false_and, Bool.xor_false,
                 h8le_i16, Bool.true_and]
      rw [hv1_def, Nat.testBit_xor, Nat.testBit_shiftLeft, h8le_i16,
          Bool.true_and]
    · rcases lt_or_ge i 16 with hi16 | hi16
      · have h255i : (255 : Nat).testBit i = false := h255_ge i hi8
        have h_ile : decide ((8 : Nat) ≤ i + 16) = true := by
          simp only [decide_eq_true_eq]; omega
        have h_ile_i : decide ((8 : Nat) ≤ i) = true := by
          simp only [decide_eq_true_eq]; omega
        simp only [h255i, Bool.and_false, Bool.false_xor, h_ile, Bool.true_and,
                   h_ile_i]
        rw [hk1_def, Nat.testBit_shiftRight]
        have ht1_eq_false : t1.testBit (i + 16 - 8) = false := ht1_high _ (by omega)
        rw [ht1_eq_false, Bool.xor_false]
        grind
      · have hv_eq : v.testBit (i + 16) = false := hv_high _ (by omega)
        have ht1_eq : t1.testBit (i + 16 - 8) = false := ht1_high _ (by omega)
        have hk1_eq : k1.testBit (i - 8) = false := hk1_high _ (by omega)
        have h255i : (255 : Nat).testBit i = false := h255_ge i (by omega)
        have h_ile : decide ((8 : Nat) ≤ i + 16) = true := by grind
        have h_ile_i : decide ((8 : Nat) ≤ i) = true := by grind
        simp only [hv_eq, ht1_eq, hk1_eq, h255i, h_ile, h_ile_i,
                   Bool.and_false, Bool.xor_false]
  have hhigh_poly : natToBinaryPoly ((v1 ^^^ t2) >>> 16) =
      natToBinaryPoly k2 + natToBinaryPoly k1 * X ^ 8 := by
    rw [hhigh, natToBinaryPoly_xor, natToBinaryPoly_shiftLeft]
  have hd1 : polyGF2 ∣ (natToBinaryPoly k1 * X ^ (8 + 16) +
      natToBinaryPoly t1 * X ^ 8) := xor_table_shift_dvd k1 8 (htable k1 hk1_lt)
  have hd2 : polyGF2 ∣ (natToBinaryPoly k2 * X ^ (0 + 16) +
      natToBinaryPoly t2 * X ^ 0) := xor_table_shift_dvd k2 0 (htable k2 hk2_lt)
  have hxor_eq : natToBinaryPoly (v1 ^^^ t2) =
      natToBinaryPoly v + natToBinaryPoly t1 * X ^ 8 + natToBinaryPoly t2 := by
    rw [natToBinaryPoly_xor, hv1_def, natToBinaryPoly_xor, natToBinaryPoly_shiftLeft]
  have hsplit : natToBinaryPoly (v1 ^^^ t2) =
      natToBinaryPoly ((v1 ^^^ t2) % 2 ^ 16) +
        natToBinaryPoly ((v1 ^^^ t2) >>> 16) * X ^ 16 :=
    natToBinaryPoly_split (v1 ^^^ t2) 16
  have hkey : natToBinaryPoly v - natToBinaryPoly ((v1 ^^^ t2) % 2 ^ 16) =
      (natToBinaryPoly k1 * X ^ (8 + 16) + natToBinaryPoly t1 * X ^ 8) +
      (natToBinaryPoly k2 * X ^ (0 + 16) + natToBinaryPoly t2 * X ^ 0) := by
    have h1 : natToBinaryPoly ((v1 ^^^ t2) % 2 ^ 16) =
        natToBinaryPoly v + natToBinaryPoly t1 * X ^ 8 + natToBinaryPoly t2 -
          natToBinaryPoly ((v1 ^^^ t2) >>> 16) * X ^ 16 := by
      have hh := hsplit
      rw [hxor_eq] at hh
      linear_combination -hh
    rw [h1, hhigh_poly]
    rw [show natToBinaryPoly v - (natToBinaryPoly v + natToBinaryPoly t1 * X ^ 8 +
            natToBinaryPoly t2 - (natToBinaryPoly k2 + natToBinaryPoly k1 * X ^ 8) * X ^ 16) =
          (natToBinaryPoly k2 + natToBinaryPoly k1 * X ^ 8) * X ^ 16 +
            -(natToBinaryPoly t1 * X ^ 8 + natToBinaryPoly t2) from by ring,
        BinaryPoly.neg_eq]
    ring
  have hdvd : polyGF2 ∣ (natToBinaryPoly v - natToBinaryPoly ((v1 ^^^ t2) % 2 ^ 16)) := by
    grind [dvd_add hd1 hd2]
  have hmod_eq : natToBinaryPoly v %ₘ polyGF2 =
      natToBinaryPoly ((v1 ^^^ t2) % 2 ^ 16) %ₘ polyGF2 :=
    Polynomial.modByMonic_eq_of_dvd_sub polyGF2_monic hdvd
  have ha_lt : (v1 ^^^ t2) % 2 ^ 16 < 2 ^ 16 := Nat.mod_lt _ (by norm_num)
  have ha_deg : (natToBinaryPoly ((v1 ^^^ t2) % 2 ^ 16)).degree < polyGF2.degree := by
    rw [Polynomial.degree_eq_natDegree polyGF2_monic.ne_zero, polyGF2_natDegree]
    rcases eq_or_ne (natToBinaryPoly ((v1 ^^^ t2) % 2 ^ 16)) 0 with heq | hne
    · rw [heq, Polynomial.degree_zero]; exact WithBot.bot_lt_coe _
    · rw [Polynomial.degree_lt_iff_coeff_zero]
      intro m hm
      have hm' : 16 ≤ m := by exact_mod_cast hm
      rw [natToBinaryPoly_coeff]
      have hbnd : (v1 ^^^ t2) % 2 ^ 16 < 2 ^ m := lt_of_lt_of_le ha_lt
        (Nat.pow_le_pow_right (by norm_num) hm')
      rw [Nat.testBit_eq_false_of_lt hbnd]
      simp
  have ha_self : natToBinaryPoly ((v1 ^^^ t2) % 2 ^ 16) %ₘ polyGF2 =
      natToBinaryPoly ((v1 ^^^ t2) % 2 ^ 16) :=
    (Polynomial.modByMonic_eq_self_iff polyGF2_monic).mpr ha_deg
  rw [hmod_eq, ha_self]

set_option maxHeartbeats 800000 in
-- step* is heavy.
/-- **Spec theorem for `spqr::encoding::gf::reduce::poly_reduce`**

Table-based polynomial reduction of a 32-bit carry-less product modulo the irreducible polynomial
POLY = 0x1100b, yielding a 16-bit GF(2¹⁶) element.

The function uses the precomputed `REDUCE_BYTES` table to process the input byte-by-byte from high
to low:
  1. Clear bits 24–31 using `REDUCE_BYTES[v >> 24] << 8`.
  2. Clear bits 16–23 using `REDUCE_BYTES[(v >> 16) & 0xFF]`.
  3. Return the remaining 16 bits.

The result satisfies the algebraic specification:
  `natToBinaryPoly result.val = (natToBinaryPoly v.val) %ₘ polyGF2`

This connects the bitwise table-lookup implementation to polynomial reduction in GF(2)[X],
confirming that `poly_reduce` computes the canonical degree-< 16 representative of `v` modulo
polyGF2 = X¹⁶ + X¹² + X³ + X + 1. -/
@[step]
theorem poly_reduce_spec (v : U32) :
    poly_reduce v ⦃ (result : U16) =>
      natToBinaryPoly result = (natToBinaryPoly v) %ₘ polyGF2 ⦄ := by
  unfold poly_reduce spqr.encoding.gf.reduce.REDUCE_BYTES
  step*
  · scalar_tac
  · simp only [Array.length_eq]
    rw [i21_post1, UScalar.val_and]
    exact nat_and_255_lt_256 _
  · have hi1_val : i1.val = v.val >>> 24 := by
      grind [U32.cast_Usize_val_eq]
    have hi1_lt : i1.val < 256 := by
      rw [hi1_val, Nat.shiftRight_eq_div_pow]
      grind
    have hi2_eq : i2.val = reduceByteTable i1.val := by
      apply natToBinaryPoly_inj
      have h := a_post i1 (by scalar_tac)
      simp only [Array.getElem!_Usize_eq] at h
      rw [i2_post, List.Inhabited_getElem_eq_getElem! _ _ (by scalar_tac)]
      exact h.trans (reduceByteTable_eq_poly_full i1.val hi1_lt).symm
    have hi3_val : i3.val = i2.val := by
      rw [i3_post, U16.cast_U32_val_eq]
    have hi2_lt : i2.val < 2 ^ 16 := i2.hBounds
    have hi4_val : i4.val = i2.val <<< 8 := by
      rw [i4_post1, hi3_val]
      have hbnd : i2.val <<< 8 < U32.size := by
        rw [Nat.shiftLeft_eq]
        scalar_tac
      exact Nat.mod_eq_of_lt hbnd
    have hv1_val : v1.val = v.val ^^^ (i2.val <<< 8) := by
      rw [v1_post1, UScalar.val_xor, hi4_val]
    have hsh_val : shifted_v.val = i5.val := by
      rw [shifted_v_post, U32.cast_Usize_val_eq]
    have hi21_val : i21.val = (v1.val >>> 16) &&& 255 := by
      grind
    have hi21_lt : i21.val < 256 := by
      rw [hi21_val]
      apply nat_and_255_lt_256 _
    have hi6_eq : i6.val = reduceByteTable i21.val := by
      apply natToBinaryPoly_inj
      have h := a_post i21 hi21_lt
      simp only [Array.getElem!_Usize_eq] at h
      rw [i6_post, List.Inhabited_getElem_eq_getElem! a.val ↑i21
        (by rw [Array.length_eq]; exact_mod_cast hi21_lt)]
      exact h.trans (reduceByteTable_eq_poly_full i21.val hi21_lt).symm
    have hi7_val : i7.val = i6.val := by
      rw [i7_post, U16.cast_U32_val_eq]
    have hv2_val : v2.val = v1.val ^^^ i6.val := by
      rw [v2_post1, UScalar.val_xor, hi7_val]
    have hbridge : (UScalar.cast UScalarTy.U16 v2).val = polyReduce v.val := by
      rw [UScalar.cast_val_eq]
      change v2.val % 2 ^ 16 = polyReduce v.val
      rw [hv2_val, hi6_eq, hi21_val, hv1_val, hi2_eq, hi1_val]
      simp only [polyReduce]
    rw [hbridge]
    exact polyReduce_eq v.val v.hBounds reduceByteTable_eq_poly_full

end spqr.encoding.gf.reduce
