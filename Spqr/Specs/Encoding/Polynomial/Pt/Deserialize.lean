/-
Copyright 2026 The Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE-APACHE.
Authors: Hoang Le Truong
-/
import SrcTranslated.Funs


/-! # Spec Theorem for `Pt::deserialize`

Specification and proof for `encoding.polynomial.Pt.deserialize`, which deserializes a 4-byte
big-endian array into a GF(2¹⁶) cartesian point `Pt { x, y }`.

The function reads a `[u8; 4]` input array and reconstructs a point:
  - `result.x.value ← u16::from_be_bytes(s[0..2])`
    where `result.x.value = s[0] · 256 + s[1]`
  - `result.y.value ← u16::from_be_bytes(s[2..4])`
    where `result.y.value = s[2] · 256 + s[3]`

The two-byte big-endian identity
  `result.x.value.val = s[0].val · 256 + s[1].val`
  `result.y.value.val = s[2].val · 256 + s[3].val`
ensures that the deserialized point faithfully represents the original bytes, and together with
`Pt::serialize` forms a round-trip:
  `Pt::deserialize(pt.serialize()) = pt`

**Source**: spqr/src/encoding/polynomial.rs (lines 38:4-43:5)
-/


open Aeneas Aeneas.Std Result

namespace spqr.encoding.polynomial.Pt

/-
natural language description:

• Takes a `[u8; 4]` array `s`.
• Extracts the first two bytes `s[0..2]`, converts them from a big-endian byte pair into a `u16`
  via `u16::from_be_bytes`:
    - `x_val = (s[0] as u16) << 8 | (s[1] as u16)`
    i.e. `x_val = s[0] · 256 + s[1]`
• Wraps the resulting `u16` as a `GF16` field element → `x`.
• Extracts the last two bytes `s[2..4]`, converts them from a big-endian byte pair into a `u16`
  via `u16::from_be_bytes`:
    - `y_val = (s[2] as u16) << 8 | (s[3] as u16)`
    i.e. `y_val = s[2] · 256 + s[3]`
• Wraps the resulting `u16` as a `GF16` field element → `y`.
• Returns `ok { x, y }`.

natural language specs:

• The function always succeeds (no panic) for any valid `[u8; 4]` input.
• The x-coordinate is reconstructed from the first two bytes in big-endian:
    `result.x.value.val = s[0].val * 256 + s[1].val`
• The y-coordinate is reconstructed from the last two bytes in big-endian:
    `result.y.value.val = s[2].val * 256 + s[3].val`
• Together with `Pt::serialize`, the decoding is invertible:
    `Pt::deserialize(pt.serialize()) = ok pt`
-/

/- **Spec for `U16::from_be_bytes`**:
The big-endian decoding of a 2-byte array `a` satisfies
  `result.val = a[0].val * 256 + a[1].val`.

This is the core byte-reconstruction lemma underlying `deserialize_spec`: it isolates the
`from_be_bytes` conversion so that its correctness can be reasoned about independently of the
surrounding monadic plumbing.
-/

@[step]
theorem from_be_bytes_spec (a : Array Std.U8 2#usize) :
    lift (core.num.U16.from_be_bytes a) ⦃ result =>
      result.val = (a[0]!).val * 256 + (a[1]!).val ⦄ := by
  simp  only [lift, core.num.U16.from_be_bytes, Std.UScalar.val]
  -- Decompose the 2-element array to expose list structure
  rcases a with ⟨_ | ⟨a0, _ | ⟨a1, l⟩⟩, hlen⟩
  · simp at hlen
  · simp at hlen
  · simp only [List.length_cons] at hlen
    have hl : l = [] := by
      rcases l with _ | ⟨_, _⟩
      · rfl
      · simp at hlen
    subst hl
    simp only [UScalarTy.Usize_numBits_eq, List.map_cons, List.map_nil,
    List.length_cons, List.length_nil, Nat.reduceAdd,
    Nat.reduceMul, UScalarTy.U16_numBits_eq, BitVec.fromBEBytes, List.reverse, List.reverseAux_cons,
    List.reverseAux_nil, BitVec.fromLEBytes, BitVec.setWidth_eq,
    Nat.mul_zero, zero_le, pow_zero, zero_lt_one,
    BitVec.setWidth_ofNat_of_le_of_lt, le_refl, BitVec.shiftLeft_eq_zero,
    BitVec.or_zero, BitVec.cast_eq,
    Bvify.U16.UScalar_bv, UScalar.bv_toNat, UScalarTy.U8_numBits_eq,
    Array.getElem!_Nat_eq, zero_add, Nat.ofNat_pos,
    getElem!_pos, List.getElem_cons_zero, Bvify.U8.UScalar_bv,
    Nat.one_lt_ofNat, List.getElem_cons_succ, WP.spec_ok]
    -- Unfold UScalar.val coercion to expose BitVec.toNat
    simp only [Std.UScalar.val]
    rw [BitVec.toNat_or, BitVec.toNat_shiftLeft]
    simp only [Nat.shiftLeft_eq]
    have h0 : a0.bv.toNat < 2 ^ 8 := a0.bv.isLt
    have h1 : a1.bv.toNat < 2 ^ 8 := a1.bv.isLt
    simp only at h0
    simp only at h1
    simp only [UScalarTy.U16_numBits_eq,
    BitVec.toNat_setWidth, UScalar.bv_toNat, Nat.reducePow, Nat.mod_mul_mod,
    UScalarTy.U8_numBits_eq, Bvify.U8.UScalar_bv]
    have h10 : a1.val < 65536 := by grind
    have h11:=Nat.mod_eq_of_lt h10
    rw [h11]
    have h00 : a0.val * 256 < 65536 := by grind
    have h01:=Nat.mod_eq_of_lt h00
    rw [h01]
    symm
    rw[Nat.or_comm, mul_comm, (by grind : 256 = 2 ^ 8)]
    apply Nat.two_pow_add_eq_or_of_lt
    grind

/- **Spec for `<[T; N] as TryFrom<&[T]>>::try_from`**:
When the input slice `s` has length exactly `N` and the type's `Copy` (clone) is the identity
(as for all scalar types), `try_from` succeeds with `Ok a` where `a.val = s.val`.

This is the core slice-to-array conversion lemma underlying `deserialize_spec`: it handles the
`.try_into().unwrap()` idiom that Rust uses to convert a sub-slice back into a fixed-size array.
-/
@[step]
theorem try_from_spec {T : Type} (N : Usize) (copyInst : core.marker.Copy T)
    (s : Slice T)
    (h_clone : ∀ x ∈ s.val, copyInst.cloneInst.clone x = ok x)
    (h_len : s.length = N) :
    core.array.TryFromArrayCopySlice.try_from N copyInst s ⦃ result =>
      ∃ (a : Array T N), result = .Ok a ∧ a.val = s.val ⦄ := by
  unfold core.array.TryFromArrayCopySlice.try_from
  have hm := List.mapM_clone_eq h_clone
  simp only [dif_pos h_len]
  step*

/-- **Spec and proof concerning `encoding.polynomial.Pt.deserialize`**:
• The function always succeeds (no panic) for any valid `[u8; 4]` input.
• The x-coordinate of the result is reconstructed from the first two bytes in big-endian:
  `result.x.value.val = s[0].val * 256 + s[1].val`
• The y-coordinate of the result is reconstructed from the last two bytes in big-endian:
  `result.y.value.val = s[2].val * 256 + s[3].val`
-/
@[step]
theorem deserialize_spec (s : Array Std.U8 4#usize) :
    deserialize s ⦃ result =>
      result.x.value.val = (s[0]!).val * 256 + (s[1]!).val ∧
      result.y.value.val = (s[2]!).val * 256 + (s[3]!).val ⦄ := by
  unfold deserialize encoding.gf.GF16.new core.result.Result.unwrap
  step*
  simp_all only
  step*
  simp_all only
  step*
  simp_all

end spqr.encoding.polynomial.Pt
