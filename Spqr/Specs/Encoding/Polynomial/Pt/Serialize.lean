/-
Copyright 2026 The Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE-APACHE.
Authors: Hoang Le Truong
-/
import SrcTranslated.Funs

/-! # Spec Theorem for `Pt::serialize`

Specification and proof for `encoding.polynomial.Pt.serialize`, which serializes a GF(2¹⁶)
cartesian point `Pt { x, y }` into a 4-byte big-endian array.

The function creates a `[u8; 4]` output array and fills it as follows:
  - `out[0..2] ← self.x.value.to_be_bytes()`
    where `out[0] = x.val / 256` and `out[1] = x.val % 256`
  - `out[2..4] ← self.y.value.to_be_bytes()`
    where `out[2] = y.val / 256` and `out[3] = y.val % 256`

The two-byte big-endian identity
  `out[0] · 256 + out[1] = x.val`
  `out[2] · 256 + out[3] = y.val`
ensures that the serialized bytes faithfully represent the original point, and together with
`Pt::deserialize` forms a round-trip:
  `Pt::deserialize(pt.serialize()) = pt`

**Source**: spqr/src/encoding/polynomial.rs (lines 32:4-37:5)
-/

open Aeneas Aeneas.Std Result

namespace spqr.encoding.polynomial.Pt

/-
natural language description:

• Takes a `Pt` value `self` which contains two GF16 field elements `self.x : GF16` and
  `self.y : GF16`, each wrapping a `u16` value.
• Allocates a 4-byte output array initialised to `[0, 0, 0, 0]`.
• Writes the big-endian representation of `self.x.value` into `out[0..2]`:
    - `out[0] ← (self.x.value >> 8) as u8` (high byte)
    - `out[1] ← (self.x.value & 0xFF) as u8` (low byte)
  These are produced by `u16::to_be_bytes`, which for a `u16` value `v` returns
  `[v / 256, v % 256]`.
• Writes the big-endian representation of `self.y.value` into `out[2..4]`:
    - `out[2] ← (self.y.value >> 8) as u8` (high byte)
    - `out[3] ← (self.y.value & 0xFF) as u8` (low byte)
• Returns `ok out`.

natural language specs:

• The function always succeeds (no panic) for any valid `Pt` input.
• The first two bytes encode `self.x.value` in big-endian:
    `result[0].val * 256 + result[1].val = self.x.value.val`
• The last two bytes encode `self.y.value` in big-endian:
    `result[2].val * 256 + result[3].val = self.y.value.val`
• Together with `Pt::deserialize`, the encoding is invertible:
    `Pt::deserialize(pt.serialize()) = ok pt`
-/


/-- `RangeFull` indexing on a slice is the identity: `slice[..] = slice`. -/
private theorem rangeFull_index_eq {T : Type}
    (r : core.ops.range.RangeFull) (s : Slice T) :
    core.ops.range.RangeFull.Insts.CoreSliceIndexSliceIndexSliceSlice.index r s =
    ok s := by
  rfl

@[simp, step_simps]
private theorem array_index_rangeFull_ok {T : Type} {N : Usize}
    (a : Array T N) :
    core.array.Array.index
      (core.ops.index.IndexSlice
        (core.ops.range.RangeFull.Insts.CoreSliceIndexSliceIndexSliceSlice T))
      a () =
    ok a.to_slice :=
  rangeFull_index_eq () a.to_slice

/-- `clone_from_slice` for `u8` copies the source slice into the destination, returning a slice
    whose contents and length equal those of the source. -/
@[step]
private lemma clone_from_slice_U8_spec
    (dst src : Slice Std.U8) :
    core.slice.Slice.clone_from_slice core.clone.CloneU8 dst src
    ⦃ result =>
      result.val = src.val ∧ result.length = src.length ⦄ := by
  unfold core.slice.Slice.clone_from_slice
  apply WP.spec_mono (Slice.clone_spec (fun x _ => by simp))
  intro s' h
  subst h
  exact ⟨rfl, rfl⟩

/- **Spec for `U16::to_be_bytes`**:
The two-byte big-endian encoding of a `u16` value `x` satisfies
  `result[0].val * 256 + result[1].val = x.val`.

This is the core byte-decomposition lemma underlying `serialize_spec`: it isolates the
`to_be_bytes` conversion so that its correctness can be reasoned about independently of the
surrounding monadic plumbing.
-/

@[step]
theorem to_be_bytes_spec (x : U16) :
    lift (core.num.U16.to_be_bytes x) ⦃ result =>
      (result[0]!).val * 256 + (result[1]!).val = x.val ⦄ := by
  simp  [lift, core.num.U16.to_be_bytes]
  simp only  [Std.UScalar.val]
  simp [BitVec.toBEBytes, BitVec.toLEBytes, Nat.shiftRight_eq_div_pow]
  grind


/-- **Spec and proof concerning `encoding.polynomial.Pt.serialize`**:
• The function always succeeds (no panic) for any valid `Pt` input.
• The first two bytes of the result encode `self.x.value` in big-endian:
    `result[0].val * 256 + result[1].val = self.x.value.val`
• The last two bytes of the result encode `self.y.value` in big-endian:
    `result[2].val * 256 + result[3].val = self.y.value.val`
-/
@[step]
theorem serialize_spec (self : spqr.encoding.polynomial.Pt) :
    serialize self ⦃ result =>
      (result[0]!).val * 256 + (result[1]!).val = self.x.value.val ∧
      (result[2]!).val * 256 + (result[3]!).val = self.y.value.val ⦄ := by
  unfold serialize
  step*
  simp_all [List.setSlice!]

end spqr.encoding.polynomial.Pt
