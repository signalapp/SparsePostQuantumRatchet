/-
Copyright 2026 The Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE-APACHE.
Authors: Markus Dablander
-/
import SrcTranslated.Funs
import Spqr.Specs.Util.IsNonZero
import Spqr.Aux.Aeneas.StdNextStepUsize

/-!
# Spec theorem for `spqr::util::compare`

Constant-time byte-by-byte equality test for two equal-length byte slices. The function returns
`0` when the slices match exactly and `1` when they differ in at least one position.

**Source:** "spqr/src/util.rs"
-/

open Aeneas Aeneas.Std
namespace spqr.util

/-- **Spec theorem for `spqr::util::compare_loop`**
• The loop never panics under the given preconditions.
• `result.val = 0` iff `lhs.val[j]! = rhs.val[j]!` for all `j < lhs.length`.
-/
@[step]
theorem compare_loop_spec
    (lhs rhs : Slice U8) (iter : core.ops.range.Range Usize) (r : U8)
    (hlen : lhs.length = rhs.length)
    (hstart : iter.start.val ≤ iter.«end».val)
    (hend : iter.«end».val = lhs.length)
    (hinv : r.val = 0 ↔ ∀ (j : Nat), j < iter.start.val → lhs.val[j]! = rhs.val[j]!) :
    compare_loop iter lhs rhs r ⦃ (result : U8) =>
      result.val = 0 ↔ ∀ (j : Nat), j < lhs.length → lhs.val[j]! = rhs.val[j]! ⦄ := by
  unfold compare_loop
  apply loop.spec_decr_nat
    (measure := fun p => lhs.length - p.1.start.val)
    (inv := fun p : core.ops.range.Range Usize × U8 =>
      p.1.start.val ≤ p.1.«end».val ∧ p.1.«end».val = lhs.length ∧
      (p.2.val = 0 ↔ ∀ j < p.1.start.val, lhs.val[j]! = rhs.val[j]!))
  · intro ⟨iter', r'⟩ ⟨h_lo, h_end, h_inv'⟩
    unfold compare_loop.body
    by_cases hLt : iter'.start.val < iter'.«end».val
    · step*
      obtain ⟨ho_some, hstart1, hend1⟩ := o_post2 hLt
      obtain rfl : i = iter'.start := Option.some.inj (‹o = some i› ▸ ho_some)
      have hor (a b : U8) : (a ||| b).val = 0 ↔ a.val = 0 ∧ b.val = 0 := by bv_tac 8
      have hxor (a b : U8) : (a ^^^ b).val = 0 ↔ a.val = b.val := by bv_tac 8
      refine ⟨by scalar_tac, hend1 ▸ h_end, ?_, by scalar_tac⟩
      simp only [r1_post1, hor, i3_post1, hxor, hstart1, Nat.forall_lt_succ_right,
                 getElem!_pos, show iter'.start.val < lhs.length by scalar_tac, ← hlen,
                 ← i1_post, ← i2_post, ← UScalar.eq_equiv, ← h_inv']
    · simp [core.iter.range.IteratorRange.next, core.iter.range.UScalarStep,
        core.cmp.impls.PartialOrdUsize.lt, hLt]
      simp_all [show iter'.start.val = lhs.length by scalar_tac]
  · exact ⟨hstart, hend, hinv⟩

/-- **Spec theorem for `spqr::util::compare`**
• The function never panics when `lhs` and `rhs` have equal length.
• `result.val = 0` when `lhs.val[j]! = rhs.val[j]!` for all `j < lhs.length`, and `1` otherwise.
-/
@[step]
theorem compare_spec (lhs rhs : Slice U8) (hlen : lhs.length = rhs.length) :
    compare lhs rhs ⦃ (result : U8) =>
      result.val =
        if (∀ (j : Nat), j < lhs.length → lhs.val[j]! = rhs.val[j]!) then 0 else 1 ⦄ := by
  unfold compare
  step*
  grind

end spqr.util
