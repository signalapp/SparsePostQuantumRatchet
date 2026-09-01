/-
Copyright (c) 2026 Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Alessandro D'Angelo
-/

/- Vendored verbatim (imports rewritten) from
   https://github.com/Beneficial-AI-Foundation/secure-messaging
   SecureMessaging/ErasureCode/ReedSolomon/Correctness.lean at commit 2144e35.
   The canonical copy is secure-messaging; do not edit here — re-vendor. -/

import Protocols.ErasureCode.Model.ReedSolomon.Construction

/-!
# Correctness of the Reed–Solomon Erasure Code

In the notation of `SecureMessaging.ErasureCode.ReedSolomon.Construction`, writing

`L_I := {(j, Encode(m, j)) | j ∈ I}`

for the honest chunks of a message `m` at a set of positions `I`, we prove:

* `Encode(m, i) = mᵢ` for `i < k` — the code is systematic (`encode_source`);
* `Decode(L_I) = m` when `k ≤ |I|` (`decode_encodeChunks_of_k_le_card`);
* `Decode(L_I) = ⊥` when `|I| < k` (`decode_encodeChunks_of_card_lt`).

Together these give the erasure-code correctness predicate `ErasureCode.Correct`
for `erasureCode` (`erasureCode_correct`).
-/

namespace ErasureCode.ReedSolomon

noncomputable section

open Polynomial

variable {F : Type} [Field F]

namespace Parameters

/-- The interpolation property of the encoding polynomial: `Pₘ(xᵢ) = mᵢ` for `i < k`. -/
theorem eval_encodingPolynomial_source (params : Parameters F)
    (message : Fin params.k → F) (i : Fin params.k) :
    (params.encodingPolynomial message).eval (params.sourcePoint i) = message i := by
  apply Lagrange.eval_interpolate_at_node
  · exact params.sourcePoint_injective.injOn
  · simp

/-- The degree bound of the encoding polynomial: `deg Pₘ < k`. -/
theorem degree_encodingPolynomial_lt (params : Parameters F)
    (message : Fin params.k → F) :
    (params.encodingPolynomial message).degree < params.k := by
  simpa [encodingPolynomial] using
    (Lagrange.degree_interpolate_lt
      (s := Finset.univ) message params.sourcePoint_injective.injOn)

/-- The systematic property: `Encode(m, i) = Pₘ(xᵢ) = mᵢ` for message indices `i < k`. -/
@[simp]
-- ANCHOR: reedSolomon_systematic
theorem encode_source (params : Parameters F) (message : Fin params.k → F)
    (i : Fin params.k) :
    params.encode message (params.sourceIndex i) = message i := by
  exact params.eval_encodingPolynomial_source message i
-- ANCHOR_END: reedSolomon_systematic

/-- The honest chunk set `L_I` is decodable when `k ≤ |I|`: it has one chunk per
position of `I`. -/
theorem decodable_encodeChunks_of_k_le_card (params : Parameters F)
    (message : Fin params.k → F) (I : Finset (Fin params.N))
    (hcard : params.k ≤ I.card) :
    ErasureCode.Decodable params.k (params.erasureCode.encodeChunks message I) :=
  params.erasureCode.decodable_encodeChunks_of_nchunk_le_card message I hcard

/-- Uniqueness of interpolation: for `k ≤ |I|`, the interpolant `Q` through the
honest chunks `L_I` equals `Pₘ` — both have degree `< |I|` and agree at the `|I|`
distinct points `{xⱼ | j ∈ I}`. -/
private theorem encodingPolynomial_eq_decodingInterpolation (params : Parameters F)
    (message : Fin params.k → F) (I : Finset (Fin params.N))
    (hcard : params.k ≤ I.card) :
    params.encodingPolynomial message =
      params.decodingPolynomial (params.erasureCode.encodeChunks message I) := by
  classical
  let chunks : Finset (Fin params.N × F) := params.erasureCode.encodeChunks message I
  have hdec : ErasureCode.Decodable params.k chunks :=
    params.decodable_encodeChunks_of_k_le_card message I hcard
  have hpoints : Set.InjOn (fun ((j, _) : Fin params.N × F) => params.point j)
      (chunks : Set (Fin params.N × F)) := by
    intro a ha b hb hab
    exact hdec.2 ha hb (params.point_injective hab)
  rw [decodingPolynomial]
  apply Lagrange.eq_interpolate_of_eval_eq _ hpoints
  · have hcard' : params.k ≤ chunks.card := hdec.1
    exact lt_of_lt_of_le
      (params.degree_encodingPolynomial_lt message) (by exact_mod_cast hcard')
  · intro chunk hchunk
    have hmem := (params.erasureCode.mem_encodeChunks message I chunk).mp hchunk
    exact hmem.2.symm

/-- Reconstruction above the threshold: `Decode(L_I) = m` when `k ≤ |I|`, by
`Q = Pₘ` and `Pₘ(xᵢ) = mᵢ`. -/
theorem decode_encodeChunks_of_k_le_card (params : Parameters F)
    (message : Fin params.k → F) (I : Finset (Fin params.N))
    (hcard : params.k ≤ I.card) :
    params.erasureCode.decode
      (params.erasureCode.encodeChunks message I) = some message := by
  have hdec := params.decodable_encodeChunks_of_k_le_card message I hcard
  have hpoly := params.encodingPolynomial_eq_decodingInterpolation message I hcard
  change params.decode (params.erasureCode.encodeChunks message I) = some message
  rw [decode]
  split_ifs with h
  · congr 1
    funext i
    exact
      (congrArg (fun poly : F[X] => poly.eval (params.sourcePoint i)) hpoly.symm).trans
        (params.eval_encodingPolynomial_source message i)
  · exact (h hdec).elim

/-- Failure below the threshold: `Decode(L_I) = ⊥` when `|I| < k`. -/
theorem decode_encodeChunks_of_card_lt (params : Parameters F)
    (message : Fin params.k → F) (I : Finset (Fin params.N))
    (hcard : I.card < params.k) :
    params.erasureCode.decode
      (params.erasureCode.encodeChunks message I) = none := by
  change params.decode (params.erasureCode.encodeChunks message I) = none
  rw [decode]
  split_ifs with hdec
  · apply Nat.not_le_of_lt hcard
    have hk := hdec.1
    calc
      params.k ≤ (params.erasureCode.encodeChunks message I).card := hk
      _ = I.card := params.erasureCode.card_encodeChunks message I
  · rfl

/-- Rejection of conflicts: `Decode(L) = ⊥` when the chunks of `L` do not have
pairwise distinct positions — in particular when `L` contains
`(j, y₁), (j, y₂)` with `y₁ ≠ y₂`. -/
theorem decode_eq_none_of_not_injective (params : Parameters F)
    (chunks : Finset (Fin params.N × F))
    (hconflict : ¬Set.InjOn Prod.fst (chunks : Set (Fin params.N × F))) :
    params.decode chunks = none := by
  simp [decode, ErasureCode.Decodable, hconflict]

/-- The Reed–Solomon erasure code is correct (`ErasureCode.Correct`, [SCKA] Def.
A.6): for every message `m` and position set `I`, `Decode(L_I) = m` if `k ≤ |I|`,
and `Decode(L_I) = ⊥` if `|I| < k`. -/
-- ANCHOR: reedSolomon_erasureCode_correct
theorem erasureCode_correct (params : Parameters F) : params.erasureCode.Correct
-- ANCHOR_END: reedSolomon_erasureCode_correct
    := by
  intro message I
  constructor
  · exact params.decode_encodeChunks_of_k_le_card message I
  · exact params.decode_encodeChunks_of_card_lt message I

end Parameters

end

end ErasureCode.ReedSolomon
