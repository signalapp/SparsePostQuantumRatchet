/-
Copyright (c) 2026 Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Alessandro D'Angelo
-/

/- Vendored verbatim (imports rewritten) from
   https://github.com/Beneficial-AI-Foundation/secure-messaging
   SecureMessaging/ErasureCode/SPQRReedSolomon/Correctness.lean at commit 2144e35.
   The canonical copy is secure-messaging; do not edit here — re-vendor. -/

import Protocols.ErasureCode.Model.ReedSolomon.Correctness
import Protocols.ErasureCode.Model.SPQRReedSolomon.Construction

/-!
# Correctness of the Parallel Reed–Solomon Erasure Code

Let `params` be Reed–Solomon parameters, `m ∈ (F^16)^k`, and
`I ⊆ {0, …, N-1}`. Denote by

`L_I := {(j, Encode(m, j)) | j ∈ I}`

the set of chunks at positions `I`. Each of the 16 coordinates forms an ordinary
Reed–Solomon codeword. We prove:

* `Encode(m, i) = mᵢ` for `i < k` — the parallel code is systematic (`encode_source`);
* `Decode(L_I) = m` when `k ≤ |I|` (`decode_encodeChunks_of_k_le_card`);
* `Decode(L_I) = ⊥` when `|I| < k` (`decode_encodeChunks_of_card_lt`);
* `ErasureCode.Correct` for `parallelErasureCode params`
  (`parallelErasureCode_correct`) and its specialization `erasureCode k`
  (`erasureCode_correct`).
-/

namespace ErasureCode.SPQRReedSolomon

noncomputable section

open Polynomial

variable {F : Type} [Field F]

/-- Systematic encoding: at each source index `i < k`, parallel encoding returns the
source chunk itself, `Encode(message, i) = message i`. -/
@[simp]
theorem encode_source (params : ReedSolomon.Parameters F)
    (message : Fin params.k → Chunk F) (i : Fin params.k) :
    encode params message (params.sourceIndex i) = message i := by
  funext coordinate
  exact params.encode_source (fun j => message j coordinate) i

/-- If `I` contains at least `k` positions, then the chunk set
`(parallelErasureCode params).encodeChunks message I` is decodable: it has one chunk per
position of `I`. -/
theorem decodable_encodeChunks_of_k_le_card (params : ReedSolomon.Parameters F)
    (message : Fin params.k → Chunk F) (I : Finset (Fin params.N))
    (hcard : params.k ≤ I.card) :
    ErasureCode.Decodable params.k ((parallelErasureCode params).encodeChunks message I) :=
  (parallelErasureCode params).decodable_encodeChunks_of_nchunk_le_card message I hcard

/-- Projection commutes with encoding: selecting coordinate `c` from every parallel
encoded chunk over `I` gives exactly the scalar encoded chunk set for the coordinate
message `i ↦ message i c`. -/
@[simp]
theorem coordinateChunks_encodeChunks (params : ReedSolomon.Parameters F)
    (message : Fin params.k → Chunk F) (I : Finset (Fin params.N))
    (coordinate : Fin 16) :
    coordinateChunks params ((parallelErasureCode params).encodeChunks message I) coordinate =
      params.erasureCode.encodeChunks (fun i => message i coordinate) I := by
  classical
  ext chunk
  constructor
  · intro hchunk
    rcases Finset.mem_image.mp hchunk with ⟨fullChunk, hfull, rfl⟩
    have hmem := ((parallelErasureCode params).mem_encodeChunks message I fullChunk).mp hfull
    apply (params.erasureCode.mem_encodeChunks (fun i => message i coordinate) I _).mpr
    refine ⟨hmem.1, ?_⟩
    exact congrFun hmem.2 coordinate
  · intro hchunk
    have hmem :=
      (params.erasureCode.mem_encodeChunks
        (fun i => message i coordinate) I chunk).mp hchunk
    rcases chunk with ⟨index, value⟩
    let fullChunk := (index, (parallelErasureCode params).encode message index)
    apply Finset.mem_image.mpr
    refine ⟨fullChunk, ?_, ?_⟩
    · exact
        ((parallelErasureCode params).mem_encodeChunks message I fullChunk).mpr ⟨hmem.1, rfl⟩
    · change
        (index, ((parallelErasureCode params).encode message index) coordinate) = (index, value)
      congr
      change params.encode (fun i => message i coordinate) index = value
      exact hmem.2.symm

/-- Coordinatewise interpolation of honest chunks: when `k ≤ |I|`, the decoding
polynomial for coordinate `c` equals the scalar encoding polynomial of
`i ↦ message i c`. -/
private theorem encodingPolynomial_eq_decodingPolynomial
    (params : ReedSolomon.Parameters F)
    (message : Fin params.k → Chunk F) (I : Finset (Fin params.N))
    (hcard : params.k ≤ I.card)
    (coordinate : Fin 16) :
    params.encodingPolynomial (fun i => message i coordinate) =
      params.decodingPolynomial
        (coordinateChunks params
          ((parallelErasureCode params).encodeChunks message I) coordinate) := by
  classical
  let scalarMessage := fun i => message i coordinate
  let chunks : Finset (Fin params.N × F) :=
    params.erasureCode.encodeChunks scalarMessage I
  have hdec : ErasureCode.Decodable params.k chunks :=
    params.decodable_encodeChunks_of_k_le_card scalarMessage I hcard
  have hpoints : Set.InjOn (fun ((j, _) : Fin params.N × F) => params.point j)
      (chunks : Set (Fin params.N × F)) := by
    intro a ha b hb hab
    exact hdec.2 ha hb (params.point_injective hab)
  rw [coordinateChunks_encodeChunks, ReedSolomon.Parameters.decodingPolynomial]
  apply Lagrange.eq_interpolate_of_eval_eq _ hpoints
  · have hdegree := params.degree_encodingPolynomial_lt scalarMessage
    have hcard' : params.k ≤ chunks.card := hdec.1
    exact lt_of_lt_of_le hdegree (by exact_mod_cast hcard')
  · intro chunk hchunk
    have hmem :=
      (params.erasureCode.mem_encodeChunks scalarMessage I chunk).mp hchunk
    exact hmem.2.symm

/-- Reconstruction at or above the threshold: encoding a message at every position in
`I` and decoding those chunks returns the message whenever `k ≤ |I|`. -/
theorem decode_encodeChunks_of_k_le_card (params : ReedSolomon.Parameters F)
    (message : Fin params.k → Chunk F) (I : Finset (Fin params.N))
    (hcard : params.k ≤ I.card) :
    (parallelErasureCode params).decode
      ((parallelErasureCode params).encodeChunks message I) = some message := by
  have hdec := decodable_encodeChunks_of_k_le_card params message I hcard
  change decode params ((parallelErasureCode params).encodeChunks message I) = some message
  rw [decode]
  split_ifs with h
  · congr 1
    funext i coordinate
    have hpoly :=
      encodingPolynomial_eq_decodingPolynomial params message I hcard coordinate
    exact
      (congrArg (fun poly : F[X] => poly.eval (params.sourcePoint i)) hpoly.symm).trans
        (params.eval_encodingPolynomial_source (fun j => message j coordinate) i)
  · exact (h hdec).elim

/-- Failure below the threshold: decoding
`(parallelErasureCode params).encodeChunks message I` returns `none` whenever `|I| < k`. -/
theorem decode_encodeChunks_of_card_lt (params : ReedSolomon.Parameters F)
    (message : Fin params.k → Chunk F) (I : Finset (Fin params.N))
    (hcard : I.card < params.k) :
    (parallelErasureCode params).decode
      ((parallelErasureCode params).encodeChunks message I) = none := by
  change decode params ((parallelErasureCode params).encodeChunks message I) = none
  rw [decode]
  split_ifs with hdec
  · apply Nat.not_le_of_lt hcard
    have hk := hdec.1
    calc
      params.k ≤ ((parallelErasureCode params).encodeChunks message I).card := hk
      _ = I.card := (parallelErasureCode params).card_encodeChunks message I
  · rfl

/-- Rejection of conflicting chunks: decoding returns `none` if two distinct received
entries share a position. -/
theorem decode_eq_none_of_not_injective (params : ReedSolomon.Parameters F)
    (chunks : Finset (Fin params.N × Chunk F))
    (hconflict : ¬Set.InjOn Prod.fst (chunks : Set (Fin params.N × Chunk F))) :
    decode params chunks = none := by
  simp [decode, ErasureCode.Decodable, hconflict]

/-- Correctness of the parallel construction: for every message and position
set `I`, decoding honest chunks returns the message when `k ≤ |I|` and returns `none`
when `|I| < k`. -/
-- ANCHOR: parallelReedSolomon_erasureCode_correct
theorem parallelErasureCode_correct (params : ReedSolomon.Parameters F) :
    (parallelErasureCode params).Correct
-- ANCHOR_END: parallelReedSolomon_erasureCode_correct
    := by
  intro message I
  constructor
  · exact decode_encodeChunks_of_k_le_card params message I
  · exact decode_encodeChunks_of_card_lt params message I

/-- Correctness of the abstract SPQR specialization for every threshold
`0 < k ≤ 2^16`. -/
-- ANCHOR: spqrReedSolomon_erasureCode_correct
theorem erasureCode_correct (k : ℕ) (hk : k ≤ 2 ^ 16) (hk_pos : 0 < k) :
    (erasureCode k hk hk_pos).Correct
-- ANCHOR_END: spqrReedSolomon_erasureCode_correct
    := by
  exact parallelErasureCode_correct (spqrParameters k hk hk_pos)

end

end ErasureCode.SPQRReedSolomon
