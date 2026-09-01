/-
Copyright (c) 2026 Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Alessandro D'Angelo
-/

/- Vendored verbatim (imports rewritten) from
   https://github.com/Beneficial-AI-Foundation/secure-messaging
   SecureMessaging/ErasureCode/SPQRReedSolomon/Construction.lean at commit 2144e35.
   The canonical copy is secure-messaging; do not edit here — re-vendor. -/

import Mathlib.SetTheory.Cardinal.NatCard
import Mathlib.FieldTheory.Finite.GaloisField
import Protocols.ErasureCode.Model.ReedSolomon.Construction

/-!
# Parallel Reed–Solomon Erasure-Code Construction

This module lifts a Reed–Solomon code over `F` to an erasure code over
16-coordinate chunks `F^16` by running the same code independently on each
coordinate. This models the parallel structure of Signal's
[Sparse Post Quantum Ratchet polynomial encoder and decoder]
(https://github.com/signalapp/SparsePostQuantumRatchet/blob/main/src/encoding/polynomial.rs),
where a chunk is 16 `u16` values (32 bytes). The final section gives an abstract SPQR
specialization.

This is an algebraic abstraction, not an exact specification of Signal's
implementation. It does not model byte serialization, the concrete correspondence
between `u16` values and `GF(2^16)` elements, or protocol message encoding.

## Parallel 16-coordinate construction (`encode`, `decode`, `parallelErasureCode`)

*Recall:* a Reed–Solomon code with parameters `k ≤ N` and
pairwise distinct evaluation points `x₀, …, x_(N-1) ∈ F` is the linear code

`RS := { (P(x₀), …, P(x_(N-1))) | P ∈ F[X], deg P < k } ⊆ F^N`,

i.e. the set of evaluations of all polynomials of degree less than `k` over
the points `x₀, …, x_(N-1)`.

Fix Reed–Solomon parameters (`ReedSolomon.Parameters F`) with `k ≤ N` and
evaluation points `x_0, …, x_(N-1)`.

A *16-coordinate erasure code* has symbol set `Σ = F^16` and message size `nchunk = k`.
A source message is `m = (m₀, …, m_(k-1))`, with each `mᵢ ∈ F^16`.
Encoding and decoding apply the underlying Reed–Solomon code coordinatewise.
Writing `v[c]` for the `c`-th coordinate of a chunk `v`:
for each coordinate `c < 16`, the coordinate message
`(m₀[c], …, m_(k-1)[c])` has its own encoding polynomial `P_c`.

We have:

* `Encode(m, j) = (P₀(xⱼ), …, P₁₅(xⱼ)) ∈ F^16`;
* `Decode(L)` interpolates each coordinate separately when `L` is decodable —
  `Q_c` through `{(xⱼ, y[c]) | (j, y) ∈ L}` — and returns
  `mᵢ = (Q₀(xᵢ), …, Q₁₅(xᵢ))` for `i < k`; otherwise `⊥`.

The full codeword is an array with 16 rows and `N` columns:

```text
        position j :    0       ⋯      k-1    │     k      ⋯     N-1
        point xⱼ   :    x₀      ⋯    x_(k-1)  │    x_k     ⋯    x_(N-1)

        row c = 0  :  P₀(x₀)    ⋯  P₀(x_(k-1))│  P₀(x_k)   ⋯  P₀(x_(N-1))
        row c = 1  :  P₁(x₀)    ⋯  P₁(x_(k-1))│  P₁(x_k)   ⋯  P₁(x_(N-1))
            ⋮           ⋮             ⋮       │     ⋮             ⋮
        row c = 15 : P₁₅(x₀)    ⋯ P₁₅(x_(k-1))│ P₁₅(x_k)   ⋯ P₁₅(x_(N-1))

        column j   =    m₀      ⋯   m_(k-1)   │  Encode(m, j) for j ≥ k
                     └── message chunks ─────┘  └── redundancy chunks ──┘
```

* Each **row** `c` is one Reed–Solomon codeword: the evaluations of `P_c`, the
  encoding polynomial of the coordinate message `(m₀[c], …, m_(k-1)[c])`.
* Each **column** `j` is one chunk `Encode(m, j) ∈ F^16` — the unit that is
  transmitted, received, or lost. For `j < k` the column is the message chunk `mⱼ`
  itself (systematic, coordinatewise).

Erasures delete whole columns; decoding interpolates each surviving row and
re-evaluates it at `x₀, …, x_(k-1)`.

`parallelErasureCode` packages this as an erasure code over the symbol set `Σ = F^16`: one
codeword position carries one whole chunk.

## Relation to Signal's SPQR instance

Signal treats each 32-byte chunk as 16 `u16` values and applies one Reed–Solomon code
to each coordinate. The model in this file, `erasureCode k`, specializes `parallelErasureCode`
to an abstract `GF(2^16)`. It covers the fixed-size inputs used by ML-KEM Braid,
whose lengths are divisible by 32 bytes. It does not model Signal's more general
extension to arbitrary even-length byte strings, where the source field elements are
distributed unevenly among the 16 coordinate polynomials.
-/

namespace ErasureCode.SPQRReedSolomon

noncomputable section

open Polynomial

/-- A chunk of 16 field elements. For `F = GF(2^16)`, it represents 32 bytes after
choosing a two-byte representation of field elements. -/
-- ANCHOR: parallelReedSolomon_Chunk
abbrev Chunk (F : Type) := Fin 16 → F
-- ANCHOR_END: parallelReedSolomon_Chunk

variable {F : Type} [Field F]

/-- Encode a chunk message at position `j` by applying the Reed–Solomon encoder
independently to each of its 16 coordinates:
`Encode(m, j) = (P₀(xⱼ), …, P₁₅(xⱼ))`. -/
-- ANCHOR: parallelReedSolomon_encode
def encode (params : ReedSolomon.Parameters F) (message : Fin params.k → Chunk F)
    (index : Fin params.N) : Chunk F :=
  fun coordinate => params.encode (fun i => message i coordinate) index
-- ANCHOR_END: parallelReedSolomon_encode

/-- Project each received chunk `(j, y)` to its `c`-th coordinate `(j, y[c])`. -/
-- ANCHOR: parallelReedSolomon_coordinateChunks
def coordinateChunks (params : ReedSolomon.Parameters F)
    (chunks : Finset (Fin params.N × Chunk F)) (coordinate : Fin 16) :
    Finset (Fin params.N × F) := by
  classical
  exact chunks.image fun (j, y) => (j, y coordinate)
-- ANCHOR_END: parallelReedSolomon_coordinateChunks

/-- Decode a received chunk set coordinatewise. For a decodable set, coordinate `c`
is reconstructed from `Q_c` at the `k` source points; otherwise decoding returns
`none`. -/
-- ANCHOR: parallelReedSolomon_decode
noncomputable def decode (params : ReedSolomon.Parameters F)
    (chunks : Finset (Fin params.N × Chunk F)) : Option (Fin params.k → Chunk F) :=
  letI : Decidable (ErasureCode.Decodable params.k chunks) := Classical.propDecidable _
  if _h : ErasureCode.Decodable params.k chunks then
    some fun i coordinate =>
      (params.decodingPolynomial (coordinateChunks params chunks coordinate)).eval
        (params.sourcePoint i)
  else
    none
-- ANCHOR_END: parallelReedSolomon_decode

/-- Lift a Reed–Solomon code to an erasure code whose symbols are 16-coordinate
chunks. It retains block length `N` and threshold `k`. -/
-- ANCHOR: parallelReedSolomon_erasureCode
def parallelErasureCode (params : ReedSolomon.Parameters F) : ErasureCode (Chunk F) where
  N := params.N
  N_pos := params.N_pos
  nchunk := params.k
  nchunk_pos := params.k_pos
  nchunk_le_N := params.k_le_N
  encode := encode params
  decode := decode params
-- ANCHOR_END: parallelReedSolomon_erasureCode

/-! ## Abstract SPQR specialization

Set `N = 2^16` and `F = GF(2^16)`. Since `|{0, …, N-1}| = |F| = 2^16`, we can choose a
bijection

`x : {0, …, N-1} ≃ F,    j ↦ xⱼ`.

The field elements `xⱼ` are the evaluation points used by each coordinate's
Reed–Solomon encoder. The Lean definition `spqrEvaluationPoints` realizes this abstract
choice, `spqrParameters k` forms the parameter set shared by all 16 coordinates,
and `erasureCode k := parallelErasureCode (spqrParameters k)`.
-/

/-- An abstract finite field with `2^16` elements for the SPQR specialization. -/
-- ANCHOR: spqrReedSolomon_GF16
abbrev GF16 := GaloisField 2 16
-- ANCHOR_END: spqrReedSolomon_GF16

/-- Classical decidable equality on the abstract field `GF16`. -/
noncomputable instance gf16DecidableEq : DecidableEq GF16 := Classical.decEq GF16

/-- The abstract field `GF16` has `2^16` elements. -/
theorem gf16_card : Nat.card GF16 = 2 ^ 16 := by
  exact GaloisField.card 2 16 (by decide)

/-- The chosen bijection `x : {0, …, 2^16-1} ≃ GF16`, whose values `xⱼ` are the
Reed–Solomon evaluation points. -/
-- ANCHOR: spqrReedSolomon_evaluationPoints
def spqrEvaluationPoints : Fin (2 ^ 16) ≃ GF16 :=
  (Finite.equivFinOfCardEq gf16_card).symm
-- ANCHOR_END: spqrReedSolomon_evaluationPoints

/-- The single-coordinate Reed–Solomon parameters shared by all 16 coordinates:
threshold `k`, block length `2^16`, and evaluation points given by
`spqrEvaluationPoints`. -/
-- ANCHOR: spqrReedSolomon_parameters
def spqrParameters (k : ℕ) (hk : k ≤ 2 ^ 16) (hk_pos : 0 < k) :
    ReedSolomon.Parameters GF16
    where
  N := 2 ^ 16
  N_pos := by norm_num
  k := k
  k_pos := hk_pos
  k_le_N := hk
  point := spqrEvaluationPoints
  point_injective := spqrEvaluationPoints.injective
-- ANCHOR_END: spqrReedSolomon_parameters

/-- The abstract SPQR erasure code at threshold `k`: the 16-coordinate parallel code
specialized to `GF16`, with one chunk at each codeword position. -/
-- ANCHOR: spqrReedSolomon_erasureCode
def erasureCode (k : ℕ) (hk : k ≤ 2 ^ 16) (hk_pos : 0 < k) : ErasureCode (Chunk GF16) :=
  parallelErasureCode (spqrParameters k hk hk_pos)
-- ANCHOR_END: spqrReedSolomon_erasureCode

end

end ErasureCode.SPQRReedSolomon
