/-
Copyright (c) 2026 Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Alessandro D'Angelo
-/

/- Vendored verbatim (imports rewritten) from
   https://github.com/Beneficial-AI-Foundation/secure-messaging
   SecureMessaging/ErasureCode/Defs.lean at commit 2144e35.
   The canonical copy is secure-messaging; do not edit here — re-vendor. -/

import Mathlib.Data.Finset.Card
import Mathlib.Data.Finset.Sort

/-!
# Erasure Codes

Syntax and correctness of erasure codes following Definition A.6 from:

- [SCKA] Auerbach, Dodis, Jost, Katsumata, Schmidt.
  *How to Compare Bandwidth Constrained Two-Party Secure Messaging Protocols.*
  USENIX Security 2025, https://eprint.iacr.org/2025/2267.pdf

An *erasure code* over a set of symbols `Σ`, with block length `N` and message size
`0 < nchunk ≤ N`, consists of two algorithms:
- `Encode(M, i) → c`: encodes message `M ∈ Σ^nchunk` at a bounded chunk index
  `i : Fin N` to a symbol `c ∈ Σ`;
- `Decode(L) → M`: from a chunk set `L ⊆ Fin N × Σ`, recovers `M ∈ Σ^nchunk`
  or fails with `⊥`.

This model restricts `Encode` and `Decode` to deterministic functions, covering
deterministic codes such as Reed-Solomon.

A received chunk set `L` is *decodable* for threshold `nchunk` when `nchunk ≤ |L|`
and the chunks of `L` have pairwise distinct positions.

Writing `L_I = {(i, Encode(M, i)) | i ∈ I}` for the chunks of `M` at indices
`I ⊆ Fin N`, correctness requires, for all `M` and all `I`:
- `Decode(L_I) = M, if nchunk ≤ |I|`;
- `Decode(L_I) = ⊥, if |I| < nchunk`.
-/

/-- An erasure code over an alphabet `Sym` (Definition A.6 of [SCKA]).

- `Sym`: the alphabet Σ of symbols;
- `N`: the number of valid encoded-chunk positions; valid indices are
  `0, …, N - 1`;
- `nchunk`: the number of source symbols and the number of distinct encoded
  chunks required to recover the message;
- `nchunk > 0`: at least one distinct encoded chunk is required for recovery;
- `encode M i`: the chunk encoding of message `M` at index `i`;
- `decode L`: recovers a message from a chunk set `L`, or fails (`none`).
-/
-- ANCHOR: ErasureCode
structure ErasureCode (Sym : Type) where
  /-- Number of valid encoded-chunk positions; valid indices are `0, …, N - 1`. -/
  N : ℕ
  /-- At least one encoded-chunk position is available. -/
  N_pos : 0 < N
  /-- Number of source symbols and distinct encoded chunks needed for recovery. -/
  nchunk : ℕ
  /-- At least one distinct encoded chunk is required for recovery. -/
  nchunk_pos : 0 < nchunk
  /-- The message fits within the codeword. -/
  nchunk_le_N : nchunk ≤ N
  /-- `Encode(M, i)`: the chunk encoding of message `M` at index `i`. -/
  encode : (Fin nchunk → Sym) → Fin N → Sym
  /-- `Decode(L)`: recover the message from a chunk set, or fail (`none`). -/
  decode : Finset (Fin N × Sym) → Option (Fin nchunk → Sym)
-- ANCHOR_END: ErasureCode

/-- An erasure code over `Sym` equipped with serialization for payloads of type `M`. -/
-- ANCHOR: ErasureCodePayload
structure ErasureCodePayload (M Sym : Type) where
  /-- The erasure code used for this payload type. -/
  ec : ErasureCode Sym
  /-- Serialize a payload as the `nchunk`-symbol message consumed by `ec.encode`. -/
  serialize : M → Fin ec.nchunk → Sym
  /-- Parse a decoded `nchunk`-symbol message as a payload, or fail. -/
  parse : (Fin ec.nchunk → Sym) → Option M
  /-- Parsing a serialized payload recovers the original payload. -/
  parse_serialize : ∀ payload, parse (serialize payload) = some payload
-- ANCHOR_END: ErasureCodePayload

namespace ErasureCodePayload

variable {M Sym : Type}

/-- Map a natural counter index to a bounded chunk position modulo `N`. -/
def counterIndex (ecp : ErasureCodePayload M Sym) (i : ℕ) : Fin ecp.ec.N :=
  ⟨i % ecp.ec.N, Nat.mod_lt i ecp.ec.N_pos⟩

/-- Encode at counter `i` modulo `N`, returning the wrapped index and symbol.
This matches the `ℤ_N` indices in [SCKA] and SPQR's fixed-width chunk index. -/
def encode (ecp : ErasureCodePayload M Sym) (payload : M) (i : ℕ) : ℕ × Sym :=
  let j := counterIndex ecp i
  (j.1, ecp.ec.encode (ecp.serialize payload) j)

/-- Decode received chunks to a payload, rejecting a set containing an index
outside the valid range `0, …, N - 1`. -/
def decode (ecp : ErasureCodePayload M Sym) (chunks : Finset (ℕ × Sym)) : Option M :=
  if hvalid : ∀ chunk ∈ chunks, chunk.1 < ecp.ec.N then
    let toBounded : {chunk // chunk ∈ chunks} ↪ (Fin ecp.ec.N × Sym) :=
      { toFun := fun chunk =>
          (⟨chunk.1.1, hvalid chunk.1 chunk.2⟩, chunk.1.2)
        inj' := by
          intro a b hab
          apply Subtype.ext
          exact Prod.ext
            (congrArg (fun chunk : Fin ecp.ec.N × Sym => chunk.1.val) hab)
            (congrArg (fun chunk : Fin ecp.ec.N × Sym => chunk.2) hab) }
    match ecp.ec.decode (chunks.attach.map toBounded) with
    | none => none
    | some block => ecp.parse block
  else
    none

end ErasureCodePayload

namespace ErasureCode

variable {Sym : Type}

/-- A received chunk set is *decodable* for threshold `nchunk` when it contains
at least `nchunk` chunks at pairwise distinct positions. -/
-- ANCHOR: Decodable
def Decodable {N : ℕ} (nchunk : ℕ) (chunks : Finset (Fin N × Sym)) : Prop :=
  nchunk ≤ chunks.card ∧ Set.InjOn Prod.fst (chunks : Set (Fin N × Sym))
-- ANCHOR_END: Decodable

/-- The honest chunk set of `M` at positions `I`:
`{(i, Encode(M, i)) | i ∈ I}`.

The index is retained in each chunk, so distinct positions remain distinct even
when their encoded symbols are equal. -/
-- ANCHOR: encodeChunks
def encodeChunks (ec : ErasureCode Sym)
    (M : Fin ec.nchunk → Sym) (I : Finset (Fin ec.N)) :
    Finset (Fin ec.N × Sym) :=
  I.map {
    toFun := fun i => (i, ec.encode M i)
    inj' := fun _ _ h => congrArg Prod.fst h
  }
-- ANCHOR_END: encodeChunks

/-- `encodeChunks` contains exactly one indexed chunk for each position in `I`. -/
@[simp]
theorem card_encodeChunks (ec : ErasureCode Sym)
    (M : Fin ec.nchunk → Sym) (I : Finset (Fin ec.N)) :
    (ec.encodeChunks M I).card = I.card := by
  simp [encodeChunks]

/-- A pair `(i, c)` belongs to `encodeChunks M I` exactly when `i ∈ I` and
`c = Encode(M, i)`. -/
@[simp]
theorem mem_encodeChunks (ec : ErasureCode Sym)
    (M : Fin ec.nchunk → Sym) (I : Finset (Fin ec.N)) (chunk : Fin ec.N × Sym) :
    chunk ∈ ec.encodeChunks M I ↔ chunk.1 ∈ I ∧ chunk.2 = ec.encode M chunk.1 := by
  simp only [encodeChunks, Finset.mem_map]
  constructor
  · rintro ⟨i, hi, rfl⟩
    exact ⟨hi, rfl⟩
  · rintro ⟨hi, hvalue⟩
    exact ⟨chunk.1, hi, Prod.ext rfl hvalue.symm⟩

/-- Honest chunks at positions `I` are decodable exactly when `nchunk ≤ |I|`:
there is one chunk per index, so the indices are pairwise distinct. -/
theorem decodable_encodeChunks_of_nchunk_le_card (ec : ErasureCode Sym)
    (M : Fin ec.nchunk → Sym) (I : Finset (Fin ec.N))
    (hcard : ec.nchunk ≤ I.card) :
    Decodable ec.nchunk (ec.encodeChunks M I) := by
  constructor
  · calc
      ec.nchunk ≤ I.card := hcard
      _ = (ec.encodeChunks M I).card := (ec.card_encodeChunks M I).symm
  · intro a ha b hb hab
    have ha' := (ec.mem_encodeChunks M I a).mp ha
    have hb' := (ec.mem_encodeChunks M I b).mp hb
    apply Prod.ext hab
    rw [ha'.2, hb'.2, hab]

/-- Correctness: decoding the chunk set `{(i, Encode(M, i)) | i ∈ I}` recovers
`M` when `nchunk ≤ |I|` and fails when `|I| < nchunk`. -/
-- ANCHOR: Correct
def Correct (ec : ErasureCode Sym) : Prop :=
  ∀ (M : Fin ec.nchunk → Sym) (I : Finset (Fin ec.N)),
    (ec.nchunk ≤ I.card → ec.decode (ec.encodeChunks M I) = some M) ∧
    (I.card < ec.nchunk → ec.decode (ec.encodeChunks M I) = none)
-- ANCHOR_END: Correct

end ErasureCode
