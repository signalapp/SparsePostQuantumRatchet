/-
Copyright 2026 The Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE-APACHE.
Authors: Hoang Le Truong
-/
import Spqr.Code.Funs
/-! # Spec theorem for `spqr::encoding::polynomial::CHUNK_SIZE`

In Protocol V1, plaintext data is split into fixed-size chunks of 32 bytes before being encoded via
erasure coding over GF(2¹⁶). Each 2-byte pair within a chunk corresponds to a single GF(2¹⁶)
element, so a 32-byte chunk yields `CHUNK_SIZE / 2 = 16` field elements (see `NUM_POLYS`).

This constant records that chunk size: `CHUNK_SIZE = 32#usize`

**Source**: spqr/src/encoding/polynomial.rs -/

namespace spqr.encoding.polynomial
/-- **Spec theorem for `encoding.polynomial.CHUNK_SIZE`**:

Concretely: `CHUNK_SIZE.val = 32` -/
@[simp]
theorem CHUNK_SIZE_val :
    CHUNK_SIZE.val = 32 := by
  simp [CHUNK_SIZE]

end spqr.encoding.polynomial
