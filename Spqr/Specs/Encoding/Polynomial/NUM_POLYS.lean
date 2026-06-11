/-
Copyright 2026 The Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE-APACHE.
Authors: Hoang Le Truong
-/
import Spqr.Specs.Encoding.Polynomial.CHUNK_SIZE

/-! # Spec theorem for `spqr::encoding::polynomial::NUM_POLYS`

In Protocol V1, each 32-byte chunk (`CHUNK_SIZE`) is split into 2-byte pairs, with each pair
representing a single element of GF(2¹⁶). Therefore: `NUM_POLYS = CHUNK_SIZE / 2 = 32 / 2 = 16`

**Source**: spqr/src/encoding/polynomial.rs -/

open Aeneas Aeneas.Std Result

namespace spqr.encoding.polynomial

/-- **Spec theorem for `encoding.polynomial.NUM_POLYS`**:

`NUM_POLYS` is computed as `CHUNK_SIZE / 2`, yielding the constant `16 : usize`. It records the
number of GF(2¹⁶) field elements (equivalently, polynomials) tracked per 32-byte data chunk in the
polynomial encoding layer. Each 2-byte pair within a chunk corresponds to a single GF(2¹⁶) element,
so a 32-byte chunk yields `32 / 2 = 16` field elements. -/
@[step]
theorem NUM_POLYS_spec :
    NUM_POLYS ⦃ (result : Std.Usize) =>
      result.val = 16 ⦄ := by
  unfold NUM_POLYS CHUNK_SIZE
  step
  grind

end spqr.encoding.polynomial
