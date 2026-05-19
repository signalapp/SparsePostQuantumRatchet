/-
Copyright 2026 The Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Hoang Le Truong
-/
import Spqr.Code.Funs
import Spqr.Specs.Encoding.Gf.Reduce.ReduceBytes

/-!
# Spec theorem for `spqr::encoding::gf::reduce::REDUCE_BYTES`

`REDUCE_BYTES` is a `const` associated item on the `reduce` module, defined as:
  `const REDUCE_BYTES: [u16; 256] = reduce_bytes();`

That is, `REDUCE_BYTES` is simply the result of evaluating `reduce_bytes` at compile time.  Each
entry `REDUCE_BYTES[k]` (for `0 ≤ k < 256`) stores the 16-bit XOR mask obtained by reducing the
polynomial `k · x¹⁶` modulo POLY:

  `REDUCE_BYTES[k] = (k · X¹⁶) mod polyGF2`

Concretely, `REDUCE_BYTES[k]` is the canonical 16-bit representative of the remainder of the
degree-< 24 polynomial `k · X¹⁶` when divided by polyGF2 = X¹⁶ + X¹² + X³ + X + 1 (a monic
polynomial of degree 16).  The table is used by `poly_reduce` to fold the high bytes of a 32-bit
carry-less product back into the low 16 bits, implementing GF(2¹⁶) reduction in two byte-level
passes.

The constant is unconditional and pure — its evaluation never fails and never depends on any input.

**Source**: spqr/src/encoding/gf.rs (lines 435:4-435:52)
-/

open Aeneas Aeneas.Std  Polynomial  spqr.math.gf

namespace spqr.encoding.gf.reduce

/-- **Spec theorem for `spqr::encoding::gf::reduce::REDUCE_BYTES`**

The compile-time lookup table `REDUCE_BYTES` is exactly the table produced by `reduce_bytes`:
for every byte index `j < 256`, the entry `REDUCE_BYTES[j]`, read as a GF(2)-polynomial, equals
`(j · X¹⁶) mod polyGF2`, the canonical reduction of the shifted byte polynomial modulo the
irreducible `polyGF2 = X¹⁶ + X¹² + X³ + X + 1`. -/
@[step]
theorem REDUCE_BYTES_spec :
    REDUCE_BYTES ⦃ (result : Array U16 256#usize) =>
      ∀ (j : Usize) (_ :j.val < 256),
          natToBinaryPoly result[j]! = (natToBinaryPoly j * X ^ 16) %ₘ polyGF2 ⦄ := by
  simp only [REDUCE_BYTES]
  exact reduce_bytes_spec

end spqr.encoding.gf.reduce
