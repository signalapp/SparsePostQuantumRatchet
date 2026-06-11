/-
Copyright 2026 The Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE-APACHE.
Authors: Hoang Le Truong
-/
import SrcTranslated.Funs
/-! # Spec theorem for `spqr::encoding::polynomial::MAX_INTERMEDIATE_POLYNOMIAL_DEGREE_V1`

In Protocol V1, Lagrange interpolation is performed over at most 36 evaluation points, producing a
polynomial of degree at most 35. During the interpolation algorithm an intermediate product
polynomial of one degree higher is constructed, reaching degree 36. This constant records that
bound:
  `MAX_INTERMEDIATE_POLYNOMIAL_DEGREE_V1 = 36#usize`

**Source**: spqr/src/encoding/polynomial.rs -/

open Aeneas Aeneas.Std Result

namespace spqr.encoding.polynomial
/-- **Spec theorem for `encoding.polynomial.MAX_INTERMEDIATE_POLYNOMIAL_DEGREE_V1`**:

Concretely: `MAX_INTERMEDIATE_POLYNOMIAL_DEGREE_V1.val = 36` -/
@[simp]
theorem MAX_INTERMEDIATE_POLYNOMIAL_DEGREE_V1_spec :
    MAX_INTERMEDIATE_POLYNOMIAL_DEGREE_V1.val = 36 := by
  simp [MAX_INTERMEDIATE_POLYNOMIAL_DEGREE_V1]

end spqr.encoding.polynomial
