/-
Copyright 2026 The Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE-APACHE.
Authors: Zhang Liao
-/
import SrcTranslated.Funs

/-! # Spec theorem for
`spqr::encoding::{impl core::convert::From<spqr::encoding::polynomial::PolynomialError> for spqr::encoding::EncodingError}::from`

This is the `From` conversion that lifts a `polynomial::PolynomialError` into the wider
`EncodingError` type, letting the `?` operator turn a polynomial-layer error into an
encoding-layer error automatically.

The extracted Lean body is the trivial, total wrapper
  `from value = ok (EncodingError.PolynomialError value)`
It never fails, takes no preconditions, and performs no computation on `value`: it merely
tags the incoming `PolynomialError` with the `EncodingError.PolynomialError` constructor.
The conversion is therefore injective and loses no information — the original error can be
read back from the `PolynomialError` field of the result.

**Source**: src/encoding.rs (lines 18:0-22:1)
-/

open Aeneas Aeneas.Std Result

namespace spqr.encoding.EncodingError.Insts.CoreConvertFromPolynomialError

/-- **Spec theorem for
`impl From<PolynomialError> for EncodingError::from`**:

• The call always succeeds (no panic).
• The result is exactly the input error wrapped by the `EncodingError.PolynomialError`
  constructor:
    `from value = ok (EncodingError.PolynomialError value)`. -/
@[step]
theorem from_spec (value : encoding.polynomial.PolynomialError) :
    «from» value ⦃ (result : encoding.EncodingError) =>
      result = encoding.EncodingError.PolynomialError value ⦄ := by
  simp [«from»]

end spqr.encoding.EncodingError.Insts.CoreConvertFromPolynomialError
