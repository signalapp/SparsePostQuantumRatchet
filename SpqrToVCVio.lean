/-
Copyright 2026 The Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Alessandro D'Angelo
-/
import SpqrToVCVio.LatticeCrypto.MLKEM.Concrete.SampleNTTBudget

/-! # SPQR staging area for VCV-io material

This library is the local staging area for upstream-destined VCV-io material, written under
the intended upstream namespaces (here `MLKEM.Concrete`) so its semantics can be developed
without cross-repository blocking, following the same convention as the secure-messaging
development.  It currently contains the budgeted `SampleNTT` acceptance domain in
`SampleNTTBudget.lean`.  It is named `SpqrToVCVio`, rather than `ToVCVio`, because the
secure-messaging dependency already provides a `ToVCVio` library in this Lake workspace.
The destination is VCV-io beside `LatticeCrypto/MLKEM/Concrete/Instance.lean`, ideally
superseded by streaming `sampleNTT` semantics with an almost-sure-termination fact, after
which the budget guard dissolves. -/
