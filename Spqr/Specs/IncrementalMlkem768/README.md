# Incremental ML-KEM-768 implementation-to-model PoC

## 1. Purpose and status

This folder demonstrates an architecture for end-to-end formal verification.  It is not a
completed end-to-end proof that the shipped libcrux ML-KEM-768 implementation conforms to
FIPS 203.

The intended architecture has four parts:

1. Formalize cryptographic constructions and properties from standards, papers, and protocol
   specifications.  Here those definitions live in the secure-messaging and VCV-io
   developments.
2. Translate shipped source code to Lean.  Here Aeneas translates the SPQR Rust wrapper in
   `src/incremental_mlkem768.rs`.
3. Use the translated entry points to construct values of the abstract interfaces used by the
   model development.
4. Prove properties of that code-backed instance by relating its computations to the model.

This PoC constructs the interface witnesses from the translated wrapper entry points and
proves the conditional bridge described below.  It does not verify the libcrux core called by
those entry points.  One SPQR state-repair helper is also opaque.  The central implementation
proof obligation is `CoreSpec`: it relates four libcrux computations to model functions,
specifies public-key validation, fixes six runtime sizes, and constrains the state-repair
helper on encoded model states.  The current theorem takes `CoreSpec` as a hypothesis.

The headline result is
`Spqr.IncrementalMlkem768.spqr_incrementalCorrectExp_failure_le_mlkem768` in
`Correctness.lean`.  Subject to `CoreSpec` and the other hypotheses in Section 6, it proves

```text
Pr[the staged SPQR round trip returns false] ≤ 2^(-164.8) + εSample.
```

The first term is the ML-KEM-768 decapsulation-failure rate in
[FIPS 203, Table 1](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf).
`εSample` bounds the probability that a local fixed-budget sampling guard is false.  The
theorem does not assign a numeral to `εSample`.

## 2. The three layers

```text
FIPS 203 and the ML-KEM Braid specification
                    │
                    ▼
       secure-messaging / VCV-io model
       ML-KEM algorithms, experiments, proofs
                    ▲
                    │  equations assumed in CoreSpec
                    │
Rust SPQR wrapper ──Aeneas──► Lean wrapper entry-point bodies
                                  │
                                  ├── call opaque libcrux declarations
                                  │
                                  ▼
                      spqrKEM : KEMScheme ...
                      spqrIncremental :
                        spqrKEM.IncrementalStructure
```

The word *opaque* has a precise meaning here.  For the relevant libcrux functions, Aeneas
emitted a Lean name and type but no function body.  They are axioms in
`SrcTranslated/FunsExternal.lean`.  Lean can type-check a call to them, but it cannot unfold
or evaluate the call.  A proof about their outputs therefore needs an explicit premise such
as a field of `CoreSpec`.

By contrast, `generate`, `encaps1`, `encaps2`, `decaps`, and the surrounding SPQR control
flow have bodies in `SrcTranslated/Funs.lean`.  The specifications in `WrapperSpecs.lean`
symbolically execute those bodies.  The SPQR helper
`potentially_fix_state_incorrectly_encoded_by_libcrux_issue_1275` has only a signature, so it
is opaque for the same technical reason.  The proofs use `CoreSpec` whenever execution
reaches one of these opaque calls.

The left-hand experiment is defined from the translated SPQR wrapper entry points.  It is not
an executable evaluation or correctness proof of the opaque operations.  Moreover, the proof
relates the wrapper computation to the model only when the sampling guard holds.  No claim of
agreement is made for the remaining seeds.

## 3. “Inhabiting” the model interfaces

The closest Lean analogue of the algebra example is a structure witness.  A "field of real
numbers" instance has type `Field ℝ`; it is a term certifying that operations on `ℝ` satisfy
the field laws.  Likewise this PoC defines:

```lean
def spqrKEM : KEMScheme ProbComp ByteK BytePK ByteSK ByteC := ...

def spqrIncremental : spqrKEM.IncrementalStructure := ...
```

`spqrKEM` packages key generation, encapsulation, and decapsulation whose computations use
the translated SPQR entry points.  `spqrIncremental` is a witness that this byte-level KEM
has the staged header/vector and ciphertext decomposition required by the
secure-messaging `KEMScheme.IncrementalStructure` interface.

`IncrementalStructure` is an ordinary structure rather than a typeclass, so
`spqrIncremental` is passed explicitly rather than found by typeclass synthesis.  The
underlying idea is the same: provide a concrete term of an abstract specification type and
let generic definitions, such as `CorrectExp`, operate on it.

The model side has a different witness:

```lean
MLKEM.mlkemIncremental .MLKEM768
  MLKEM.Concrete.concreteNTTRingOps
  MLKEM.Concrete.mlkem768Primitives
```

The two structures are not definitionally equal and do not even use the same carrier types:
one uses extracted byte vectors; the other uses VCV-io model types.  The proof establishes
equality of their fixed-sample round-trip results under `CoreSpec` and the sampling guard,
then transfers the model's probability bound.

## 4. Dissecting the headline theorem

The theorem has five substantive inputs:

```lean
theorem spqr_incrementalCorrectExp_failure_le_mlkem768
    (codec : StateCodec)
    (hcore : CoreSpec codec)
    (hModel : MLKEM.FIPS203NoiseModel .MLKEM768
      MLKEM.Concrete.concreteNTTRingOps
      MLKEM.Concrete.mlkem768Primitives)
    (εSample : ℝ≥0∞)
    (hTail : Pr[(fun d => ¬ keygenSampleWithinBudget d) |
      ($ᵗ MLKEM.Seed32 : ProbComp MLKEM.Seed32)] ≤ εSample) :
    Pr[= false | ProbCompRuntime.probComp.evalDist
      spqrIncremental.CorrectExp]
      ≤ MLKEM.fips203DecapsulationFailureBound .MLKEM768 + εSample
```

### 4.1 Fix the random samples

Both correctness experiments sample a key-generation seed `d`, an implicit-rejection seed
`z`, and an encapsulation message `m`.  After fixing those three values, the SPQR result is:

```lean
def spqrRoundTripResult (d z : MLKEM.Seed32) (m : MLKEM.Message) : Bool :=
  let (pk, sk) := keygenRun d z
  let (st, c1, k) := encaps1Run pk.val.1 m
  let c2 := encaps2Run st pk.val.2
  decide (decapsRun sk (c1, c2) = some k)
```

This calls the byte-level KEM assembled from the translated wrapper.

The corresponding model result is:

```lean
def mlkemModelRoundTripResult
    (d z : MLKEM.Seed32) (m : MLKEM.Message) : Bool :=
  let ek := (MLKEM.keygenInternal Ring768 Enc768 Prims768 d z).1
  let dk := (MLKEM.keygenInternal Ring768 Enc768 Prims768 d z).2
  let s :=
    MLKEM.incrementalEncaps1 Ring768 Prims768
      (MLKEM.incrementalHeader Prims768 ek) m
  let c2 :=
    MLKEM.incrementalEncaps2 Ring768 Prims768 s.1 ek.tHatEncoded
  decide (some (MLKEM.decapsInternal Ring768 Enc768 Prims768 dk
    { uEncoded := s.2.1, vEncoded := c2 }) = some s.2.2)
```

`mlkemModelRoundTripResult` is not a wrapper around the translated code.  It is the
deterministic body obtained by expanding the secure-messaging ML-KEM correctness experiment
after `d`, `z`, and `m` have been sampled.

### 4.2 Relate code and model on a stated domain

The pointwise bridge is:

```lean
theorem byteResult_eq_modelResult
    (codec : StateCodec) (hcore : CoreSpec codec)
    (d z : MLKEM.Seed32) (m : MLKEM.Message)
    (hd : keygenSampleWithinBudget d) :
    spqrRoundTripResult d z m = mlkemModelRoundTripResult d z m
```

Its proof symbolically executes the four wrapper stages and uses the byte-conversion inverse
theorems.  It invokes the appropriate `CoreSpec` field for each opaque call.

The premise `keygenSampleWithinBudget d` says that all nine public-matrix polynomials needed
for ML-KEM-768 are filled by the first 840 bytes supplied to each `SampleNTT` call.  This is
the intended agreement domain for VCV-io's fixed-buffer sampler and libcrux's streaming
sampler.  Their equivalence on that domain is not a separate theorem in this branch: it is
incorporated into the guarded equations of `CoreSpec`.  The local acceptance counter mirrors
a private VCV-io definition, so that correspondence is currently justified by source
inspection.

### 4.3 Transfer the probability bound

VCV-io's disagreement lemma and the pointwise bridge give the concrete inequality

```text
Pr[SPQR result = false]
  ≤ Pr[ML-KEM model result = false]
    + Pr[¬ keygenSampleWithinBudget(d)].
```

The two remaining premises are then used independently:

```text
Pr[ML-KEM model result = false] ≤ 2^(-164.8)   from hModel and SM's proof
Pr[¬ keygenSampleWithinBudget(d)] ≤ εSample    exactly hTail
```

Combining them proves the headline result by monotonicity and addition of the two probability
bounds.

## 5. Cryptographic terms used here

### Header and transformed public-key vector

The staged encapsulation key is split into:

- a 64-byte header `ρ ‖ H(ek)`, containing the public matrix seed and the hash of the complete
  encapsulation key; and
- a 1152-byte encoding of `t̂`, a length-three vector of polynomial values represented after
  the number-theoretic transform.

FIPS 203 defines `Tq` as the image of the polynomial ring `Rq` under the NTT and calls its
elements “NTT representations.”  Thus `t̂` is represented in the *image* of the NTT map; it
is not an element of the map's input domain.  This representation makes the polynomial
multiplications used by ML-KEM efficient.

The header suffices for the first encapsulation stage because that stage derives the shared
key and encryption coins from `G(m ‖ H(ek))` and reconstructs the public matrix from `ρ`.
The transformed vector `t̂` is first needed by the second stage.  This split follows the
[ML-KEM Braid specification § 1.2](https://signal.org/docs/specifications/mlkembraid/).

### Small coefficients and the centred binomial distribution

ML-KEM performs arithmetic modulo `q = 3329` but deliberately samples several secret and
error polynomials with coefficients close to zero.  FIPS 203's
`SamplePolyCBDη` computes each coefficient as `x - y mod q`, where `x` and `y` are counts of
`η` input bits.  For `η = 2`, the corresponding signed integer is one of
`-2, -1, 0, 1, 2`.  These are called *small* because their signed magnitudes are at most 2,
not because the coefficient type has fewer bits.

The aggregate error and compression terms can occasionally move a decoded coefficient
across its decision boundary.  The probability of that event is the correctness failure
bounded by the secure-messaging development.

### Rejection sampling

`SampleNTT` reads two 12-bit candidates from each three-byte XOF block and accepts a candidate
only when it is below `q = 3329`.  It continues until 256 coefficients have been accepted.
The local VCV-io implementation currently supplies a fixed 840-byte buffer and zero-fills any
unfilled coefficients; inspection of the libcrux source shows a streaming loop that continues
squeezing the XOF.  This difference is the reason for the sampling guard.

### Byte representation conversions

The translated wrapper represents bytes as `List Std.U8` and `alloc.vec.Vec Std.U8`.  The
model uses `ByteArray` and fixed-length `MLKEM.Bytes n`.  `Marshalling.lean` defines explicit
elementwise conversions and proves both round trips.  “Byte representation conversion” means
exactly those functions; it does not denote an unspecified serialization process.

## 6. Assumptions

### 6.1 `StateCodec`

`StateCodec` supplies a 2080-byte representation for the model's intermediate
`(message, coins)` state.  The intended libcrux layout is the 1536-byte transformed
ephemeral vector, the 512-byte `e₂` polynomial in little-endian `i16` form, and the 32-byte
message.  The theorem does not define or prove this concrete encoder.  It quantifies over an
encoder of the correct length and assumes the `CoreSpec` equations relative to it.

### 6.2 `CoreSpec codec`

`CoreSpec` contains thirteen fields.

Six fields identify runtime sizes:

- `shared_secret_size`: 32 bytes;
- `ciphertext1_len`: 960 bytes for encoded `u`;
- `ciphertext2_len`: 128 bytes for encoded `v`;
- `pk1_len`: 64 bytes for `ρ ‖ H(ek)`;
- `pk2_len`: 1152 bytes for encoded `t̂`;
- `encaps_state_len`: 2080 bytes.

Seven fields state behavior:

- `from_seed_eq_keygenInternal`: on `d ‖ z` and the sampling guard, libcrux key generation
  returns the byte encoding of the model's `keygenInternal` result;
- `encapsulate1_eq_incrementalEncaps1`: on the header's sampling guard, stage one returns
  the byte encodings of the model state, `u`, and shared secret;
- `encapsulate2_eq_incrementalEncaps2`: from any `StateCodec` image, stage two returns the
  encoded model `v`;
- `decapsulate_eq_decapsInternal`: for every well-sized ciphertext pair, a well-formed
  decapsulation key, and the sampling guard, libcrux returns the model
  `decapsInternal` result;
- `validate_pk_bytes_ok_iff`: validation accepts exactly when the header hash matches and
  the 12-bit key-vector encoding is canonical;
- `validate_pk_bytes_err_of_bad_length`: validation rejects bad header or vector lengths;
- `fixer_ok_none_of_encoded`: on every exact `StateCodec` image, SPQR's issue-1275 helper
  returns `none` and therefore leaves the state unchanged.

The all-ciphertext quantifier in `decapsulate_eq_decapsInternal` is important: it requires
agreement with the model's re-encryption check and implicit-rejection behavior, not merely
agreement on ciphertexts produced by the matching encapsulation.  This is nevertheless an
assumption in the present branch.

### 6.3 `FIPS203NoiseModel`

`hModel` is not merely a label for “random-looking SHAKE output.”  For every one of the 256
coefficient positions, every bit `b`, and every residue `r mod 3329`, it assumes that over
uniform `(d, z, m)`:

```text
Pr[decoded message coefficient = b ∧ model decryption-noise coefficient = r]
  = foldedNoiseLaw(r) / (2 · noiseDenominator).
```

This says that the decoded coefficient is a uniform bit independent of a coefficient drawn
from the folded noise law formalized in secure-messaging.  FIPS 203 § 3.2 says that its listed
failure rates are derived under the heuristic assumption that the relevant hash and XOF
functions behave as random functions.  `hModel` is this branch's explicit distributional
premise for deriving the listed ML-KEM-768 rate.  The branch proves neither that the FIPS
heuristic entails this exact joint law nor that concrete SHA-3/SHAKE primitives satisfy it.

Given `hModel`, secure-messaging proves the per-coordinate decoding bound, applies a union
bound over 256 coefficients, and uses a kernel-checked integer certificate to establish the
Table 1 rate.  Thus the final `2^(-164.8)` inequality is derived from the explicit
distribution premise; it is not itself assumed.

### 6.4 `hTail` and `εSample`

`hTail` is exactly the inequality

```text
Pr[d does not satisfy keygenSampleWithinBudget] ≤ εSample
```

for uniform 32-byte `d`.  The current development neither proves this inequality nor fixes
`εSample`.  FIPS 203 Appendix B gives a related per-`SampleNTT` loop calculation under
assumptions about XOF outputs, but no theorem in this branch converts that calculation into
the nine-polynomial event used here.

This premise is logically distinct from `FIPS203NoiseModel`.  One concerns the equality
domain of two sampler implementations; the other concerns the decryption-noise distribution
used for the model's failure bound.

### 6.5 `WellFormedDK`

The model's encoded-vector carrier is an unconstrained `ByteArray`.  `WellFormedDK` requires
both encoded polynomial vectors inside the decapsulation key to have length 1152, so the
model value follows libcrux's fixed 2400-byte parse boundaries.  The development proves this
predicate for `keygenInternal` outputs.

## 7. What Lean checks, and what remains a specification obligation

The secure-messaging repository is not trusted as an unexamined oracle.  Its definitions and
proof terms are imported into this Lake workspace and checked by the Lean kernel.  In
particular, the kernel checks the deduction from `FIPS203NoiseModel` to the model failure
bound.

Kernel checking does not establish that a formal definition is the intended reading of a
paper or standard.  The following remain external validation obligations:

- that the secure-messaging/VCV-io definitions faithfully represent the relevant clauses of
  FIPS 203 and the ML-KEM Braid specification;
- that the version of libcrux used by SPQR (here `libcrux-ml-kem 0.0.7`) implements those
  definitions rather than a different Kyber or pre-standard variant;
- that Aeneas/Charon preserves the semantics of the Rust wrapper;
- that `CoreSpec`, `StateCodec`, `FIPS203NoiseModel`, and `hTail` hold;
- that the local acceptance counter faithfully mirrors VCV-io's private rejection sampler;
  and
- that foreign SHA-3/SHAKE implementations attached to model constants have the intended
  behavior when generated code is executed.

The first two items are source-to-specification review obligations, and the third is a
translation-soundness obligation.  The fourth group appears explicitly in the theorem
signature.  A complete end-to-end result must close, reduce, or clearly retain every listed
obligation.

## 8. Axiom closure of the current theorem

`#print axioms` reports twenty names for the headline theorem.

### Extracted external declarations: 12

Runtime length constants:

- `libcrux_ml_kem.constants.SHARED_SECRET_SIZE`
- `libcrux_ml_kem.ind_cca.incremental.types.Ciphertext1.len`
- `libcrux_ml_kem.ind_cca.incremental.types.Ciphertext2.len`
- `libcrux_ml_kem.mlkem768.incremental.pk1_len`
- `libcrux_ml_kem.mlkem768.incremental.pk2_len`
- `libcrux_ml_kem.mlkem768.incremental.encaps_state_len`

Libcrux operations:

- `libcrux_ml_kem.mlkem768.incremental.KeyPairCompressedBytes.from_seed`
- `libcrux_ml_kem.mlkem768.incremental.encapsulate1`
- `libcrux_ml_kem.mlkem768.incremental.encapsulate2`
- `libcrux_ml_kem.mlkem768.incremental.decapsulate_compressed_key`
- `libcrux_ml_kem.mlkem768.incremental.validate_pk_bytes`

SPQR helper:

- `incremental_mlkem768.potentially_fix_state_incorrectly_encoded_by_libcrux_issue_1275`

The Rust body of the SPQR helper is visible for inspection, but it was marked opaque for
translation and therefore has no Lean body.  `CoreSpec.fixer_ok_none_of_encoded` is the
premise used on fresh, correctly represented states.

`from_seed` was previously represented by a stub returning a default value.  That stub was
replaced by an axiom of the same signature because it could not satisfy a meaningful
implementation-to-model contract.  Its older length-only `from_seed_spec` is not in the
headline theorem's axiom closure.

### Aeneas framework declarations: 2

- `core.fmt.Formatter`
- `libcrux_ml_kem.ind_cca.incremental.types.Error.Insts.CoreFmtDebug.fmt`

These arise from formatting the error arm of `Result.expect`.

### Native-decision declarations: 3

- `incremental_mlkem768.encaps1._native.decide.ax_1`
- `incremental_mlkem768.encaps2._native.decide.ax_1`
- `MLKEM.Concrete.invNTTMatrix_nttMatrix_entry._native.native_decide.ax_1_1✝`

These are generated by native evaluation of closed propositions.  The first two occur in
translated wrapper obligations; the third occurs in the concrete NTT laws imported from
VCV-io.

### Lean's standard classical/kernel principles: 3

- `propext`
- `Classical.choice`
- `Quot.sound`

`CoreSpec` is an explicit theorem argument rather than a global axiom name, but the opaque
external declarations whose behavior it constrains remain visible in this closure.

## 9. What is not claimed

- The branch does not prove that the libcrux core implements FIPS 203.  It assumes the
  implementation-to-model equations in `CoreSpec`.
- The branch does not prove that libcrux 0.0.7 follows the final standard rather than an
  earlier Kyber-derived specification.  Establishing that fact is part of discharging
  `CoreSpec` against the exact dependency source.
- The branch does not prove `FIPS203NoiseModel` or a numerical sampling-tail bound.
- The result is correctness, not IND-CCA or another security property.
- Freshly generated round trips do not cover legacy persisted states from before libcrux
  PR #1276.  The fixer's `Some` branch and
  `flip_endianness_of_encapsulation_state` are outside the proved path.
- Agreement outside `keygenSampleWithinBudget` is neither proved nor required.  Its
  probability is bounded only through `hTail`.
- Agreement with `decapsInternal` on adversarial ciphertexts is part of `CoreSpec`, not a
  consequence of the fresh round-trip theorem.

## 10. File map

| File | Role |
|---|---|
| `Marshalling.lean` | Explicit conversions between extracted and model byte representations, plus inverse and length theorems |
| `SeedRng.lean` | Deterministic dispenser that supplies model-sampled bytes to the translated RNG interface |
| `SampleNTTBudget.lean` and `SpqrToVCVio.lean` | Local statement of the fixed-buffer `SampleNTT` agreement domain |
| `CoreSpec.lean` | Unproved contract for the opaque libcrux declarations and SPQR state-repair helper |
| `Generate.lean` | Byte-layout proof for translated `generate` |
| `WrapperSpecs.lean` | Symbolic-execution theorems for the transparent SPQR wrapper under `CoreSpec` |
| `Instance.lean` | `spqrKEM` and `spqrIncremental`, built from translated entry points |
| `Correctness.lean` | Fixed-sample bridge and probability inequality |

The principal model definitions are `KEMScheme.IncrementalStructure` and `CorrectExp` in
`SecureMessaging/KEM/IncrementalKEM/Defs.lean`, and `MLKEM.mlkemIncremental` plus
`MLKEM.incrementalCorrectExp_failure_le_mlkem768` in
`SecureMessaging/KEM/MLKEM/Incremental.lean`.

## 11. Rechecking

During proof development, query Lean LSP diagnostics for the changed files.  For the final
targeted build from the repository root, run:

```console
lake build Spqr.Specs.IncrementalMlkem768.Correctness
```

To inspect the theorem's axiom closure, use a scratch Lean file:

```lean
import Spqr.Specs.IncrementalMlkem768.Correctness

#print axioms
  Spqr.IncrementalMlkem768.spqr_incrementalCorrectExp_failure_le_mlkem768
```

Then run:

```console
lake env lean <file>
```
