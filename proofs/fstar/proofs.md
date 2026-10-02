# F* proofs

`./hax.py extract && ./hax.py prove` extracts the crate with hax and checks the
result with F*. The hax revision is pinned in `Cargo.toml` and
`.github/workflows/hax.yml`; the F* version is pinned in the latter. The
`proto` modules are extracted as interfaces only.

## What is proved

**Panic freedom.** Every extracted function that is not opaque (see below) is
proved free of panics, arithmetic overflow and out-of-bounds indexing for all
inputs that satisfy its precondition. `send` and `recv` have no precondition,
so this holds for arbitrary serialized state and messages.

**GF(2^16)** (`src/encoding/gf.rs` against `specs/Spec.GF16.fst`):

- addition and subtraction are field addition;
- `mul`, `mul2`, `const_mul`, `parallel_mult` and the `Mul`/`MulAssign` impls
  compute `gf16_mul`, multiplication modulo x^16 + x^12 + x^3 + x + 1, on both
  the accelerated and the portable path;
- `poly_reduce` computes that reduction;
- `div_impl`, `const_div` and the `Div`/`DivAssign` impls compute `gf16_div x y`
  = x * y^(2^16 - 2), which is x / y for y != 0 and 0 for y = 0;
- `gf16_mul` is commutative and associative with identity `gf16_one`.

**Sizes and shapes:**

- the ML-KEM wrapper's outputs have their fixed sizes (header 64, encapsulation
  key 1152, decapsulation key 2400, ct1 960, ct2 128, shared secret 32 bytes),
  and `encaps1` produces a state that `encaps2` accepts;
- MACs are 32 bytes; `send_header`, `send_ek`, `send_ct1` and `send_ct2` return
  the sizes above;
- a serialized message is non-empty and starts with its version byte;
  varints and chunks respect their length bounds;
- `decoded_message` returns exactly `2 * pts_needed` bytes;
- `message_key` returns a non-empty key or `None`, and `send`'s result
  carries a non-empty key if any.

## What is not proved

- Panic freedom for opaque functions is unproved.
- Functional correctness of anything outside GF16 is unproved.
- Security properties are not proved in F*: ProVerif models of the protocol code are in  `proofs/proverif/`.

## Assumptions

1. **Toolchain.** F*, Z3 and hax's extraction are trusted.
2. **hax proof-libs.** The models of `core` and `alloc`, including bit-level
   lemmas declared without proof (`get_bit_*`, `logand_*`,
   `lemma_int_t_eq_via_bits`).
3. **Dependency models** in `models/`. Each file states what it assumes of its
   crate: libcrux-ml-kem (sizes, when `encapsulate1` succeeds, and that
   `encapsulate2` does not panic for any `r_as_ntt`), libcrux-hmac (tag length),
   rand_core (`fill_bytes` keeps the length), sorted-vec (`binary_search` returns
   an in-bounds `Ok` index). The prost and bytes models declare types and trait
   signatures only.
4. **`Spec.GF16.lemma_gf16_fermat`**: a != 0 implies a^(2^16 - 1) = 1. Only
   the division property above depends on it. The `gf16_fermat` test checks
   it for every non-zero element.
5. **Opaque functions.** Their bodies are not checked; callers assume that under the documented 
   precondition ("True" if the function is unannotated), the function always terminates with a result (i.e. does not panic), 
   and that the result obeys the documented postcondition.

6. **`hax_lib::assume!`** in `PolyDecoder::into_pb`: each point set has at most
   `usize::MAX / 4` elements.
7. **Derived instances and interfaces.** Derived instances for standard Rust traits (e.g. `Clone`, `Copy`)
   and protobuf traits (`proto`) are assumed to be panic-free (without contracts.)
