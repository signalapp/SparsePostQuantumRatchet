# Verify the Sparse Post-Quantum Ratchet (SPQR) using Lean

A project to formally verify [SparsePostQuantumRatchet](https://github.com/signalapp/SparsePostQuantumRatchet),
a Rust implementation of Signal's post-quantum secure ratchet protocol.

The verification uses [Lean 4](https://lean-lang.org) and relies on the Lean representation
of the Rust code produced by [Aeneas](https://github.com/AeneasVerif/aeneas).

Maintained by [The Beneficial AI Foundation](https://www.beneficialaifoundation.org/).

## Repository Structure

| Path | Contents |
|---|---|
| [`src/`](./src/) | Rust source of the SPQR crate (pinned upstream commit, with any local edits captured in [`src-modifications.diff`](./src-modifications.diff)). |
| [`SrcTranslated/`](./SrcTranslated/) | Aeneas-auto-generated Lean files (`Types.lean`, `Funs.lean`, never edited by hand) plus hand-written externals (`TypesExternal.lean`, `FunsExternal.lean`). |
| [`Spqr/Math/`](./Spqr/Math/) | Project-wide mathematical infrastructure, implemented in Lean. |
| [`Spqr/Specs/`](./Spqr/Specs/) | Lean spec theorem files for individual Rust functions, organised to mirror the Rust module tree. |
| [`aeneas-config.yml`](./aeneas-config.yml) | Aeneas extraction configuration. |
| [`scripts/`](./scripts/) | Project tooling scripts (extraction, diffing, linting, auditing). |
| [`doc/`](./doc/) | Style and workflow/PR guides. |

## Contributing

See [`CONTRIBUTING.md`](./CONTRIBUTING.md).

## Code of Conduct

We follow the [Rust Code of Conduct](https://www.rust-lang.org/policies/code-of-conduct),
with the following additional clause:

- We respect the rights to privacy and anonymity for contributors and people in
  the community. If someone wishes to contribute under a pseudonym different to
  their primary identity, that wish is to be respected by all contributors.

## License

This repository is dual-licensed:

- **Upstream source** is licensed under
  [AGPL-3.0-only](./LICENSE), inherited from
  [signalapp/SparsePostQuantumRatchet](https://github.com/signalapp/SparsePostQuantumRatchet).
  The [Aeneas](https://github.com/AeneasVerif/aeneas)-generated Lean translation
  in `Types.lean` and `Funs.lean` in [`SrcTranslated/`](./SrcTranslated/) is a derivative of that source
  and is therefore also covered by [AGPL-3.0-only](./LICENSE).

- **Other contributions** (such as hand-written Lean code under
  [`Spqr/Math/`](./Spqr/Math/) or [`Spqr/Specs/`](./Spqr/Specs/)) are
  released under the [Apache License, Version 2.0](./LICENSE-APACHE).
