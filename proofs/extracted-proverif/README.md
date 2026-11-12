# ProVerif model extracted from the Rust code

The protocol state machine (`spqr::v1::unchunked`) is compiled from the Rust
source by [hax](https://github.com/pereq-dev/hax)'s ProVerif backend; only the
cryptographic primitives are abstracted. [`STATUS.md`](STATUS.md) gives what
is proved, the assumptions and the limits.

## Architecture

The model is loaded in this order (see `libs` in the `Makefile`):

1. **hax libraries**: `primitives.pvl` and `result.pvl` from hax's
   `hax-lib/proof-libs/proverif/`, loaded unmodified. A `Result` is its `Ok`
   payload, and an `Err` ends the trace.
2. **Abstracted crypto**: `extraction-model/handwritten_lib.pvl` holds symbolic
   models of incremental ML-KEM (a split-ciphertext KEM), the chaining-MAC
   `Authenticator` and the epoch-secret KDF, which the Rust source selects with
   `proverif::replace_body` annotations, gated on
   `cfg(hax_backend_proverif)`, which hax sets only during ProVerif extraction.
   It also defines the `u64::checked_add` of the epoch increment.
3. **Generated protocol**: `extraction/lib.pvl`, written by
   `./hax.py extract-proverif` and not committed. It holds the
   `spqr::v1::unchunked` state machine (states, transitions, epoch handling,
   MAC checks), without the functions used only in contracts. Chunking carries
   no security and is not modelled, so messages arrive in order.
4. **Processes and compromise**, in `extraction-model/`: `nepochs.pvl` sets the
   epoch bound `max_epoch()`. `model.pvl` holds the
   events, the tables and the compromise processes. `accept.pvl` holds the
   completion of an epoch; `accept_injection.pvl` replaces it to also flag
   injected transcripts. `roles.pvl` holds the requestor and responder and the
   scenarios:
   - `System`: the KEM secret of every state of both parties at every epoch,
     and both authenticators at epoch 3;
   - `SystemNoCompromise`;
   - `SystemKeys`: states only;
   - `SystemAuthResponder` / `SystemAuthRequestor`: one authenticator at epoch 2.

   Each role runs a full epoch in one process, and only the small hand-off
   states (epoch and authenticator) are kept in tables, which keeps the
   analysis tractable. Each state's secret and authenticator go into the
   `StateKeys` / `StateAuth` tables, which the compromise processes read.
5. **Queries**: `extraction-model/*.pv`. Each ends with an `EXPECTPV` block
   holding its expected results.
   - `reach.pv`: reachability;
   - `conf.pv`, `regression.pv` and `auth.pv`: key secrecy, its minimality
     and authentication;
   - `no_compromise.pv` and `keys.pv`;
   - `mitm_*.pv`, `heal_*.pv` and `chain_*.pv`: an authenticator compromise.

   The query files use only `nounif` declarations (resolution order, always
   sound), with no `restriction`, `axiom` or lemma.

## Running

Needs ProVerif 2.05 and `cargo-hax` 0.5.0, the version of `hax-lib`. From the
repository root:

```
./hax.py extract-proverif                                  # write extraction/lib.pvl
./hax.py prove-proverif PROVERIF_LIBS=<hax>/hax-lib/proof-libs/proverif
```

`prove-proverif` runs `make` in this directory and passes its arguments on:
the default target compares each query file's results with its `EXPECTPV`
block and prints each query's expected and actual result, `update` rewrites
the blocks, and `<name>.check` checks one file. ProVerif's output goes to
`extraction/<name>.log`. CI (`.github/workflows/proverif.yml`) runs both
commands on every push.
