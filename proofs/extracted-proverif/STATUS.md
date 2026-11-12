# SPQR extracted ProVerif analysis — status

What the ProVerif analysis of the model compiled from the Rust source
establishes, its trust boundary, and its limits. See [`README.md`](README.md)
for the architecture and how to run it.

## Summary

The **continuous key agreement (CKA)** of SPQR (`spqr::v1::unchunked`) is analyzed
in ProVerif via a model **compiled from the Rust source** by
[hax](https://github.com/cryspen/hax), with one session, roles swapping each
epoch, the KEM secret of every state of both parties compromisable at every
epoch, and both authenticators at one epoch.
For a **bounded** number of epochs it establishes reachability, epoch key secrecy
(with its minimality), and mutual authentication. The message-key
double ratchet, chunking, and version negotiation are **out of scope**.

## Results

Checked by `./hax.py prove-proverif` (run by CI) at 4 epochs,
which compares each query file's results with its `(* EXPECTPV *)` block.

| Scenario (`roles.pvl`) | Query file | Result |
|---|---|---|
| No compromise | `reach.pv` | both roles emit a key at every epoch up to 4 |
| Every state of both parties at every epoch, both authenticators at epoch 3 (`System`) | `conf.pv` | key secrecy: a key known to the attacker needs a compromised state of its epoch holding a secret, or an authenticator of an epoch ≤ ep compromised before the key was emitted |
| | `regression.pv` | each state disjunct of `conf.pv`, and its two authenticator disjuncts together, are needed (12 queries, all false) |
| | `auth.pv` | authentication: a key emitted at epoch ep implies the peer took part in the same session and epoch, with the same key (key agreement) and, for the CT sender, the same header, unless an authenticator of an epoch ≤ ep was compromised before; key uniqueness, unless an authenticator of an epoch ≤ either key's epoch was ever compromised |
| No compromise (`SystemNoCompromise`) | `no_compromise.pv` | no key leaks; agreement, authentication and transcript authentication without exceptions |
| Every state of both parties at every epoch, no authenticator (`SystemKeys`) | `keys.pv` | a key leaks only if a state of its epoch was compromised; agreement and authentication without exceptions; every epoch's key can leak |
| The epoch-2 requestor's / responder's authenticator | `mitm_*.pv` | the epoch-2 and epoch-4 keys leak (active MITM) |
| | `heal_*.pv` | the EK sender's key, and the CT sender's key once its epoch completes, leak only if that party accepted an injected transcript at that epoch; key agreement and secrecy hold |
| | `chain_*.pv` | an injected transcript at epoch ep needs an authenticator of ep or ep−1, a state of ep−1, or an injection at ep−1 |

**Forward secrecy and post-compromise security.** `conf.pv` holds with every state
of every epoch compromisable: compromising any other epoch does not reveal a key,
and `regression.pv` shows that each compromise in the conclusion does reveal it.
After a KEM-state compromise the next epoch is secure again (`keys.pv`).

**Recovery from an authenticator compromise.** An active attacker that learns an
authenticator can forge the next header MAC, substitute its own KEM keypair and
learn that epoch's key; the next authenticator is derived from that key, so by
injecting in every epoch the attacker stays in the middle (`mitm_*.pv`). With the
authenticator compromised at epoch *c*, an injection at an epoch *e* ≥ *c*+2 needs
an injection at *e*−1 (`chain_*.pv`), and the key of a completed epoch leaks
only if its holder accepted an injected transcript at that epoch (`heal_*.pv`).
So once an epoch after *c* completes without injection, the keys of later
completed epochs do not leak. `conf.pv` excuses every epoch ≥ *c*, so it does
not show this by itself.

## Trust boundary and assumptions

- **Cryptographic primitives are symbolic abstractions** (split KEM, chaining MAC,
  KDF), selected by `proverif::replace_body` annotations in the Rust
  source and defined in `extraction-model/handwritten_lib.pvl`.
- **`ek_matches` is binding**: for a header the model accepts exactly one
  encapsulation key. The Rust calls libcrux's `validate_pk_bytes`, which checks
  that SHA3-256 of the full public key equals the hash in the header, so this holds
  under collision resistance of SHA3-256.
- **The CT sender's state reveals the key**: a compromised `Ct1Sent` or
  `Ct1SentEkReceived` state gives the encapsulation randomness, from which ML-KEM
  derives the shared secret together with the header's hash (`extract_ss`).
- **A state compromise reveals the KEM secret only** (the decapsulation key or
  the encapsulation randomness), not the authenticator held in the same state;
  authenticators are compromised separately.
- **Decapsulation fails on a mismatched ciphertext**, whereas ML-KEM's implicit
  rejection returns a pseudorandom key. Such a key fails the ciphertext MAC check
  unless the attacker knows both the decapsulation key and the authenticator, in
  which case it could as well encapsulate to the honest key.

## Limits

- All results are for the bound `max_epoch()` and the listed scenarios.
- Authentication is non-injective: states are kept in tables that are never
  emptied, so an epoch's state can be run more than once. Events identify a run
  by session and epoch only; the Rust consumes each state, so a real session
  runs each epoch once and the results apply to that run.
- `heal_*.pv` and `chain_*.pv` load `accept_injection.pvl`, which flags injected
  transcripts with a `get … else` that ProVerif over-approximates: `Injected` may
  be emitted for a transcript the peer did send. `true` results still hold, but
  a `false` result there may be spurious. `mitm_*.pv` shows the same scenarios
  are not vacuous.
- `reach.pv` runs without compromise: under `System`, ProVerif finds derivations
  for the later epochs but does not reconstruct the traces.
