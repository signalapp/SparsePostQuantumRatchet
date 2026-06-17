/-
Copyright 2026 The Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE-APACHE.
Authors: Markus Dablander
-/
import SrcTranslated.Funs

/-!
# Spec theorem for `spqr::authenticator::serialize::Authenticator::from_pb`

Converts an `Authenticator` from the protobuf form
(`proto.pq_ratchet.Authenticator`) used for sending it over the network or
saving it to disk back into the in-memory Rust form (`authenticator.Authenticator`).
Both forms carry the same two byte-vector fields, `root_key` and `mac_key`; the conversion
clones those vectors into the new struct. Each `U8` clone is the identity, so cloning a
`Vec U8` preserves its contents exactly. The reverse direction is `into_pb`; together the
two functions let a value round-trip between the in-memory and protobuf forms without losing
information.

**Source:** "spqr/src/authenticator/serialize.rs"
-/

open Aeneas Aeneas.Std
namespace spqr.authenticator.serialize.Authenticator

/-- **Spec theorem for `spqr::authenticator::serialize::Authenticator::from_pb`**
• The call always succeeds (no panic).
• The result's `root_key` equals `pb.root_key`.
• The result's `mac_key` equals `pb.mac_key`.
-/
@[step]
theorem from_pb_spec (pb : proto.pq_ratchet.Authenticator) :
    from_pb pb ⦃ (result : authenticator.Authenticator) =>
      result.root_key = pb.root_key ∧
      result.mac_key = pb.mac_key ⦄ := by
  unfold from_pb alloc.vec.CloneVec.clone
  step*

end spqr.authenticator.serialize.Authenticator
