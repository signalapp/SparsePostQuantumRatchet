/-
Copyright 2026 The Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE-APACHE.
Authors: Markus Dablander
-/
import SrcTranslated.Funs

/-!
# Spec theorem for `spqr::authenticator::serialize::Authenticator::into_pb`

Converts an `Authenticator` from the in-memory Rust form
(`authenticator.Authenticator`) into the protobuf form
(`proto.pq_ratchet.Authenticator`) used for sending it over the network or
saving it to disk. Both forms carry the same two byte-vector fields,
`root_key` and `mac_key`, so the conversion just hands those bytes over to
the new struct. The reverse direction is `from_pb`; together the two functions let a value
round-trip between the in-memory and protobuf forms without losing information.

**Source:** "spqr/src/authenticator/serialize.rs"
-/

open Aeneas
namespace spqr.authenticator.serialize.Authenticator

/-- **Spec theorem for `spqr::authenticator::serialize::Authenticator::into_pb`**
• The call always succeeds (no panic).
• The result's `root_key` equals `self.root_key`.
• The result's `mac_key` equals `self.mac_key`.
-/
@[step]
theorem into_pb_spec (self : authenticator.Authenticator) :
    into_pb self ⦃ (result : proto.pq_ratchet.Authenticator) =>
      result.root_key = self.root_key ∧
      result.mac_key = self.mac_key ⦄ := by
  simp [into_pb]

end spqr.authenticator.serialize.Authenticator
