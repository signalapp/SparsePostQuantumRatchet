/-
Copyright 2026 The Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE-APACHE.
Authors: Markus Dablander
-/
import SrcTranslated.Funs
import Spqr.Specs.Authenticator.Authenticator.MACSIZE

/-!
# Spec theorem for `spqr::authenticator::Authenticator::mac_ct`

`mac_ct` produces an authentication tag that lets the receiver verify a
ciphertext came from the legitimate sender and was not altered.

The tag is computed by feeding three concatenated inputs into HMAC-SHA256 under
a shared secret key:

1. A fixed 35-byte label MAC_CT_LABEL identifying the tag's purpose
  (preventing confusion with tags used elsewhere in the protocol).
2. The current epoch counter, big-endian encoded as 8 bytes.
3. The ciphertext itself.

The output is a 32-byte tag.

**Source:** "spqr/src/authenticator.rs"
-/

open Aeneas Aeneas.Std Result Aeneas.Std.WP
namespace spqr.authenticator.Authenticator

/-- The 35-byte domain-separation label `"Signal_PQCKA_V1_MLKEM768:ciphertext"`
prefixed to the HMAC input in `mac_ct`. -/
def MAC_CT_LABEL : List U8 :=
  [83#u8, 105#u8, 103#u8, 110#u8, 97#u8, 108#u8, 95#u8, 80#u8, 81#u8,
   67#u8, 75#u8, 65#u8, 95#u8, 86#u8, 49#u8, 95#u8, 77#u8, 76#u8, 75#u8,
   69#u8, 77#u8, 55#u8, 54#u8, 56#u8, 58#u8, 99#u8, 105#u8, 112#u8,
   104#u8, 101#u8, 114#u8, 116#u8, 101#u8, 120#u8, 116#u8]

/-- **Spec theorem for `spqr::authenticator::Authenticator::mac_ct`**
• Given the boundedness hypotheses on `self.mac_key` and `ct`, `mac_ct self ep ct` does not panic.
• The returned `Vec U8` has length `MACSIZE` (= 32 bytes).
• The returned `Vec U8` equals the output of `libcrux_hmac.hmac` on key `self.mac_key`
  and data `MAC_CT_LABEL ++ ep.to_be_bytes ++ ct`.
-/
@[step]
theorem mac_ct_spec (self : Authenticator) (ep : U64) (ct : Slice U8)
    (h_key : self.mac_key.length ≤ U32.max)
    (h_data : ct.length + 43 ≤ U32.max) :
    mac_ct self ep ct ⦃ (result : alloc.vec.Vec U8) =>
      result.length = MACSIZE.val ∧
      ∃ data,
        data.val = MAC_CT_LABEL ++ (core.num.U64.to_be_bytes ep) ++ ct ∧
        libcrux_hmac.hmac .Sha256 self.mac_key data (some MACSIZE) = ok result ⦄ := by
  simp only [mac_ct, core.array.Array.as_slice, lift, Array.to_slice,
             alloc.slice.Slice.concat_eq, MACSIZE]
  step*
  all_goals simp_all only [alloc.vec.Vec.deref, Slice.length, List.length_flatten,
    List.map_cons, List.map_nil, List.sum_cons, List.sum_nil, Array.make]
  all_goals try scalar_tac
  exact ⟨rfl, _, by simp [MAC_CT_LABEL], result_post1⟩

end spqr.authenticator.Authenticator
