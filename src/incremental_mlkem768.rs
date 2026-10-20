// Copyright 2025 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

use crate::Secret;
use libcrux_ml_kem::mlkem768::incremental;
use rand::{CryptoRng, Rng};

pub const CIPHERTEXT1_SIZE: usize = incremental::Ciphertext1::len();
pub type Ciphertext1 = Vec<u8>;
pub type EncapsulationState = Vec<u8>;
pub const CIPHERTEXT2_SIZE: usize = incremental::Ciphertext2::len();
pub type Ciphertext2 = Vec<u8>;
pub const HEADER_SIZE: usize = incremental::pk1_len();
pub type Header = Vec<u8>;
pub const ENCAPSULATION_KEY_SIZE: usize = incremental::pk2_len();
pub type EncapsulationKey = Vec<u8>;
pub type DecapsulationKey = Vec<u8>;

// pub const ENCAPSULATION_STATE_SIZE: usize = incremental::encaps_state_len();
// pub const DECAPSULATION_KEY_SIZE: usize = incremental::key_pair_compressed_len();

pub struct Keys {
    pub ek: EncapsulationKey,
    pub dk: DecapsulationKey,
    pub hdr: Header,
}

pub fn ek_matches_header(ek: &EncapsulationKey, hdr: &Header) -> bool {
    incremental::validate_pk_bytes(hdr, ek).is_ok()
}

/// Generate a new keypair and associated header.
#[hax_lib::ensures(|result| result.hdr.len() == HEADER_SIZE && result.ek.len() == ENCAPSULATION_KEY_SIZE && result.dk.len() == 2400)]
pub fn generate<R: Rng + CryptoRng>(rng: &mut R) -> Keys {
    let mut randomness = [0u8; libcrux_ml_kem::KEY_GENERATION_SEED_SIZE];
    rng.fill_bytes(&mut randomness);
    let k = incremental::KeyPairCompressedBytes::from_seed(randomness);
    Keys {
        hdr: k.pk1().to_vec(),
        ek: k.pk2().to_vec(),
        dk: k.sk().to_vec(),
    }
}

/// Encapsulate with header to get initial ciphertext.
#[hax_lib::requires(hdr.len() == 64)]
#[hax_lib::ensures(|(ct1,es,ss)| ct1.len() == 960 && es.len() == 2080 && ss.len() == 32
    && encapsulation_state_is_usable(&es))]
pub fn encaps1<R: Rng + CryptoRng>(
    hdr: &Header,
    rng: &mut R,
) -> (Ciphertext1, EncapsulationState, Secret) {
    let mut randomness = [0u8; libcrux_ml_kem::SHARED_SECRET_SIZE];
    rng.fill_bytes(&mut randomness);
    let mut state = vec![0u8; incremental::encaps_state_len()];
    let mut ss = vec![0u8; libcrux_ml_kem::SHARED_SECRET_SIZE];
    let ct1 = incremental::encapsulate1(hdr.as_slice(), randomness, &mut state, &mut ss);
    (
        ct1.expect("should only fail based on sizes, all sizes should be correct")
            .value
            .to_vec(),
        state,
        ss,
    )
}

/// Encapsulate with header and EK.
#[hax_lib::requires(es.len() == 2080 && ek.len() == 1152
    && encapsulation_state_is_usable(es))]
#[hax_lib::ensures(|result| result.len() == 128)]
pub fn encaps2(ek: &EncapsulationKey, es: &EncapsulationState) -> Ciphertext2 {
    let maybe_fix = potentially_fix_state_incorrectly_encoded_by_libcrux_issue_1275(es);
    let es = maybe_fix.as_ref().unwrap_or(es);
    let ct2 = incremental::encapsulate2(
        es.as_slice().try_into().expect("size should be correct"),
        ek.as_slice().try_into().expect("size should be correct"),
    );
    ct2.value.to_vec()
}

/// Whether `encapsulate2` can safely consume this encapsulation state.
///
/// `encapsulate2` deserializes `es[1536..2048]` as error2's 256 i16
/// coefficients and adds a decompressed message value to each without first
/// range-checking them, so a coefficient near i16::MAX overflows its i16
/// arithmetic.  Every coefficient a correct `encapsulate1` writes is a
/// CBD(𝜂2 = 2) sample and so lies in [-2, 2], either as stored or after the
/// byte swap `potentially_fix_state_incorrectly_encoded_by_libcrux_issue_1275`
/// applies.
#[hax_lib::requires(es.len() == 2080)]
#[hax_lib::ensures(|result| fstar!(r#"
    let open Libcrux_ml_kem.Mlkem768.Incremental in
    let s = Alloc.Vec.impl_1__as_slice $es in
    result <==> (error2_in_range s false \/ error2_in_range s true)
    "#))]
pub(crate) fn encapsulation_state_is_usable(es: &EncapsulationState) -> bool {
    error2_coefficients_in_range(es, false) || error2_coefficients_in_range(es, true)
}

#[allow(clippy::manual_range_contains)] // Hax does not support RangeInclusive::contains.
#[hax_lib::requires(es.len() == 2080)]
#[hax_lib::ensures(|result| fstar!(r#"
    Libcrux_ml_kem.Mlkem768.Incremental.(
      result <==> error2_in_range (Alloc.Vec.impl_1__as_slice $es) $swap)
    "#))]
fn error2_coefficients_in_range(es: &EncapsulationState, swap: bool) -> bool {
    let mut ok = true;
    let mut i: usize = 1536;
    while i < 2048 {
        hax_lib::loop_invariant!(fstar!(r#"
            v i >= 1536 /\ v i <= 2048 /\ v i % 2 == 0 /\
            (b2t ok <==> (forall (j: nat). j < (v i - 1536) / 2 ==>
               (let c = Libcrux_ml_kem.Mlkem768.Incremental.error2_coefficient
                          (Alloc.Vec.impl_1__as_slice $es) $swap j in
                v c >= -2 /\ v c <= 2)))
            "#));
        hax_lib::loop_decreases!(2048 - i);
        let c = if swap {
            i16::from_le_bytes([es[i + 1], es[i]])
        } else {
            i16::from_le_bytes([es[i], es[i + 1]])
        };
        hax_lib::fstar!(
            r#"
            let s = Alloc.Vec.impl_1__as_slice $es in
            let j0 = (v $i - 1536) / 2 in
            assert (1536 + 2 * j0 == v $i);
            assert (Seq.index s (v $i) == es.[ i ]);
            assert (Seq.index s (v $i + 1) == es.[ i +! mk_usize 1 ]);
            assert (Libcrux_ml_kem.Mlkem768.Incremental.error2_coefficient s $swap j0 == $c)
        "#
        );
        ok = ok && c >= -2 && c <= 2;
        i += 2;
    }
    ok
}

/// Due to https://github.com/cryspen/libcrux/issues/1275, state may
/// contain incorrect endian-ness.  We need to fix this locally before
/// using it.  Luckily, this is doable by checking that the values in
/// error2 are in the range [-2, 2].
#[hax_lib::requires(es.len() == 2080 && encapsulation_state_is_usable(es))]
#[hax_lib::ensures(|result| fstar!(r#"
    let open Libcrux_ml_kem.Mlkem768.Incremental in
    match result with
    | Core_models.Option.Option_Some fixed ->
      Alloc.Vec.impl_1__len fixed = mk_usize 2080 /\
      error2_in_range (Alloc.Vec.impl_1__as_slice fixed) false
    | Core_models.Option.Option_None ->
      error2_in_range (Alloc.Vec.impl_1__as_slice $es) false
    "#))]
#[hax_lib::opaque]
fn potentially_fix_state_incorrectly_encoded_by_libcrux_issue_1275(
    es: &EncapsulationState,
) -> Option<EncapsulationState> {
    assert_eq!(es.len(), 2080);
    // Look at each value within the error2 portion of EncapsState.
    //
    // The last 32 bytes are a raw random vector, thus they don't have endianness
    // and we shouldn't flip them.  All other bytes are encoded i16s.
    // This is the libcrux-specific encoding of the following struct, where all
    // PolynomialRingElements are encoded as described.
    //
    //    pub struct EncapsState<const K: usize, Vector: Operations> {
    //        pub(super) r_as_ntt: [PolynomialRingElement<Vector>; K],
    //        pub(super) error2: PolynomialRingElement<Vector>,
    //        pub(super) randomness: [u8; 32],
    //    }
    //
    // To determine whether it's valid or not, we look at the encoding of `error2`.
    // All error2 values should be in the range [-2, 2].
    // This is 𝜂2 from https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.203.pdf
    // page 39 table 2, generated as 𝑒2 on page 30 algorithm 14 line 17.
    const NEG1_I16: i16 = 0xFFFFu16 as i16;
    const NEG2_I16_GOOD: i16 = 0xFFFEu16 as i16;
    const NEG2_I16_BAD: i16 = 0xFEFFu16 as i16;

    for c in es[1536..2080 - 32].chunks(2) {
        match i16::from_le_bytes(c.try_into().expect("chunk should be size 2")) {
            0x0000i16 | NEG1_I16 => {} // These have the same encoding for i16 in little/big-endian
            0x0001i16 | 0x0002i16 | NEG2_I16_GOOD => {
                return None;
            }
            0x0100i16 | 0x0200i16 | NEG2_I16_BAD => {
                // If they aren't in the expected range, we probably have a state with bad endian-ness.  So flip it.
                #[cfg(not(hax))]
                log::info!("spqr fixing bad encapsulate1 stored state endianness");
                return Some(flip_endianness_of_encapsulation_state(es));
            }
            _ => {
                // We're in a weird state, so just use what we had initially.
                #[cfg(not(hax))]
                log::warn!("spqr unable to fix encapsulate1 stored state endianness");
                return None;
            }
        }
    }
    None
}

#[hax_lib::requires(es.len()%2 == 0 && es.len() == 2080)]
#[hax_lib::ensures(|result| result.len() == es.len())]
fn flip_endianness_of_encapsulation_state(es: &EncapsulationState) -> EncapsulationState {
    #[allow(clippy::manual_is_multiple_of)] // Hax does not support is_multiple_of.
    let es_len_multiple_of_2 = es.len() % 2 == 0;
    assert!(es_len_multiple_of_2);
    assert!(es.len() > 32);
    let mut fixed_es = es.clone();
    for i in (0..fixed_es.len() - 32).step_by(2) {
        hax_lib::loop_invariant!(|_: usize| fixed_es.len() == es.len());
        (fixed_es[i], fixed_es[i + 1]) = (fixed_es[i + 1], fixed_es[i])
    }
    fixed_es
}

/// Decapsulate ciphertext to get shared secret.
#[hax_lib::requires(ct1.len() == 960 && ct2.len() == 128 && dk.len() == 2400)]
#[hax_lib::ensures(|result| result.len() == 32)]
pub fn decaps(dk: &DecapsulationKey, ct1: &Ciphertext1, ct2: &Ciphertext2) -> Secret {
    let ct1 = incremental::Ciphertext1 {
        value: ct1.as_slice().try_into().expect("size should be correct"),
    };
    let ct2 = incremental::Ciphertext2 {
        value: ct2.as_slice().try_into().expect("size should be correct"),
    };
    incremental::decapsulate_compressed_key(
        dk.as_slice().try_into().expect("size should be correct"),
        &ct1,
        &ct2,
    )
    .to_vec()
}

#[cfg(test)]
mod test {
    use super::*;
    use rand::TryRngCore;
    use rand_core::OsRng;

    #[test]
    fn incremental_mlkem768_round_trip() {
        let mut rng = OsRng.unwrap_err();
        let keys = generate(&mut rng);
        let (ct1, es, ss1) = encaps1(&keys.hdr, &mut rng);
        let ct2 = encaps2(&keys.ek, &es);
        let ss2 = decaps(&keys.dk, &ct1, &ct2);
        assert_eq!(ss1, ss2);
    }

    #[test]
    fn encapsulation_state_range_check() {
        let mut rng = OsRng.unwrap_err();
        let keys = generate(&mut rng);
        let (_, es, _) = encaps1(&keys.hdr, &mut rng);
        assert!(encapsulation_state_is_usable(&es));

        // The byte-swapped encoding: in range only once swapped back.
        let mut swapped = es.clone();
        for i in (1536..2048).step_by(2) {
            swapped.swap(i, i + 1);
        }
        assert!(encapsulation_state_is_usable(&swapped));

        // An error2 coefficient outside [-2, 2] overflows encapsulate2's i16
        // arithmetic, in either byte order.
        for at in [1536, 1538, 2046] {
            let mut bad = es.clone();
            bad[at] = 0xFF;
            bad[at + 1] = 0x7F;
            assert!(!encapsulation_state_is_usable(&bad), "at {at}");
        }
    }
}
