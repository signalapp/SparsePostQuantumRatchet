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
#[hax_lib::ensures(|(ct1,es,ss)| ct1.len() == 960 && es.len() == 2080 && ss.len() == 32)]
pub fn encaps1<R: Rng + CryptoRng>(
    hdr: &Header,
    rng: &mut R,
) -> (Ciphertext1, EncapsulationState, Secret) {
    let mut randomness = [0u8; libcrux_ml_kem::SHARED_SECRET_SIZE];
    rng.fill_bytes(&mut randomness);
    let mut state = vec![0u8; incremental::encaps_state_len()];
    let mut ss = vec![0u8; libcrux_ml_kem::SHARED_SECRET_SIZE];
    let ct1 = incremental::encapsulate1(hdr.as_slice(), randomness, &mut state, &mut ss);
    hax_lib::assume!(ct1.is_ok());
    hax_lib::assume!(state.len() == 2080 && ss.len() == 32);
    (
        ct1.expect("should only fail based on sizes, all sizes should be correct")
            .value
            .to_vec(),
        state,
        ss,
    )
}

/// Encapsulate with header and EK.
#[hax_lib::requires(es.len() == 2080 && ek.len() == 1152)]
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

/// Due to https://github.com/cryspen/libcrux/issues/1275, state may
/// contain incorrect endian-ness.  We need to fix this locally before
/// using it.  Luckily, this is doable by checking that the values in
/// error2 are in the range [-2, 2].
#[hax_lib::requires(es.len() == 2080)]
#[hax_lib::ensures(|result| if let Some(es) = result {
    es.len() == 2080
} else {
    true
})]
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
#[hax_lib::opaque]
fn flip_endianness_of_encapsulation_state(es: &EncapsulationState) -> EncapsulationState {
    assert!(es.len() % 2 == 0);
    assert!(es.len() > 32);
    let mut fixed_es = es.clone();
    for i in (0..fixed_es.len() - 32).step_by(2) {
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
}
