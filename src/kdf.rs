// Copyright 2025 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

use crate::Epoch;

/// HKDF-SHA256 expands to at most 255 hash lengths; `expand` fails beyond that.
// Used in hax_lib annotations
#[allow(dead_code)]
const MAX_OKM_LEN: usize = 255 * 32;

#[hax_lib::requires(okm_len <= MAX_OKM_LEN)]
#[hax_lib::ensures(|res| res.len() >= okm_len)]
pub fn hkdf_to_vec(salt: &[u8], ikm: &[u8], info: &[u8], okm_len: usize) -> Vec<u8> {
    let mut out = vec![0u8; okm_len];
    hkdf_to_slice(salt, ikm, info, &mut out);
    out
}

/// Derive the epoch's SCKA secret from a KEM shared secret.
#[cfg_attr(
    hax_backend_proverif,
    hax_lib::proverif::replace_body("derive_scka_secret_f(kem_ss, epoch)")
)]
pub fn derive_scka_secret(kem_ss: &[u8], epoch: Epoch) -> Vec<u8> {
    let info = [
        b"Signal_PQCKA_V1_MLKEM768:SCKA Key".as_slice(),
        epoch.to_be_bytes().as_slice(),
    ]
    .concat();
    hkdf_to_vec(&[0u8; 32], kem_ss, &info, 32)
}

#[hax_lib::opaque]
#[hax_lib::requires(okm.len() <= MAX_OKM_LEN)]
#[hax_lib::ensures(|_| future(okm).len() == okm.len())]
pub fn hkdf_to_slice(salt: &[u8], ikm: &[u8], info: &[u8], okm: &mut [u8]) {
    hkdf::Hkdf::<sha2::Sha256>::new(Some(salt), ikm)
        .expand(info, okm)
        .expect("okm is at most MAX_OKM_LEN bytes");
}
