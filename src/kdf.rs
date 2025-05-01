// Copyright 2025 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#[hax_lib::opaque]
#[hax_lib::ensures(|res| res.len() >= okm_len)]
pub fn hkdf_to_vec(salt: &[u8], ikm: &[u8], info: &[u8], okm_len: usize) -> Vec<u8> {
    if cfg!(feature = "proof") {
        libcrux_hkdf::hkdf(libcrux_hkdf::Algorithm::Sha256, salt, ikm, info, okm_len)
            .expect("all lengths should work for SHA256")
    } else {
        let mut out = vec![0u8; okm_len];
        hkdf_to_slice(salt, ikm, info, &mut out);
        out
    }
}

#[hax_lib::opaque]
pub fn hkdf_to_slice(salt: &[u8], ikm: &[u8], info: &[u8], okm: &mut [u8]) {
    if cfg!(feature = "proof") {
        okm.copy_from_slice(&hkdf_to_vec(salt, ikm, info, okm.len()));
    } else {
        hkdf::Hkdf::<sha2::Sha256>::new(Some(salt), ikm)
            .expand(info, okm)
            .expect("all lengths should work for SHA256");
    }
}
