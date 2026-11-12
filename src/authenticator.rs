// Copyright 2025 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

use libcrux_hmac::hmac;

use crate::{kdf, util::compare, Epoch};
pub mod serialize;
pub type Mac = Vec<u8>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Ciphertext MAC is invalid")]
    InvalidCtMac,
    #[error("Encapsulation key MAC is invalid")]
    InvalidHdrMac,
    #[error("Authenticator previous root key present when should be erased")]
    AuthenticatorRootKeyPresent,
    #[error("Authenticator previous root key missing")]
    AuthenticatorRootKeyMissing,
    #[error("Authenticator previous MAC key present when should be erased")]
    AuthenticatorMacKeyPresent,
    #[error("Authenticator previous MAC key missing")]
    AuthenticatorMacKeyMissing,
}

#[cfg_attr(test, derive(Clone))]
pub struct Authenticator {
    root_key: Mac,
    mac_key: Mac,
}

#[hax_lib::attributes]
impl Authenticator {
    pub const MACSIZE: usize = 32usize;
    #[cfg_attr(
        hax_backend_proverif,
        hax_lib::proverif::replace_body("auth_new(root_key, ep)")
    )]
    pub fn new(root_key: Vec<u8>, ep: Epoch) -> Self {
        let result = Self {
            root_key: vec![0u8; 32],
            mac_key: vec![0u8; 32],
        };
        result.update(ep, &root_key)
    }

    // Takes and returns `self`: in ProVerif, `replace_body` gives the result
    // and leaves `&mut` arguments unchanged.
    #[cfg_attr(
        hax_backend_proverif,
        hax_lib::proverif::replace_body("auth_update(self, ep, k)")
    )]
    pub fn update(mut self, ep: Epoch, k: &[u8]) -> Self {
        let ikm = [self.root_key.as_slice(), k].concat();
        let info = [
            b"Signal_PQCKA_V1_MLKEM768:Authenticator Update".as_slice(),
            &ep.to_be_bytes(),
        ]
        .concat();
        let kdf_out = kdf::hkdf_to_vec(&[0u8; 32], &ikm, &info, 64);
        self.root_key = kdf_out.as_slice()[..32].to_vec();
        self.mac_key = kdf_out.as_slice()[32..].to_vec();
        self
    }

    #[cfg_attr(
        hax_backend_proverif,
        hax_lib::proverif::replace_body(
            "let (=expected_mac) = mac_ct_f(self, ep, ct) in hax_result_ok(rust_primitives__hax__Tuple0__Tuple0) else hax_result_err(spqr__authenticator__Error__InvalidCtMac())"
        )
    )]
    #[hax_lib::requires(expected_mac.len() == Authenticator::MACSIZE)]
    pub fn verify_ct(&self, ep: Epoch, ct: &[u8], expected_mac: &[u8]) -> Result<(), Error> {
        if compare(expected_mac, &self.mac_ct(ep, ct)) != 0 {
            Err(Error::InvalidCtMac)
        } else {
            Ok(())
        }
    }

    #[cfg_attr(
        hax_backend_proverif,
        hax_lib::proverif::replace_body("mac_ct_f(self, ep, ct)")
    )]
    #[hax_lib::ensures(|res| res.len() == Authenticator::MACSIZE)]
    pub fn mac_ct(&self, ep: Epoch, ct: &[u8]) -> Mac {
        let ct_mac_data = [
            b"Signal_PQCKA_V1_MLKEM768:ciphertext".as_slice(),
            &ep.to_be_bytes(),
            ct,
        ]
        .concat();
        hmac(
            libcrux_hmac::Algorithm::Sha256,
            &self.mac_key,
            &ct_mac_data,
            Some(Self::MACSIZE),
        )
    }

    #[cfg_attr(
        hax_backend_proverif,
        hax_lib::proverif::replace_body(
            "let (=expected_mac) = mac_hdr_f(self, ep, hdr) in hax_result_ok(rust_primitives__hax__Tuple0__Tuple0) else hax_result_err(spqr__authenticator__Error__InvalidHdrMac())"
        )
    )]
    #[hax_lib::requires(expected_mac.len() == Authenticator::MACSIZE)]
    pub fn verify_hdr(&self, ep: Epoch, hdr: &[u8], expected_mac: &[u8]) -> Result<(), Error> {
        if compare(expected_mac, &self.mac_hdr(ep, hdr)) != 0 {
            Err(Error::InvalidHdrMac)
        } else {
            Ok(())
        }
    }

    #[cfg_attr(
        hax_backend_proverif,
        hax_lib::proverif::replace_body("mac_hdr_f(self, ep, hdr)")
    )]
    #[hax_lib::ensures(|res| res.len() == Authenticator::MACSIZE)]
    pub fn mac_hdr(&self, ep: Epoch, hdr: &[u8]) -> Mac {
        let ct_mac_data = [
            b"Signal_PQCKA_V1_MLKEM768:ekheader".as_slice(),
            &ep.to_be_bytes(),
            hdr,
        ]
        .concat();
        hmac(
            libcrux_hmac::Algorithm::Sha256,
            &self.mac_key,
            &ct_mac_data,
            Some(Self::MACSIZE),
        )
    }
}
