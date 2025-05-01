// Copyright 2025 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

mod serialize;

use super::send_ct;
use crate::authenticator;
use crate::incremental_mlkem768;
use crate::kdf;
use crate::{Epoch, EpochSecret, Error};
use rand::{CryptoRng, Rng};

//                       START (epoch = 1)
//                         │
//                   ┌─────▼─────────────┐
//             ┌─────► KeysUnsampled     │
//             │     └─────┬─────────────┘
//             │           │
//             │           │send_header
//             │           │
//             │     ┌─────▼─────────────┐
//             │     │ HeaderSent        │
//             │     └─────┬─────────────┘
//             │           │
//     recv_ct2│           │send_ek
// (epoch += 1)│           │
//             │     ┌─────▼─────────────┐
//             │     │ EkSent            │
//             │     └─────┬─────────────┘
//             │           │
//             │           │recv_ct1
//             │           │
//             │     ┌─────▼─────────────┐
//             └─────┤ EkSentCt1Received │
//                   └───────────────────┘

#[cfg_attr(test, derive(Clone))]
pub struct KeysUnsampled {
    pub epoch: Epoch,
    pub(super) auth: authenticator::Authenticator,
}

#[cfg_attr(test, derive(Clone))]
#[hax_lib::attributes]
pub struct HeaderSent {
    pub epoch: Epoch,
    auth: authenticator::Authenticator,
    #[hax_lib::refine(ek.len() == 1152)]
    ek: incremental_mlkem768::EncapsulationKey,
    #[hax_lib::refine(dk.len() == 2400)]
    dk: incremental_mlkem768::DecapsulationKey,
}

#[cfg_attr(test, derive(Clone))]
#[hax_lib::attributes]
pub struct EkSent {
    pub epoch: Epoch,
    auth: authenticator::Authenticator,
    #[hax_lib::refine(dk.len() == 2400)]
    dk: incremental_mlkem768::DecapsulationKey,
}

#[cfg_attr(test, derive(Clone))]
#[hax_lib::attributes]
pub struct EkSentCt1Received {
    pub epoch: Epoch,
    auth: authenticator::Authenticator,
    #[hax_lib::refine(dk.len() == 2400)]
    dk: incremental_mlkem768::DecapsulationKey,
    #[hax_lib::refine(ct1.len() == 960)]
    ct1: incremental_mlkem768::Ciphertext1,
}

impl KeysUnsampled {
    pub fn new(auth_key: &[u8]) -> Self {
        Self {
            epoch: 1,
            auth: authenticator::Authenticator::new(auth_key.to_vec(), 1),
        }
    }

    pub fn send_header<R: Rng + CryptoRng>(
        self,
        rng: &mut R,
    ) -> (HeaderSent, incremental_mlkem768::Header, authenticator::Mac) {
        let keys = incremental_mlkem768::generate(rng);
        let mac = self.auth.mac_hdr(self.epoch, &keys.hdr);
        (
            HeaderSent {
                epoch: self.epoch,
                auth: self.auth,
                ek: keys.ek,
                dk: keys.dk,
            },
            keys.hdr,
            mac,
        )
    }
}

impl HeaderSent {
    pub fn send_ek(self) -> (EkSent, incremental_mlkem768::EncapsulationKey) {
        (
            EkSent {
                epoch: self.epoch,
                auth: self.auth,
                dk: self.dk,
            },
            self.ek,
        )
    }
}

#[hax_lib::attributes]
impl EkSent {
    #[hax_lib::requires(epoch == self.epoch && ct1.len() == 960)]
    pub fn recv_ct1(
        self,
        epoch: Epoch,
        ct1: incremental_mlkem768::Ciphertext1,
    ) -> EkSentCt1Received {
        assert_eq!(epoch, self.epoch);
        EkSentCt1Received {
            epoch: self.epoch,
            auth: self.auth,
            dk: self.dk,
            ct1,
        }
    }
}

#[hax_lib::attributes]
impl EkSentCt1Received {
    #[hax_lib::requires(ct2.len() == 128 && mac.len() == authenticator::Authenticator::MACSIZE)]
    pub fn recv_ct2(
        self,
        ct2: incremental_mlkem768::Ciphertext2,
        mac: authenticator::Mac,
    ) -> Result<(send_ct::NoHeaderReceived, EpochSecret), Error> {
        let Self {
            epoch,
            mut auth,
            dk,
            mut ct1,
        } = self;
        let ss = incremental_mlkem768::decaps(&dk, &ct1, &ct2);
        let info = [
            b"Signal_PQCKA_V1_MLKEM768:SCKA Key",
            epoch.to_be_bytes().as_slice(),
        ]
        .concat();
        let ss = kdf::hkdf_to_vec(&[0u8; 32], &ss, &info, 32);

        auth.update(epoch, &ss);
        ct1.extend_from_slice(&ct2);
        auth.verify_ct(epoch, &ct1, &mac)?;
        hax_lib::assume!(epoch < u64::MAX);
        Ok((
            send_ct::NoHeaderReceived {
                epoch: epoch + 1,
                auth,
            },
            EpochSecret {
                secret: ss.to_vec(),
                epoch,
            },
        ))
    }
}
