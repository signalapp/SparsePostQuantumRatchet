// Copyright 2025 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

mod serialize;

use super::send_ek;
use crate::authenticator;
use crate::incremental_mlkem768;
use crate::kdf;
use crate::{Epoch, EpochSecret, Error};
use rand::{CryptoRng, Rng};

//                            START (epoch = 1)
//                              │
//                      ┌───────▼───────────┐
//                ┌─────► NoHeaderReceived  │
//                │     └───────┬───────────┘
//                │             │
//                │             │recv_header
//                │             │
//                │     ┌───────▼───────────┐
//                │     │ HeaderReceived    │
//                │     └───────┬───────────┘
//                │             │
//                │             │send_ct1
//                │             │
//                │     ┌───────▼───────────┐
// recv_next_epoch│     │ Ct1Sent           │
//   (epoch += 1) │     └───────┬───────────┘
//                │             │
//                │             │recv_ek
//                │             │
//                │     ┌───────▼───────────┐
//                │     │ Ct1SentEkReceived │
//                │     └───────┬───────────┘
//                │             │
//                │             │send_ct2
//                │             │
//                │     ┌───────▼───────────┐
//                └─────┤ Ct2Sent           │
//                      └───────────────────┘

#[cfg_attr(test, derive(Clone))]
pub struct NoHeaderReceived {
    pub epoch: Epoch,
    pub(super) auth: authenticator::Authenticator,
}

#[cfg_attr(test, derive(Clone))]
#[hax_lib::attributes]
pub struct HeaderReceived {
    pub epoch: Epoch,
    auth: authenticator::Authenticator,
    #[hax_lib::refine(hdr.len() == 64)]
    hdr: incremental_mlkem768::Header,
}

#[cfg_attr(test, derive(Clone))]
#[hax_lib::attributes]
pub struct Ct1Sent {
    pub epoch: Epoch,
    auth: authenticator::Authenticator,
    #[hax_lib::refine(hdr.len() == 64)]
    hdr: incremental_mlkem768::Header,
    #[hax_lib::refine(es.len() == 2080)]
    es: incremental_mlkem768::EncapsulationState,
    #[hax_lib::refine(ct1.len() == 960)]
    ct1: incremental_mlkem768::Ciphertext1,
}

#[cfg_attr(test, derive(Clone))]
#[hax_lib::attributes]
pub struct Ct1SentEkReceived {
    pub epoch: Epoch,
    auth: authenticator::Authenticator,
    #[hax_lib::refine(es.len() == 2080)]
    es: incremental_mlkem768::EncapsulationState,
    #[hax_lib::refine(ek.len() == 1152)]
    ek: incremental_mlkem768::EncapsulationKey,
    #[hax_lib::refine(ct1.len() == 960)]
    ct1: incremental_mlkem768::Ciphertext1,
}

#[cfg_attr(test, derive(Clone))]
pub struct Ct2Sent {
    pub epoch: Epoch,
    auth: authenticator::Authenticator,
}

#[hax_lib::attributes]
impl NoHeaderReceived {
    pub fn new(auth_key: &[u8]) -> Self {
        Self {
            epoch: 1,
            auth: authenticator::Authenticator::new(auth_key.to_vec(), 1),
        }
    }

    #[hax_lib::requires(epoch == self.epoch && hdr.len() == 64 && mac.len() == authenticator::Authenticator::MACSIZE)]
    pub fn recv_header(
        self,
        epoch: Epoch,
        hdr: incremental_mlkem768::Header,
        mac: &authenticator::Mac,
    ) -> Result<HeaderReceived, Error> {
        assert_eq!(epoch, self.epoch);
        self.auth.verify_hdr(self.epoch, &hdr, mac)?;
        Ok(HeaderReceived {
            epoch: self.epoch,
            auth: self.auth,
            hdr,
        })
    }
}

#[hax_lib::attributes]
impl HeaderReceived {
    #[hax_lib::requires(self.hdr.len() == 64)]
    pub fn send_ct1<R: Rng + CryptoRng>(
        self,
        rng: &mut R,
    ) -> (Ct1Sent, incremental_mlkem768::Ciphertext1, EpochSecret) {
        let Self {
            epoch,
            mut auth,
            hdr,
        } = self;
        let (ct1, es, secret) = incremental_mlkem768::encaps1(&hdr, rng);
        let info = [
            b"Signal_PQCKA_V1_MLKEM768:SCKA Key",
            epoch.to_be_bytes().as_slice(),
        ]
        .concat();
        let secret = kdf::hkdf_to_vec(&[0u8; 32], &secret, &info, 32);
        auth.update(epoch, &secret);
        (
            Ct1Sent {
                epoch,
                auth,
                hdr,
                es,
                ct1: ct1.clone(),
            },
            ct1,
            EpochSecret { secret, epoch },
        )
    }
}

#[hax_lib::attributes]
impl Ct1Sent {
    #[hax_lib::requires(epoch == self.epoch && ek.len() == 1152)]
    pub fn recv_ek(
        self,
        epoch: Epoch,
        ek: incremental_mlkem768::EncapsulationKey,
    ) -> Result<Ct1SentEkReceived, Error> {
        assert_eq!(epoch, self.epoch);
        if incremental_mlkem768::ek_matches_header(&ek, &self.hdr) {
            Ok(Ct1SentEkReceived {
                epoch: self.epoch,
                auth: self.auth,
                ek,
                es: self.es,
                ct1: self.ct1,
            })
        } else {
            Err(Error::ErroneousDataReceived)
        }
    }
}

#[hax_lib::attributes]
impl Ct1SentEkReceived {
    #[hax_lib::ensures(|(_, ct2, mac)| ct2.len() == 128 && mac.len() == authenticator::Authenticator::MACSIZE)]
    pub fn send_ct2(
        self,
    ) -> (
        Ct2Sent,
        incremental_mlkem768::Ciphertext2,
        authenticator::Mac,
    ) {
        let Self {
            epoch,
            ek,
            es,
            auth,
            mut ct1,
        } = self;
        let ct2 = incremental_mlkem768::encaps2(&ek, &es);
        ct1.extend_from_slice(&ct2);
        let mac = auth.mac_ct(epoch, &ct1);
        (Ct2Sent { epoch, auth }, ct2, mac)
    }
}

#[hax_lib::attributes]
impl Ct2Sent {
    #[hax_lib::requires(self.epoch < u64::MAX && next_epoch == self.epoch + 1)]
    pub fn recv_next_epoch(self, next_epoch: Epoch) -> send_ek::KeysUnsampled {
        let Self { epoch, auth } = self;
        assert_eq!(epoch + 1, next_epoch);
        send_ek::KeysUnsampled {
            epoch: epoch + 1,
            auth,
        }
    }
}
