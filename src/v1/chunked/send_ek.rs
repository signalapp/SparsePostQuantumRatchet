// Copyright 2025 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

mod serialize;

use super::send_ct;
use crate::authenticator;
use crate::encoding::polynomial;
use crate::encoding::{Chunk, Decoder, Encoder};
use crate::incremental_mlkem768;
use crate::v1::unchunked::send_ek as unchunked;
use crate::{Epoch, EpochSecret, Error};
use rand::{CryptoRng, Rng};

#[cfg_attr(test, derive(Clone))]
pub struct KeysUnsampled {
    pub(super) uc: unchunked::KeysUnsampled,
}

#[cfg_attr(test, derive(Clone))]
pub struct KeysSampled {
    uc: unchunked::HeaderSent,
    sending_hdr: polynomial::PolyEncoder,
}

#[cfg_attr(test, derive(Clone))]
pub struct HeaderSent {
    uc: unchunked::EkSent,
    sending_ek: polynomial::PolyEncoder,
    // `receiving_ct1` only decodes messages of length `incremental_mlkem768::CIPHERTEXT1_SIZE`
    receiving_ct1: polynomial::PolyDecoder,
}

#[cfg_attr(test, derive(Clone))]
pub struct Ct1Received {
    uc: unchunked::EkSentCt1Received,
    sending_ek: polynomial::PolyEncoder,
}

#[cfg_attr(test, derive(Clone))]
pub struct EkSentCt1Received {
    uc: unchunked::EkSentCt1Received,
    // `receiving_ct2` only decodes messages of length `incremental_mlkem768::CIPHERTEXT2_SIZE + authenticator::Authenticator::MACSIZE`
    receiving_ct2: polynomial::PolyDecoder,
}

impl KeysUnsampled {
    pub fn new(auth_key: &[u8]) -> Self {
        Self {
            uc: unchunked::KeysUnsampled::new(auth_key),
        }
    }

    pub fn send_hdr_chunk<R: Rng + CryptoRng>(self, rng: &mut R) -> (KeysSampled, Chunk) {
        let (uc, hdr, mac) = self.uc.send_header(rng);
        let to_send = [hdr, mac].concat();
        let encoder = polynomial::PolyEncoder::encode_bytes(&to_send);
        hax_lib::assume!(encoder.is_ok());
        let mut sending_hdr = encoder.expect("should be able to encode header size");
        let chunk = sending_hdr.next_chunk();
        (KeysSampled { uc, sending_hdr }, chunk)
    }

    pub fn epoch(&self) -> Epoch {
        self.uc.epoch
    }
}

#[hax_lib::attributes]
impl KeysSampled {
    pub fn send_hdr_chunk(self) -> (KeysSampled, Chunk) {
        let Self {
            uc,
            mut sending_hdr,
        } = self;
        let chunk = sending_hdr.next_chunk();
        (KeysSampled { uc, sending_hdr }, chunk)
    }

    #[hax_lib::requires(epoch == self.uc.epoch)]
    pub fn recv_ct1_chunk(self, epoch: Epoch, chunk: &Chunk) -> HeaderSent {
        assert_eq!(epoch, self.uc.epoch);
        let decoder = polynomial::PolyDecoder::new(incremental_mlkem768::CIPHERTEXT1_SIZE);
        hax_lib::assume!(decoder.is_ok());
        let mut receiving_ct1 = decoder.expect("should be able to decode header size");
        receiving_ct1.add_chunk(chunk);
        let (uc, ek) = self.uc.send_ek();

        let encoder = polynomial::PolyEncoder::encode_bytes(&ek);
        hax_lib::assume!(encoder.is_ok());
        let sending_ek = encoder.expect("should be able to send ek");
        HeaderSent {
            uc,
            receiving_ct1,
            sending_ek,
        }
    }

    pub fn epoch(&self) -> Epoch {
        self.uc.epoch
    }
}

#[allow(clippy::large_enum_variant)]
pub enum HeaderSentRecvChunk {
    StillReceiving(HeaderSent),
    Done(Ct1Received),
}

#[hax_lib::attributes]
impl HeaderSent {
    pub fn send_ek_chunk(self) -> (HeaderSent, Chunk) {
        let Self {
            uc,
            mut sending_ek,
            receiving_ct1,
        } = self;
        let chunk = sending_ek.next_chunk();
        (
            HeaderSent {
                uc,
                sending_ek,
                receiving_ct1,
            },
            chunk,
        )
    }

    #[hax_lib::requires(epoch == self.uc.epoch)]
    pub fn recv_ct1_chunk(self, epoch: Epoch, chunk: &Chunk) -> HeaderSentRecvChunk {
        assert_eq!(epoch, self.uc.epoch);
        let Self {
            uc,
            sending_ek,
            mut receiving_ct1,
        } = self;
        receiving_ct1.add_chunk(chunk);
        hax_lib::assume!(
            receiving_ct1.get_pts_needed() <= polynomial::MAX_STORED_POLYNOMIAL_DEGREE_V1
        );
        if let Some(decoded) = receiving_ct1.decoded_message() {
            hax_lib::assume!(decoded.len() == 960);
            let uc = uc.recv_ct1(epoch, decoded);
            HeaderSentRecvChunk::Done(Ct1Received { uc, sending_ek })
        } else {
            HeaderSentRecvChunk::StillReceiving(HeaderSent {
                uc,
                sending_ek,
                receiving_ct1,
            })
        }
    }

    pub fn epoch(&self) -> Epoch {
        self.uc.epoch
    }
}

#[hax_lib::attributes]
impl Ct1Received {
    pub fn send_ek_chunk(self) -> (Ct1Received, Chunk) {
        let Self { uc, mut sending_ek } = self;
        let chunk = sending_ek.next_chunk();
        (Ct1Received { uc, sending_ek }, chunk)
    }

    #[hax_lib::requires(epoch == self.uc.epoch)]
    pub fn recv_ct2_chunk(self, epoch: Epoch, chunk: &Chunk) -> EkSentCt1Received {
        assert_eq!(epoch, self.uc.epoch);
        let decoder = polynomial::PolyDecoder::new(
            incremental_mlkem768::CIPHERTEXT2_SIZE + authenticator::Authenticator::MACSIZE,
        );
        hax_lib::assume!(decoder.is_ok());
        let mut receiving_ct2 = decoder.expect("should be able to decode ct2+mac size");
        receiving_ct2.add_chunk(chunk);
        EkSentCt1Received {
            uc: self.uc,
            receiving_ct2,
        }
    }

    pub fn epoch(&self) -> Epoch {
        self.uc.epoch
    }
}

pub enum EkSentCt1ReceivedRecvChunk {
    StillReceiving(EkSentCt1Received),
    Done((send_ct::NoHeaderReceived, EpochSecret)),
}

#[hax_lib::attributes]
impl EkSentCt1Received {
    #[hax_lib::requires(epoch == self.uc.epoch)]
    pub fn recv_ct2_chunk(
        self,
        epoch: Epoch,
        chunk: &Chunk,
    ) -> Result<EkSentCt1ReceivedRecvChunk, Error> {
        assert_eq!(epoch, self.uc.epoch);
        let Self {
            uc,
            mut receiving_ct2,
        } = self;
        receiving_ct2.add_chunk(chunk);
        hax_lib::assume!(
            receiving_ct2.get_pts_needed() <= polynomial::MAX_STORED_POLYNOMIAL_DEGREE_V1
        );
        if let Some(mut ct2) = receiving_ct2.decoded_message() {
            let mac: authenticator::Mac = ct2
                .drain(incremental_mlkem768::CIPHERTEXT2_SIZE..)
                .collect();
            hax_lib::assume!(
                ct2.len() == incremental_mlkem768::CIPHERTEXT2_SIZE
                    && mac.len() == authenticator::Authenticator::MACSIZE
            );
            let (uc, sec) = uc.recv_ct2(ct2, mac)?;
            let decoder = polynomial::PolyDecoder::new(
                incremental_mlkem768::HEADER_SIZE + authenticator::Authenticator::MACSIZE,
            );
            hax_lib::assume!(decoder.is_ok());
            Ok(EkSentCt1ReceivedRecvChunk::Done((
                send_ct::NoHeaderReceived {
                    uc,
                    receiving_hdr: decoder.expect("should be able to decode header size"),
                },
                sec,
            )))
        } else {
            Ok(EkSentCt1ReceivedRecvChunk::StillReceiving(
                EkSentCt1Received { uc, receiving_ct2 },
            ))
        }
    }

    pub fn epoch(&self) -> Epoch {
        self.uc.epoch
    }
}
