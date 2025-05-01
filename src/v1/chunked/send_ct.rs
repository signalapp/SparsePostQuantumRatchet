// Copyright 2025 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

mod serialize;

use super::send_ek;
use crate::encoding::polynomial;
use crate::encoding::{Chunk, Decoder, Encoder};
use crate::v1::unchunked::send_ct as unchunked;
use crate::{authenticator, incremental_mlkem768};
use crate::{Epoch, EpochSecret, Error};
use rand::{CryptoRng, Rng};

#[cfg_attr(test, derive(Clone))]
pub struct NoHeaderReceived {
    pub(super) uc: unchunked::NoHeaderReceived,
    // `receiving_hdr` only decodes messages of length `incremental_mlkem768::HEADER_SIZE + authenticator::Authenticator::MACSIZE`
    pub(super) receiving_hdr: polynomial::PolyDecoder,
}

#[cfg_attr(test, derive(Clone))]
pub struct HeaderReceived {
    uc: unchunked::HeaderReceived,
    // `receiving_ek` only decodes messages of length `incremental_mlkem768::ENCAPSULATION_KEY_SIZE`
    receiving_ek: polynomial::PolyDecoder,
}

#[cfg_attr(test, derive(Clone))]
pub struct Ct1Sampled {
    uc: unchunked::Ct1Sent,
    sending_ct1: polynomial::PolyEncoder,
    // `receiving_ek` only decodes messages of length `incremental_mlkem768::ENCAPSULATION_KEY_SIZE`
    receiving_ek: polynomial::PolyDecoder,
}

#[cfg_attr(test, derive(Clone))]
pub struct EkReceivedCt1Sampled {
    uc: unchunked::Ct1SentEkReceived,
    sending_ct1: polynomial::PolyEncoder,
}

#[cfg_attr(test, derive(Clone))]
pub struct Ct1Acknowledged {
    uc: unchunked::Ct1Sent,
    // `receiving_ek` only decodes messages of length `incremental_mlkem768::ENCAPSULATION_KEY_SIZE`
    receiving_ek: polynomial::PolyDecoder,
}

#[cfg_attr(test, derive(Clone))]
pub struct Ct2Sampled {
    uc: unchunked::Ct2Sent,
    sending_ct2: polynomial::PolyEncoder,
}

#[cfg_attr(test, derive(Clone))]
pub enum NoHeaderReceivedRecvChunk {
    StillReceiving(NoHeaderReceived),
    Done(HeaderReceived),
}

#[hax_lib::attributes]
impl NoHeaderReceived {
    pub fn new(auth_key: &[u8]) -> Self {
        let decoder = polynomial::PolyDecoder::new(
            incremental_mlkem768::HEADER_SIZE + authenticator::Authenticator::MACSIZE,
        );
        hax_lib::assume!(decoder.is_ok());
        NoHeaderReceived {
            uc: unchunked::NoHeaderReceived::new(auth_key),
            receiving_hdr: decoder.expect("should be able to decode header size"),
        }
    }

    #[hax_lib::requires(epoch == self.uc.epoch)]
    pub fn recv_hdr_chunk(
        self,
        epoch: Epoch,
        chunk: &Chunk,
    ) -> Result<NoHeaderReceivedRecvChunk, Error> {
        assert_eq!(epoch, self.uc.epoch);
        let Self {
            uc,
            mut receiving_hdr,
        } = self;
        receiving_hdr.add_chunk(chunk);
        hax_lib::assume!(
            receiving_hdr.get_pts_needed() <= polynomial::MAX_STORED_POLYNOMIAL_DEGREE_V1
        );
        if let Some(mut hdr) = receiving_hdr.decoded_message() {
            let mac: authenticator::Mac = hdr.drain(incremental_mlkem768::HEADER_SIZE..).collect();
            hax_lib::assume!(hdr.len() == 64 && mac.len() == authenticator::Authenticator::MACSIZE);
            let receiving_ek =
                polynomial::PolyDecoder::new(incremental_mlkem768::ENCAPSULATION_KEY_SIZE);
            hax_lib::assume!(receiving_ek.is_ok());
            Ok(NoHeaderReceivedRecvChunk::Done(HeaderReceived {
                uc: uc.recv_header(epoch, hdr, &mac)?,
                receiving_ek: receiving_ek.expect("should be able to decode EncapsulationKey size"),
            }))
        } else {
            Ok(NoHeaderReceivedRecvChunk::StillReceiving(Self {
                uc,
                receiving_hdr,
            }))
        }
    }

    pub fn epoch(&self) -> Epoch {
        self.uc.epoch
    }
}

// Once the header has been received, it seems like we could start receiving
// EK chunks and should handle that possibility.  However, this is not actually
// correct, as the send_ek side won't start sending EK chunks until it receives
// the first CT0 chunk.  Thus, send_ct1_chunk is the only state transition
// we need to implement here.
impl HeaderReceived {
    pub fn send_ct1_chunk<R: Rng + CryptoRng>(
        self,
        rng: &mut R,
    ) -> (Ct1Sampled, Chunk, EpochSecret) {
        let Self { uc, receiving_ek } = self;

        let (uc, ct1, epoch_secret) = uc.send_ct1(rng);
        let encoder = polynomial::PolyEncoder::encode_bytes(&ct1);
        hax_lib::assume!(encoder.is_ok());
        let mut sending_ct1 = encoder.expect("should be able to send CTSIZE");
        let chunk = sending_ct1.next_chunk();
        (
            Ct1Sampled {
                uc,
                sending_ct1,
                receiving_ek,
            },
            chunk,
            epoch_secret,
        )
    }

    pub fn epoch(&self) -> Epoch {
        self.uc.epoch
    }
}

// Consider fixing this, but since this is only used as a return value it doesn't take too much memory.
#[allow(clippy::large_enum_variant)]
pub enum Ct1SampledRecvChunk {
    StillReceivingStillSending(Ct1Sampled),
    StillReceiving(Ct1Acknowledged),
    StillSending(EkReceivedCt1Sampled),
    Done(Ct2Sampled),
}

#[hax_lib::fstar::verification_status(lax)]
fn send_ct2_encoder(ct2: &[u8], mac: &[u8]) -> polynomial::PolyEncoder {
    polynomial::PolyEncoder::encode_bytes(&[ct2, mac].concat()).expect("should be able to send ct2")
}

#[hax_lib::attributes]
impl Ct1Sampled {
    #[hax_lib::requires(epoch == self.uc.epoch)]
    pub fn recv_ek_chunk(
        self,
        epoch: Epoch,
        chunk: &Chunk,
        ct1_ack: bool,
    ) -> Result<Ct1SampledRecvChunk, Error> {
        let Self {
            uc,
            mut receiving_ek,
            sending_ct1,
        } = self;
        receiving_ek.add_chunk(chunk);
        hax_lib::assume!(
            receiving_ek.get_pts_needed() <= polynomial::MAX_STORED_POLYNOMIAL_DEGREE_V1
        );
        Ok(if let Some(decoded) = receiving_ek.decoded_message() {
            hax_lib::assume!(decoded.len() == 1152);
            let uc = uc.recv_ek(epoch, decoded)?;
            if ct1_ack {
                let (uc, ct2, mac) = uc.send_ct2();
                Ct1SampledRecvChunk::Done(Ct2Sampled {
                    uc,
                    sending_ct2: send_ct2_encoder(&ct2, &mac),
                })
            } else {
                Ct1SampledRecvChunk::StillSending(EkReceivedCt1Sampled { uc, sending_ct1 })
            }
        } else if ct1_ack {
            Ct1SampledRecvChunk::StillReceiving(Ct1Acknowledged { uc, receiving_ek })
        } else {
            Ct1SampledRecvChunk::StillReceivingStillSending(Self {
                uc,
                receiving_ek,
                sending_ct1,
            })
        })
    }

    pub fn send_ct1_chunk(self) -> (Ct1Sampled, Chunk) {
        let Self {
            uc,
            mut sending_ct1,
            receiving_ek,
        } = self;
        let chunk = sending_ct1.next_chunk();
        (
            Ct1Sampled {
                uc,
                sending_ct1,
                receiving_ek,
            },
            chunk,
        )
    }

    pub fn epoch(&self) -> Epoch {
        self.uc.epoch
    }
}

#[hax_lib::attributes]
impl EkReceivedCt1Sampled {
    pub fn send_ct1_chunk(self) -> (EkReceivedCt1Sampled, Chunk) {
        let Self {
            uc,
            mut sending_ct1,
        } = self;
        let chunk = sending_ct1.next_chunk();
        (EkReceivedCt1Sampled { uc, sending_ct1 }, chunk)
    }

    #[hax_lib::requires(epoch ==self.uc.epoch)]
    pub fn recv_ct1_ack(self, epoch: Epoch) -> Ct2Sampled {
        assert_eq!(epoch, self.uc.epoch);
        let (uc, ct2, mac) = self.uc.send_ct2();
        Ct2Sampled {
            uc,
            sending_ct2: send_ct2_encoder(&ct2, &mac),
        }
    }

    pub fn epoch(&self) -> Epoch {
        self.uc.epoch
    }
}

#[allow(clippy::large_enum_variant)]
pub enum Ct1AcknowledgedRecvChunk {
    StillReceiving(Ct1Acknowledged),
    Done(Ct2Sampled),
}

#[hax_lib::attributes]
impl Ct1Acknowledged {
    #[hax_lib::requires(epoch ==self.uc.epoch)]
    pub fn recv_ek_chunk(
        self,
        epoch: Epoch,
        chunk: &Chunk,
    ) -> Result<Ct1AcknowledgedRecvChunk, Error> {
        let Self {
            uc,
            mut receiving_ek,
        } = self;
        receiving_ek.add_chunk(chunk);
        hax_lib::assume!(
            receiving_ek.get_pts_needed() <= polynomial::MAX_STORED_POLYNOMIAL_DEGREE_V1
        );
        Ok(if let Some(decoded) = receiving_ek.decoded_message() {
            hax_lib::assume!(decoded.len() == 1152);
            let uc = uc.recv_ek(epoch, decoded)?;
            let (uc, ct2, mac) = uc.send_ct2();
            Ct1AcknowledgedRecvChunk::Done(Ct2Sampled {
                uc,
                sending_ct2: send_ct2_encoder(&ct2, &mac),
            })
        } else {
            Ct1AcknowledgedRecvChunk::StillReceiving(Self { uc, receiving_ek })
        })
    }

    pub fn epoch(&self) -> Epoch {
        self.uc.epoch
    }
}

#[hax_lib::attributes]
impl Ct2Sampled {
    pub fn send_ct2_chunk(self) -> (Ct2Sampled, Chunk) {
        let Self {
            uc,
            mut sending_ct2,
        } = self;
        let chunk = sending_ct2.next_chunk();
        (Self { uc, sending_ct2 }, chunk)
    }

    #[hax_lib::requires(self.uc.epoch < u64::MAX && epoch == self.uc.epoch + 1)]
    pub fn recv_next_epoch(self, epoch: Epoch) -> send_ek::KeysUnsampled {
        let uc = self.uc.recv_next_epoch(epoch);
        send_ek::KeysUnsampled { uc }
    }

    pub fn epoch(&self) -> Epoch {
        self.uc.epoch
    }
}
