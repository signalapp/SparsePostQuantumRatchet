// Copyright 2025 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use crate::encoding::polynomial;
use crate::proto::pq_ratchet as pqrpb;
use crate::v1::unchunked;

#[hax_lib::attributes]
impl NoHeaderReceived {
    pub fn into_pb(self) -> pqrpb::v1_state::chunked::NoHeaderReceived {
        pqrpb::v1_state::chunked::NoHeaderReceived {
            uc: Some(self.uc.into_pb()),
            receiving_hdr: Some(self.receiving_hdr.into_pb()),
        }
    }

    #[hax_lib::requires(match pb.receiving_hdr {
        Some(rhdr) => rhdr.pts_needed == ((incremental_mlkem768::HEADER_SIZE + authenticator::Authenticator::MACSIZE) / 2) as u32,
        None => true}
    )]
    pub fn from_pb(pb: pqrpb::v1_state::chunked::NoHeaderReceived) -> Result<Self, Error> {
        Ok(Self {
            uc: unchunked::send_ct::NoHeaderReceived::from_pb(pb.uc.ok_or(Error::StateDecode)?)?,
            receiving_hdr: polynomial::PolyDecoder::from_pb(
                pb.receiving_hdr.ok_or(Error::StateDecode)?,
            )
            .map_err(|_| Error::StateDecode)?,
        })
    }
}

impl HeaderReceived {
    pub fn into_pb(self) -> pqrpb::v1_state::chunked::HeaderReceived {
        pqrpb::v1_state::chunked::HeaderReceived {
            uc: Some(self.uc.into_pb()),
            receiving_ek: Some(self.receiving_ek.into_pb()),
        }
    }

    pub fn from_pb(pb: pqrpb::v1_state::chunked::HeaderReceived) -> Result<Self, Error> {
        Ok(Self {
            uc: unchunked::send_ct::HeaderReceived::from_pb(pb.uc.ok_or(Error::StateDecode)?)?,
            receiving_ek: polynomial::PolyDecoder::from_pb(
                pb.receiving_ek.ok_or(Error::StateDecode)?,
            )
            .map_err(|_| Error::StateDecode)?,
        })
    }
}

impl Ct1Sampled {
    pub fn into_pb(self) -> pqrpb::v1_state::chunked::Ct1Sampled {
        pqrpb::v1_state::chunked::Ct1Sampled {
            uc: Some(self.uc.into_pb()),
            sending_ct1: Some(self.sending_ct1.into_pb()),
            receiving_ek: Some(self.receiving_ek.into_pb()),
        }
    }

    pub fn from_pb(pb: pqrpb::v1_state::chunked::Ct1Sampled) -> Result<Self, Error> {
        Ok(Self {
            uc: unchunked::send_ct::Ct1Sent::from_pb(pb.uc.ok_or(Error::StateDecode)?)?,
            sending_ct1: polynomial::PolyEncoder::from_pb(
                pb.sending_ct1.ok_or(Error::StateDecode)?,
            )
            .map_err(|_| Error::StateDecode)?,
            receiving_ek: polynomial::PolyDecoder::from_pb(
                pb.receiving_ek.ok_or(Error::StateDecode)?,
            )
            .map_err(|_| Error::StateDecode)?,
        })
    }
}

impl EkReceivedCt1Sampled {
    pub fn into_pb(self) -> pqrpb::v1_state::chunked::EkReceivedCt1Sampled {
        pqrpb::v1_state::chunked::EkReceivedCt1Sampled {
            uc: Some(self.uc.into_pb()),
            sending_ct1: Some(self.sending_ct1.into_pb()),
        }
    }

    pub fn from_pb(pb: pqrpb::v1_state::chunked::EkReceivedCt1Sampled) -> Result<Self, Error> {
        Ok(Self {
            uc: unchunked::send_ct::Ct1SentEkReceived::from_pb(pb.uc.ok_or(Error::StateDecode)?)?,
            sending_ct1: polynomial::PolyEncoder::from_pb(
                pb.sending_ct1.ok_or(Error::StateDecode)?,
            )
            .map_err(|_| Error::StateDecode)?,
        })
    }
}

impl Ct1Acknowledged {
    pub fn into_pb(self) -> pqrpb::v1_state::chunked::Ct1Acknowledged {
        pqrpb::v1_state::chunked::Ct1Acknowledged {
            uc: Some(self.uc.into_pb()),
            receiving_ek: Some(self.receiving_ek.into_pb()),
        }
    }

    pub fn from_pb(pb: pqrpb::v1_state::chunked::Ct1Acknowledged) -> Result<Self, Error> {
        Ok(Self {
            uc: unchunked::send_ct::Ct1Sent::from_pb(pb.uc.ok_or(Error::StateDecode)?)?,
            receiving_ek: polynomial::PolyDecoder::from_pb(
                pb.receiving_ek.ok_or(Error::StateDecode)?,
            )
            .map_err(|_| Error::StateDecode)?,
        })
    }
}

impl Ct2Sampled {
    pub fn into_pb(self) -> pqrpb::v1_state::chunked::Ct2Sampled {
        pqrpb::v1_state::chunked::Ct2Sampled {
            uc: Some(self.uc.into_pb()),
            sending_ct2: Some(self.sending_ct2.into_pb()),
        }
    }

    pub fn from_pb(pb: pqrpb::v1_state::chunked::Ct2Sampled) -> Result<Self, Error> {
        Ok(Self {
            uc: unchunked::send_ct::Ct2Sent::from_pb(pb.uc.ok_or(Error::StateDecode)?)?,
            sending_ct2: polynomial::PolyEncoder::from_pb(
                pb.sending_ct2.ok_or(Error::StateDecode)?,
            )
            .map_err(|_| Error::StateDecode)?,
        })
    }
}
