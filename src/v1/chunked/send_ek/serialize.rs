// Copyright 2025 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use crate::encoding::polynomial;
use crate::proto::pq_ratchet as pqrpb;
use crate::v1::unchunked;

impl KeysUnsampled {
    pub fn into_pb(self) -> pqrpb::v1_state::chunked::KeysUnsampled {
        pqrpb::v1_state::chunked::KeysUnsampled {
            uc: Some(self.uc.into_pb()),
        }
    }

    pub fn from_pb(pb: pqrpb::v1_state::chunked::KeysUnsampled) -> Result<Self, Error> {
        Ok(Self {
            uc: unchunked::send_ek::KeysUnsampled::from_pb(pb.uc.ok_or(Error::StateDecode)?)?,
        })
    }
}

impl KeysSampled {
    pub fn into_pb(self) -> pqrpb::v1_state::chunked::KeysSampled {
        pqrpb::v1_state::chunked::KeysSampled {
            uc: Some(self.uc.into_pb()),
            sending_hdr: Some(self.sending_hdr.into_pb()),
        }
    }

    pub fn from_pb(pb: pqrpb::v1_state::chunked::KeysSampled) -> Result<Self, Error> {
        Ok(Self {
            uc: unchunked::send_ek::HeaderSent::from_pb(pb.uc.ok_or(Error::StateDecode)?)?,
            sending_hdr: polynomial::PolyEncoder::from_pb(
                pb.sending_hdr.ok_or(Error::StateDecode)?,
            )
            .map_err(|_| Error::StateDecode)?,
        })
    }
}

#[hax_lib::attributes]
impl HeaderSent {
    pub fn into_pb(self) -> pqrpb::v1_state::chunked::HeaderSent {
        pqrpb::v1_state::chunked::HeaderSent {
            uc: Some(self.uc.into_pb()),
            sending_ek: Some(self.sending_ek.into_pb()),
            receiving_ct1: Some(self.receiving_ct1.into_pb()),
        }
    }

    pub fn from_pb(pb: pqrpb::v1_state::chunked::HeaderSent) -> Result<Self, Error> {
        if let Some(d) = &pb.receiving_ct1 {
            if d.pts_needed as usize != crate::incremental_mlkem768::CIPHERTEXT1_SIZE / 2 {
                return Err(Error::MsgDecode);
            }
        }
        Ok(Self {
            uc: unchunked::send_ek::EkSent::from_pb(pb.uc.ok_or(Error::StateDecode)?)?,
            sending_ek: polynomial::PolyEncoder::from_pb(pb.sending_ek.ok_or(Error::StateDecode)?)
                .map_err(|_| Error::StateDecode)?,
            receiving_ct1: polynomial::PolyDecoder::from_pb(
                pb.receiving_ct1.ok_or(Error::StateDecode)?,
            )
            .map_err(|_| Error::StateDecode)?,
        })
    }
}

impl Ct1Received {
    pub fn into_pb(self) -> pqrpb::v1_state::chunked::Ct1Received {
        pqrpb::v1_state::chunked::Ct1Received {
            uc: Some(self.uc.into_pb()),
            sending_ek: Some(self.sending_ek.into_pb()),
        }
    }

    pub fn from_pb(pb: pqrpb::v1_state::chunked::Ct1Received) -> Result<Self, Error> {
        Ok(Self {
            uc: unchunked::send_ek::EkSentCt1Received::from_pb(pb.uc.ok_or(Error::StateDecode)?)?,
            sending_ek: polynomial::PolyEncoder::from_pb(pb.sending_ek.ok_or(Error::StateDecode)?)
                .map_err(|_| Error::StateDecode)?,
        })
    }
}

impl EkSentCt1Received {
    pub fn into_pb(self) -> pqrpb::v1_state::chunked::EkSentCt1Received {
        pqrpb::v1_state::chunked::EkSentCt1Received {
            uc: Some(self.uc.into_pb()),
            receiving_ct2: Some(self.receiving_ct2.into_pb()),
        }
    }

    pub fn from_pb(pb: pqrpb::v1_state::chunked::EkSentCt1Received) -> Result<Self, Error> {
        if let Some(d) = &pb.receiving_ct2 {
            if d.pts_needed as usize
                != (incremental_mlkem768::CIPHERTEXT2_SIZE + authenticator::Authenticator::MACSIZE)
                    / 2
            {
                return Err(Error::MsgDecode);
            }
        }
        Ok(Self {
            uc: unchunked::send_ek::EkSentCt1Received::from_pb(pb.uc.ok_or(Error::StateDecode)?)?,
            receiving_ct2: polynomial::PolyDecoder::from_pb(
                pb.receiving_ct2.ok_or(Error::StateDecode)?,
            )
            .map_err(|_| Error::StateDecode)?,
        })
    }
}
