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
        hax_lib::assume!(match self.sending_hdr.get_encoder_state() {
            polynomial::EncoderState::Points(points) => hax_lib::prop::forall(
                |pts: &Vec<crate::encoding::gf::GF16>| hax_lib::prop::implies(
                    points.contains(pts),
                    pts.len() <= polynomial::MAX_INTERMEDIATE_POLYNOMIAL_DEGREE_V1
                )
            ),
            polynomial::EncoderState::Polys(polys) =>
                hax_lib::prop::forall(|poly: &polynomial::Poly| hax_lib::prop::implies(
                    polys.contains(poly),
                    poly.coefficients.len() <= polynomial::MAX_INTERMEDIATE_POLYNOMIAL_DEGREE_V1
                )),
        });
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

impl HeaderSent {
    pub fn into_pb(self) -> pqrpb::v1_state::chunked::HeaderSent {
        hax_lib::assume!(match self.sending_ek.get_encoder_state() {
            polynomial::EncoderState::Points(points) => hax_lib::prop::forall(
                |pts: &Vec<crate::encoding::gf::GF16>| hax_lib::prop::implies(
                    points.contains(pts),
                    pts.len() <= polynomial::MAX_INTERMEDIATE_POLYNOMIAL_DEGREE_V1
                )
            ),
            polynomial::EncoderState::Polys(polys) =>
                hax_lib::prop::forall(|poly: &polynomial::Poly| hax_lib::prop::implies(
                    polys.contains(poly),
                    poly.coefficients.len() <= polynomial::MAX_INTERMEDIATE_POLYNOMIAL_DEGREE_V1
                )),
        });
        pqrpb::v1_state::chunked::HeaderSent {
            uc: Some(self.uc.into_pb()),
            sending_ek: Some(self.sending_ek.into_pb()),
            receiving_ct1: Some(self.receiving_ct1.into_pb()),
        }
    }

    pub fn from_pb(pb: pqrpb::v1_state::chunked::HeaderSent) -> Result<Self, Error> {
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
        hax_lib::assume!(match self.sending_ek.get_encoder_state() {
            polynomial::EncoderState::Points(points) => hax_lib::prop::forall(
                |pts: &Vec<crate::encoding::gf::GF16>| hax_lib::prop::implies(
                    points.contains(pts),
                    pts.len() <= polynomial::MAX_INTERMEDIATE_POLYNOMIAL_DEGREE_V1
                )
            ),
            polynomial::EncoderState::Polys(polys) =>
                hax_lib::prop::forall(|poly: &polynomial::Poly| hax_lib::prop::implies(
                    polys.contains(poly),
                    poly.coefficients.len() <= polynomial::MAX_INTERMEDIATE_POLYNOMIAL_DEGREE_V1
                )),
        });
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
        Ok(Self {
            uc: unchunked::send_ek::EkSentCt1Received::from_pb(pb.uc.ok_or(Error::StateDecode)?)?,
            receiving_ct2: polynomial::PolyDecoder::from_pb(
                pb.receiving_ct2.ok_or(Error::StateDecode)?,
            )
            .map_err(|_| Error::StateDecode)?,
        })
    }
}
