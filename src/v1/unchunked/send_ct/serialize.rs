// Copyright 2025 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use crate::authenticator::Authenticator;
use crate::proto::pq_ratchet as pqrpb;
use crate::Error;

impl NoHeaderReceived {
    pub fn into_pb(self) -> pqrpb::v1_state::unchunked::NoHeaderReceived {
        pqrpb::v1_state::unchunked::NoHeaderReceived {
            epoch: self.epoch,
            auth: Some(self.auth.into_pb()),
        }
    }

    pub fn from_pb(pb: pqrpb::v1_state::unchunked::NoHeaderReceived) -> Result<Self, Error> {
        Ok(Self {
            epoch: pb.epoch,
            auth: Authenticator::from_pb(pb.auth.as_ref().ok_or(Error::StateDecode)?),
        })
    }
}

impl HeaderReceived {
    pub fn into_pb(self) -> pqrpb::v1_state::unchunked::HeaderReceived {
        pqrpb::v1_state::unchunked::HeaderReceived {
            epoch: self.epoch,
            auth: Some(self.auth.into_pb()),
            hdr: self.hdr,
        }
    }

    pub fn from_pb(pb: pqrpb::v1_state::unchunked::HeaderReceived) -> Result<Self, Error> {
        if pb.hdr.len() == 64 {
            Ok(Self {
                epoch: pb.epoch,
                auth: Authenticator::from_pb(pb.auth.as_ref().ok_or(Error::StateDecode)?),
                hdr: pb.hdr,
            })
        } else {
            Err(Error::StateDecode)
        }
    }
}

impl Ct1Sent {
    pub fn into_pb(self) -> pqrpb::v1_state::unchunked::Ct1Sent {
        pqrpb::v1_state::unchunked::Ct1Sent {
            epoch: self.epoch,
            auth: Some(self.auth.into_pb()),
            hdr: self.hdr,
            es: self.es,
            ct1: self.ct1.to_vec(),
        }
    }

    pub fn from_pb(pb: pqrpb::v1_state::unchunked::Ct1Sent) -> Result<Self, Error> {
        if pb.hdr.len() == 64 && pb.es.len() == 2080 && pb.ct1.len() == 960 {
            Ok(Self {
                epoch: pb.epoch,
                auth: Authenticator::from_pb(pb.auth.as_ref().ok_or(Error::StateDecode)?),
                hdr: pb.hdr,
                es: pb.es,
                ct1: pb.ct1,
            })
        } else {
            Err(Error::StateDecode)
        }
    }
}

impl Ct1SentEkReceived {
    pub fn into_pb(self) -> pqrpb::v1_state::unchunked::Ct1SentEkReceived {
        pqrpb::v1_state::unchunked::Ct1SentEkReceived {
            epoch: self.epoch,
            auth: Some(self.auth.into_pb()),
            es: self.es,
            ek: self.ek,
            ct1: self.ct1.to_vec(),
        }
    }

    pub fn from_pb(pb: pqrpb::v1_state::unchunked::Ct1SentEkReceived) -> Result<Self, Error> {
        if pb.es.len() == 2080 && pb.ct1.len() == 960 && pb.ek.len() == 1152 {
            Ok(Self {
                epoch: pb.epoch,
                auth: Authenticator::from_pb(pb.auth.as_ref().ok_or(Error::StateDecode)?),
                es: pb.es,
                ek: pb.ek,
                ct1: pb.ct1,
            })
        } else {
            Err(Error::StateDecode)
        }
    }
}

impl Ct2Sent {
    pub fn into_pb(self) -> pqrpb::v1_state::unchunked::Ct2Sent {
        pqrpb::v1_state::unchunked::Ct2Sent {
            epoch: self.epoch,
            auth: Some(self.auth.into_pb()),
        }
    }

    pub fn from_pb(pb: pqrpb::v1_state::unchunked::Ct2Sent) -> Result<Self, Error> {
        Ok(Self {
            epoch: pb.epoch,
            auth: Authenticator::from_pb(pb.auth.as_ref().ok_or(Error::StateDecode)?),
        })
    }
}
