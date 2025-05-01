// Copyright 2025 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use crate::authenticator::Authenticator;
use crate::proto::pq_ratchet as pqrpb;
use crate::Error;

impl KeysUnsampled {
    pub fn into_pb(self) -> pqrpb::v1_state::unchunked::KeysUnsampled {
        pqrpb::v1_state::unchunked::KeysUnsampled {
            epoch: self.epoch,
            auth: Some(self.auth.into_pb()),
        }
    }

    pub fn from_pb(pb: pqrpb::v1_state::unchunked::KeysUnsampled) -> Result<Self, Error> {
        Ok(Self {
            epoch: pb.epoch,
            auth: Authenticator::from_pb(pb.auth.as_ref().ok_or(Error::StateDecode)?),
        })
    }
}

impl HeaderSent {
    pub fn into_pb(self) -> pqrpb::v1_state::unchunked::HeaderSent {
        pqrpb::v1_state::unchunked::HeaderSent {
            epoch: self.epoch,
            auth: Some(self.auth.into_pb()),
            ek: self.ek,
            dk: self.dk,
        }
    }

    pub fn from_pb(pb: pqrpb::v1_state::unchunked::HeaderSent) -> Result<Self, Error> {
        if pb.dk.len() == 2400 && pb.ek.len() == 1152 {
            Ok(Self {
                epoch: pb.epoch,
                auth: Authenticator::from_pb(pb.auth.as_ref().ok_or(Error::StateDecode)?),
                ek: pb.ek,
                dk: pb.dk,
            })
        } else {
            Err(Error::StateDecode)
        }
    }
}

impl EkSent {
    pub fn into_pb(self) -> pqrpb::v1_state::unchunked::EkSent {
        pqrpb::v1_state::unchunked::EkSent {
            epoch: self.epoch,
            auth: Some(self.auth.into_pb()),
            dk: self.dk,
        }
    }

    pub fn from_pb(pb: pqrpb::v1_state::unchunked::EkSent) -> Result<Self, Error> {
        if pb.dk.len() == 2400 {
            Ok(Self {
                epoch: pb.epoch,
                auth: Authenticator::from_pb(pb.auth.as_ref().ok_or(Error::StateDecode)?),
                dk: pb.dk,
            })
        } else {
            Err(Error::StateDecode)
        }
    }
}

impl EkSentCt1Received {
    pub fn into_pb(self) -> pqrpb::v1_state::unchunked::EkSentCt1Received {
        pqrpb::v1_state::unchunked::EkSentCt1Received {
            epoch: self.epoch,
            auth: Some(self.auth.into_pb()),
            dk: self.dk,
            ct1: self.ct1,
        }
    }

    pub fn from_pb(pb: pqrpb::v1_state::unchunked::EkSentCt1Received) -> Result<Self, Error> {
        if pb.dk.len() == 2400 && pb.ct1.len() == 960 {
            Ok(Self {
                epoch: pb.epoch,
                auth: Authenticator::from_pb(pb.auth.as_ref().ok_or(Error::StateDecode)?),
                dk: pb.dk,
                ct1: pb.ct1,
            })
        } else {
            Err(Error::StateDecode)
        }
    }
}
