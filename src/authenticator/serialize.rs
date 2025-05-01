// Copyright 2025 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

use crate::proto;

use super::Authenticator;

impl Authenticator {
    pub fn into_pb(self) -> proto::pq_ratchet::Authenticator {
        proto::pq_ratchet::Authenticator {
            root_key: self.root_key,
            mac_key: self.mac_key,
        }
    }

    pub fn from_pb(pb: &proto::pq_ratchet::Authenticator) -> Self {
        Self {
            root_key: pb.root_key.clone(),
            mac_key: pb.mac_key.clone(),
        }
    }
}

#[cfg(test)]
mod test {
    use crate::authenticator::Authenticator;

    #[test]
    fn round_trip() {
        let auth = Authenticator::new(vec![42u8; 32], 1);
        let ack = auth.mac_ct(1, b"123");

        let pb_auth = auth.into_pb();

        let new_auth = Authenticator::from_pb(&pb_auth);
        let new_mac = new_auth.mac_ct(1, b"123");

        assert_eq!(ack, new_mac);
    }
}
