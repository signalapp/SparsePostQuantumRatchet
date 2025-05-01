// Copyright 2025 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

pub mod authenticator;
pub mod chain;
pub mod encoding;
pub(crate) mod incremental_mlkem768;
pub(crate) mod kdf;
pub mod proto;
pub mod serialize;
pub(crate) mod test;
pub(crate) mod util;
mod v1;

use crate::chain::Chain;
use crate::proto::pq_ratchet as pqrpb;
use num_enum::IntoPrimitive;
use prost::Message;
use rand::{CryptoRng, Rng};
use std::cmp::Ordering;
use v1::chunked::states as v1states;

pub type Epoch = u64;
pub type Secret = Vec<u8>;
pub type MessageKey = Option<Vec<u8>>;
pub type SerializedState = Vec<u8>;
pub type SerializedMessage = Vec<u8>;

pub struct EpochSecret {
    pub epoch: Epoch,
    pub secret: Secret,
}

#[derive(Clone, Copy)]
pub enum Direction {
    A2B,
    B2A,
}

impl Direction {
    fn switch(&self) -> Self {
        match self {
            Direction::A2B => Direction::B2A,
            Direction::B2A => Direction::A2B,
        }
    }
}

#[derive(PartialEq, Debug)]
pub enum SecretOutput {
    /// Receipt of the message has resulted in no additional shared secrets
    /// to mix in.
    None,
    /// Receipt of the message has resulted in a shared secret which should
    /// be mixed into the sending chain before using it to encrypt/send the
    /// next message sent by this client.
    Send(Secret),
    /// Receipt of the message has resulted in a shared secret which will be
    /// used to encrypt the next message we receive, and thus should be mixed
    /// into our new receiving chain.
    Recv(Secret),
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("state decode failed")]
    StateDecode,
    #[error("not yet implemented")]
    NotImplemented,
    #[error("message decode failed")]
    MsgDecode,
    #[error("MAC verification failed")]
    MacVerifyFailed,
    #[error("epoch not in valid range: {0}")]
    EpochOutOfRange(Epoch),
    #[error("epoch failure")]
    EpochFailure,
    #[error("MAC should have key but doesn't")]
    MacStateInvalid,
    #[error("Underlying state machine in the wrong state")]
    BaseStateInvalid,
    #[error("Encoding error: {0}")]
    EncodingDecoding(encoding::EncodingError),
    #[error("Serialization: {0}")]
    Serialization(serialize::Error),
    #[error("Version mismatch after negotiation")]
    VersionMismatch,
    #[error("Minimum version")]
    MinimumVersion,
    #[error("Key jump: {0} - {1}")]
    KeyJump(u32, u32),
    #[error("Key trimmed: {0}")]
    KeyTrimmed(u32),
    #[error("Key already requested: {0}")]
    KeyAlreadyRequested(u32),
    #[error("Erroneous data received from remote party")]
    ErroneousDataReceived,
}

impl From<encoding::EncodingError> for Error {
    fn from(e: encoding::EncodingError) -> Error {
        Error::EncodingDecoding(e)
    }
}

impl From<serialize::Error> for Error {
    fn from(v: serialize::Error) -> Self {
        Error::Serialization(v)
    }
}

impl From<authenticator::Error> for Error {
    fn from(_v: authenticator::Error) -> Self {
        Error::MacVerifyFailed
    }
}

impl SecretOutput {
    pub fn send_secret(&self) -> Option<&Secret> {
        match self {
            SecretOutput::Send(s) => Some(s),
            SecretOutput::Recv(_) => None,
            SecretOutput::None => None,
        }
    }
    pub fn recv_secret(&self) -> Option<&Secret> {
        match self {
            SecretOutput::Send(_) => None,
            SecretOutput::Recv(s) => Some(s),
            SecretOutput::None => None,
        }
    }

    pub fn secret(&self) -> Option<&Secret> {
        match self {
            SecretOutput::Send(s) | SecretOutput::Recv(s) => Some(s),
            _ => None,
        }
    }
    pub fn has_secret(&self) -> bool {
        !matches!(self, Self::None)
    }
}

/// Protocol version.
///
/// Note that these versions are strictly ordered:  if vX > vY, it is
/// assumed that vX is preferred to vY and should be used if both
/// parties support it.
#[derive(Copy, Clone, IntoPrimitive)]
#[repr(u8)]
pub enum Version {
    /// V0 is not using PQ ratcheting at all.  All sends are empty, and no
    /// secrets are ever returned.
    V0 = 0,
    /// V1 uses an incremental ML-KEM 768 negotiation with polynomial encoders
    /// based on GF16.
    V1 = 1,
}

#[hax_lib::opaque]
impl TryFrom<u8> for Version {
    type Error = String;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Version::V0),
            1 => Ok(Version::V1),
            _ => Err("Expected 0 or 1".to_owned()),
        }
    }
}

impl Version {
    pub const MAX: Version = Self::V1;

    pub fn initial_alice_state(&self, auth_key: &[u8], min_version: Version) -> SerializedState {
        hax_lib::fstar!("admit()");
        pqrpb::PqRatchetState {
            inner: self.init_alice_inner(auth_key),
            version_negotiation: Some(pqrpb::pq_ratchet_state::VersionNegotiation {
                auth_key: auth_key.to_vec(),
                alice: true,
                min_version: min_version as u32,
            }),
            chain: Some(Chain::new(auth_key, Direction::A2B).into_pb()),
        }
        .encode_to_vec()
    }

    pub fn initial_bob_state(&self, auth_key: &[u8], min_version: Version) -> SerializedState {
        hax_lib::fstar!("admit()");
        pqrpb::PqRatchetState {
            inner: self.init_bob_inner(auth_key),
            version_negotiation: Some(pqrpb::pq_ratchet_state::VersionNegotiation {
                auth_key: auth_key.to_vec(),
                alice: false,
                min_version: min_version as u32,
            }),
            chain: Some(Chain::new(auth_key, Direction::B2A).into_pb()),
        }
        .encode_to_vec()
    }

    fn init_alice_inner(&self, auth_key: &[u8]) -> Option<pqrpb::pq_ratchet_state::Inner> {
        match self {
            Version::V0 => None,
            Version::V1 => Some(pqrpb::pq_ratchet_state::Inner::V1(
                v1states::States::init_a(auth_key).into_pb(),
            )),
        }
    }
    fn init_bob_inner(&self, auth_key: &[u8]) -> Option<pqrpb::pq_ratchet_state::Inner> {
        match self {
            Version::V0 => None,
            Version::V1 => Some(pqrpb::pq_ratchet_state::Inner::V1(
                v1states::States::init_b(auth_key).into_pb(),
            )),
        }
    }
}

pub struct Send {
    pub state: SerializedState,
    pub msg: SerializedMessage,
    pub key: MessageKey,
}

#[hax_lib::fstar::verification_status(lax)]
pub fn send<R: Rng + CryptoRng>(state: &SerializedState, rng: &mut R) -> Result<Send, Error> {
    let state_pb = decode_state(state)?;
    match state_pb.inner {
        None => Ok(Send {
            state: vec![],
            msg: vec![],
            key: None,
        }),
        Some(pqrpb::pq_ratchet_state::Inner::V1(pb)) => {
            let mut chain = Chain::from_pb(state_pb.chain.ok_or(Error::StateDecode)?)?;

            let v1states::Send { msg, key, state } = v1states::States::from_pb(pb)?.send(rng)?;

            if let Some(epoch_secret) = key {
                chain.add_epoch(epoch_secret);
            }
            let (index, msg_key) = chain.send_key(msg.epoch - 1)?;

            let msg = msg.serialize(index);
            assert!(!msg.is_empty());
            assert_eq!(msg[0], Version::V1.into());
            Ok(Send {
                state: pqrpb::PqRatchetState {
                    inner: Some(pqrpb::pq_ratchet_state::Inner::V1(state.into_pb())),
                    // Sending never changes our version negotiation.
                    version_negotiation: state_pb.version_negotiation,
                    chain: Some(chain.into_pb()),
                }
                .encode_to_vec(),
                msg,
                key: Some(msg_key),
            })
        }
    }
}

pub struct Recv {
    pub state: SerializedState,
    pub key: MessageKey,
}

#[hax_lib::fstar::verification_status(lax)]
pub fn recv(state: &SerializedState, msg: &SerializedMessage) -> Result<Recv, Error> {
    // Perform version negotiation.  At the beginning of our interaction
    // with a remote party, we are set to allow negotiation.  This
    // allows either side to downgrade the connection to a protocol version
    // that that side supports, while still using the highest protocol
    // version supported by both sides.
    let prenegotiated_state_pb = decode_state(state)?;
    let state_pb = match msg_version(msg) {
        None => {
            // They have presented a version we don't support; it's too high for us,
            // so ignore it and keep sending our current version's format.
            return Ok(Recv {
                state: state.to_vec(),
                key: None,
            });
        }
        Some(v) => match (v as u8).cmp(&(state_version(&prenegotiated_state_pb) as u8)) {
            Ordering::Equal => {
                // Our versions are equal; proceed with existing state
                prenegotiated_state_pb
            }
            Ordering::Greater => {
                // Their version is greater than ours, but still one we support.
                // This should not happen, since we should use our highest supported
                // version.
                return Err(Error::VersionMismatch);
            }
            Ordering::Less => {
                // Their version is less than ours.  If we are allowed to negotiate, we
                // should.  Otherwise, we should error out.
                //
                // When negotiating down a level, we disallow future negotiation.
                match prenegotiated_state_pb.version_negotiation {
                    None => {
                        return Err(Error::VersionMismatch);
                    }
                    Some(ref vn) => {
                        if (v as u32) < vn.min_version {
                            return Err(Error::MinimumVersion);
                        }
                        pqrpb::PqRatchetState {
                            inner: if vn.alice {
                                v.init_alice_inner(&vn.auth_key)
                            } else {
                                v.init_bob_inner(&vn.auth_key)
                            },
                            // This is our negotiation; we disallow any further.
                            version_negotiation: None,
                            chain: prenegotiated_state_pb.chain,
                        }
                    }
                }
            }
        },
    };

    // At this point, we have finished version negotiation and have made sure
    // that our state version matches.  Proceed with receiving and processing
    // the associated message.
    match state_pb.inner {
        None => Ok(Recv {
            state: vec![],
            key: None,
        }),
        Some(pqrpb::pq_ratchet_state::Inner::V1(pb)) => {
            let mut chain = Chain::from_pb(state_pb.chain.ok_or(Error::StateDecode)?)?;
            let (scka_msg, index, _) = v1states::Message::deserialize(msg)?;

            let v1states::Recv { key, state } = v1states::States::from_pb(pb)?.recv(&scka_msg)?;

            if let Some(epoch_secret) = key {
                chain.add_epoch(epoch_secret);
            }

            let msg_key = chain.recv_key(scka_msg.epoch - 1, index)?;
            Ok(Recv {
                state: pqrpb::PqRatchetState {
                    inner: Some(pqrpb::pq_ratchet_state::Inner::V1(state.into_pb())),
                    // Receiving clears our version negotiation.
                    version_negotiation: None,
                    chain: Some(chain.into_pb()),
                }
                .encode_to_vec(),
                key: Some(msg_key),
            })
        }
    }
}

fn state_version(state: &pqrpb::PqRatchetState) -> Version {
    match state.inner {
        None => Version::V0,
        Some(proto::pq_ratchet::pq_ratchet_state::Inner::V1(_)) => Version::V1,
    }
}

#[hax_lib::fstar::verification_status(lax)]
fn msg_version(msg: &SerializedMessage) -> Option<Version> {
    if msg.is_empty() {
        Some(Version::V0)
    } else {
        msg[0].try_into().ok()
    }
}

#[hax_lib::fstar::verification_status(lax)]
fn decode_state(s: &SerializedState) -> Result<pqrpb::PqRatchetState, Error> {
    if s.is_empty() {
        Ok(proto::pq_ratchet::PqRatchetState {
            inner: None,
            version_negotiation: None,
            chain: None,
        })
    } else {
        proto::pq_ratchet::PqRatchetState::decode(s.as_slice()).map_err(|_| Error::StateDecode)
    }
}

#[cfg(test)]
mod lib_test {
    use rand::Rng;
    use rand::TryRngCore;
    use rand_core::OsRng;

    use crate::{recv, send, Error, Recv, Send, SerializedState, Version};

    #[test]
    fn ratchet() -> Result<(), Error> {
        let mut rng = OsRng.unwrap_err();

        let version = Version::V1;

        let alex_pq_state = version.initial_alice_state(&[41u8; 32], Version::V1);
        let blake_pq_state = version.initial_bob_state(&[41u8; 32], Version::V1);

        // Now let's send some messages
        let Send {
            state: alex_pq_state,
            msg,
            key: alex_key,
        } = send(&alex_pq_state, &mut rng)?;

        let Recv {
            state: blake_pq_state,
            key: blake_key,
        } = recv(&blake_pq_state, &msg)?;

        assert_eq!(alex_key, blake_key);

        let Send {
            state: mut blake_pq_state,
            msg,
            key: blake_key,
        } = send(&blake_pq_state, &mut rng)?;

        let Recv {
            state: mut alex_pq_state,
            key: alex_key,
        } = recv(&alex_pq_state, &msg)?;

        assert_eq!(alex_key, blake_key);

        // now let's mix it up a little
        for _ in 0..1000 {
            let a_send = rng.random_bool(0.5);
            let b_send = rng.random_bool(0.5);
            let a_recv = rng.random_bool(0.7);
            let b_recv = rng.random_bool(0.7);

            if a_send {
                let Send {
                    state,
                    msg,
                    key: alex_key,
                } = send(&alex_pq_state, &mut rng)?;
                alex_pq_state = state;
                if b_recv {
                    let Recv {
                        state,
                        key: blake_key,
                    } = recv(&blake_pq_state, &msg)?;
                    blake_pq_state = state;

                    assert_eq!(alex_key, blake_key);
                }
            }

            if b_send {
                let Send {
                    state,
                    msg,
                    key: blake_key,
                } = send(&blake_pq_state, &mut rng)?;
                blake_pq_state = state;
                if a_recv {
                    let Recv {
                        state,
                        key: alex_key,
                    } = recv(&alex_pq_state, &msg)?;
                    alex_pq_state = state;

                    assert_eq!(alex_key, blake_key);
                }
            }
        }

        Ok(())
    }

    #[test]
    fn ratchet_v0_empty_states() -> Result<(), Error> {
        let mut rng = OsRng.unwrap_err();

        // SPQR should treat empty states as V0.

        let alex_pq_state = SerializedState::new();
        let blake_pq_state = SerializedState::new();

        // Now let's send some messages
        let Send {
            state: alex_pq_state,
            msg,
            key: alex_key,
        } = send(&alex_pq_state, &mut rng)?;

        let Recv {
            state: blake_pq_state,
            key: blake_key,
        } = recv(&blake_pq_state, &msg)?;

        assert_eq!(alex_key, blake_key);

        let Send {
            state: mut blake_pq_state,
            msg,
            key: blake_key,
        } = send(&blake_pq_state, &mut rng)?;

        let Recv {
            state: mut alex_pq_state,
            key: alex_key,
        } = recv(&alex_pq_state, &msg)?;

        assert_eq!(alex_key, blake_key);

        // now let's mix it up a little
        for _ in 0..1000 {
            let a_send = rng.random_bool(0.5);
            let b_send = rng.random_bool(0.5);
            let a_recv = rng.random_bool(0.7);
            let b_recv = rng.random_bool(0.7);

            if a_send {
                let Send {
                    state,
                    msg,
                    key: alex_key,
                } = send(&alex_pq_state, &mut rng)?;
                alex_pq_state = state;
                if b_recv {
                    let Recv {
                        state,
                        key: blake_key,
                    } = recv(&blake_pq_state, &msg)?;
                    blake_pq_state = state;

                    assert_eq!(alex_key, blake_key);
                }
            }

            if b_send {
                let Send {
                    state,
                    msg,
                    key: blake_key,
                } = send(&blake_pq_state, &mut rng)?;
                blake_pq_state = state;
                if a_recv {
                    let Recv {
                        state,
                        key: alex_key,
                    } = recv(&alex_pq_state, &msg)?;
                    alex_pq_state = state;

                    assert_eq!(alex_key, blake_key);
                }
            }
        }

        Ok(())
    }
}
