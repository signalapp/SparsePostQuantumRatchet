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
pub use crate::chain::ChainParams;
use crate::proto::pq_ratchet as pqrpb;
pub use crate::proto::pq_ratchet::{Direction, Version};
use prost::Message;
use rand::{CryptoRng, Rng};
use std::cmp::Ordering;
use v1::chunked::states as v1states;

pub type Epoch = u64;
pub type Secret = Vec<u8>;
pub type MessageKey = Option<Vec<u8>>;
pub type SerializedState = Vec<u8>;
pub type SerializedMessage = Vec<u8>;

pub fn empty_state() -> SerializedState {
    SerializedState::new()
}

pub struct EpochSecret {
    pub epoch: Epoch,
    pub secret: Secret,
}

pub struct Params<'a> {
    pub direction: Direction,
    pub version: Version,
    pub min_version: Version,
    pub auth_key: &'a [u8],
    pub chain_params: ChainParams,
}

impl Direction {
    pub fn switch(&self) -> Self {
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

#[derive(Debug)]
pub enum CurrentVersion {
    StillNegotiating {
        version: Version,
        min_version: Version,
    },
    NegotiationComplete(Version),
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
    #[error("Send key epoch decreased ({0} -> {1})")]
    SendKeyEpochDecreased(u64, u64),
    #[error("Invalid params: {0}")]
    InvalidParams(&'static str),
    #[error("Chain not available")]
    ChainNotAvailable,
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

impl From<Version> for u8 {
    fn from(v: Version) -> u8 {
        match v {
            Version::V0 => 0,
            Version::V1 => 1,
        }
    }
}

fn init_inner(v: Version, d: Direction, auth_key: &[u8]) -> Option<pqrpb::pq_ratchet_state::Inner> {
    match v {
        Version::V0 => None,
        Version::V1 => match d {
            Direction::A2B => Some(pqrpb::pq_ratchet_state::Inner::V1(
                v1states::States::init_a(auth_key).into_pb(),
            )),
            Direction::B2A => Some(pqrpb::pq_ratchet_state::Inner::V1(
                v1states::States::init_b(auth_key).into_pb(),
            )),
        },
    }
}

pub fn initial_state(params: Params) -> Result<SerializedState, Error> {
    hax_lib::fstar!("admit()");
    log::info!(
        "spqr initiating state with version {:?} and direction {:?}",
        params.version,
        params.direction
    );
    match params.version {
        Version::V0 => Ok(empty_state()),
        _ => {
            let version_negotiation = Some(pqrpb::pq_ratchet_state::VersionNegotiation {
                auth_key: params.auth_key.to_vec(),
                direction: params.direction.into(),
                min_version: params.min_version.into(),
                chain_params: Some(params.chain_params.into_pb()),
            });
            Ok(pqrpb::PqRatchetState {
                inner: init_inner(params.version, params.direction, params.auth_key),
                chain: None,
                version_negotiation,
            }
            .encode_to_vec())
        }
    }
}

impl Version {
    pub const DISABLED: Version = Self::V0;
    pub const MAX: Version = Self::V1;
}

pub struct Send {
    pub state: SerializedState,
    pub msg: SerializedMessage,
    pub key: MessageKey,
}

pub fn current_version(state: &SerializedState) -> Result<CurrentVersion, Error> {
    let state_pb = decode_state(state)?;
    let version = match state_pb.inner {
        None => Version::V0,
        Some(pqrpb::pq_ratchet_state::Inner::V1(_)) => Version::V1,
    };
    Ok(match state_pb.version_negotiation {
        None => CurrentVersion::NegotiationComplete(version),
        Some(vn) => CurrentVersion::StillNegotiating {
            version,
            min_version: vn.min_version.try_into().map_err(|_| Error::StateDecode)?,
        },
    })
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
            let v1states::Send { msg, key, state } = v1states::States::from_pb(pb)?.send(rng)?;
            let chain = match state_pb.chain {
                None => match state_pb.version_negotiation.as_ref() {
                    Some(vn) => {
                        if vn.min_version > Version::V0 as i32 {
                            Some(chain_from_version_negotiation(vn)?)
                        } else {
                            None
                        }
                    }
                    None => {
                        return Err(Error::ChainNotAvailable);
                    }
                },
                Some(pb) => Some(Chain::from_pb(pb)?),
            };
            let (index, msg_key, chain_pb) = match chain {
                None => {
                    assert!(key.is_none());
                    (0, vec![], None)
                }
                Some(mut chain) => {
                    if let Some(epoch_secret) = key {
                        chain.add_epoch(epoch_secret);
                    }
                    let (index, msg_key) = chain.send_key(msg.epoch - 1)?;
                    (index, msg_key, Some(chain.into_pb()))
                }
            };

            let msg = msg.serialize(index);
            assert!(!msg.is_empty());
            assert_eq!(msg[0], Version::V1.into());
            Ok(Send {
                state: pqrpb::PqRatchetState {
                    inner: Some(pqrpb::pq_ratchet_state::Inner::V1(state.into_pb())),
                    // Sending never changes our version negotiation.
                    version_negotiation: state_pb.version_negotiation,
                    chain: chain_pb,
                }
                .encode_to_vec(),
                msg,
                // hax does not like `filter`
                key: if msg_key.is_empty() {
                    None
                } else {
                    Some(msg_key)
                },
            })
        }
    }
}

pub struct Recv {
    pub state: SerializedState,
    pub key: MessageKey,
}

fn chain_from_version_negotiation(
    vn: &pqrpb::pq_ratchet_state::VersionNegotiation,
) -> Result<Chain, Error> {
    Chain::new(
        &vn.auth_key,
        vn.direction.try_into().map_err(|_| Error::StateDecode)?,
        vn.chain_params.ok_or(Error::ChainNotAvailable)?,
    )
}

fn chain_from(
    pb: Option<pqrpb::Chain>,
    vn: Option<&pqrpb::pq_ratchet_state::VersionNegotiation>,
) -> Result<Chain, Error> {
    match pb {
        Some(pb) => Ok(Chain::from_pb(pb)?),
        None => match vn {
            None => Err(Error::ChainNotAvailable),
            Some(vn) => chain_from_version_negotiation(vn),
        },
    }
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
            Ordering::Equal | Ordering::Greater => {
                // Our versions are equal; proceed with existing state
                prenegotiated_state_pb
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
                        if (v as i32) < vn.min_version {
                            return Err(Error::MinimumVersion);
                        }
                        log::info!("spqr negotiating version down to {v:?}");
                        pqrpb::PqRatchetState {
                            inner: init_inner(
                                v,
                                vn.direction.try_into().map_err(|_| Error::StateDecode)?,
                                &vn.auth_key,
                            ),
                            // This is our negotiation; we disallow any further.
                            version_negotiation: None,
                            chain: Some(
                                chain_from(
                                    prenegotiated_state_pb.chain,
                                    prenegotiated_state_pb.version_negotiation.as_ref(),
                                )?
                                .into_pb(),
                            ),
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
            let (scka_msg, index, _) = v1states::Message::deserialize(msg)?;

            let v1states::Recv { key, state } = v1states::States::from_pb(pb)?.recv(&scka_msg)?;
            let msg_key_epoch = scka_msg.epoch - 1;
            let mut chain = chain_from(state_pb.chain, state_pb.version_negotiation.as_ref())?;
            if let Some(epoch_secret) = key {
                chain.add_epoch(epoch_secret);
            }
            let msg_key = if msg_key_epoch == 0 && index == 0 {
                vec![]
            } else {
                chain.recv_key(msg_key_epoch, index)?
            };

            Ok(Recv {
                state: pqrpb::PqRatchetState {
                    inner: Some(pqrpb::pq_ratchet_state::Inner::V1(state.into_pb())),
                    // Receiving clears our version negotiation.
                    version_negotiation: None,
                    chain: Some(chain.into_pb()),
                }
                .encode_to_vec(),
                // hax does not like `filter`
                key: if msg_key.is_empty() {
                    None
                } else {
                    Some(msg_key)
                },
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

    use super::*;

    #[test]
    fn ratchet() -> Result<(), Error> {
        let mut rng = OsRng.unwrap_err();

        let version = Version::V1;

        let alex_pq_state = initial_state(Params {
            version,
            min_version: version,
            direction: Direction::A2B,
            auth_key: &[41u8; 32],
            chain_params: ChainParams::default(),
        })?;
        let blake_pq_state = initial_state(Params {
            version,
            min_version: version,
            direction: Direction::B2A,
            auth_key: &[41u8; 32],
            chain_params: ChainParams::default(),
        })?;

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

    #[test]
    fn empty_constructor_for_state() {
        let v = empty_state();
        assert!(v.is_empty());
    }

    #[test]
    fn empty_key_until_version_negotiation() -> Result<(), Error> {
        let mut rng = OsRng.unwrap_err();

        let version = Version::V1;

        let alex_pq_state = initial_state(Params {
            version,
            min_version: Version::V0,
            direction: Direction::A2B,
            auth_key: &[41u8; 32],
            chain_params: ChainParams::default(),
        })?;
        let blake_pq_state = initial_state(Params {
            version,
            min_version: Version::V0,
            direction: Direction::B2A,
            auth_key: &[41u8; 32],
            chain_params: ChainParams::default(),
        })?;

        // Now let's send some messages
        let Send {
            state: alex_pq_state,
            msg: msg_a1,
            key: key_a1,
        } = send(&alex_pq_state, &mut rng)?;
        let Send {
            state: alex_pq_state,
            msg: msg_a2,
            key: key_a2,
        } = send(&alex_pq_state, &mut rng)?;
        let Send {
            state: alex_pq_state,
            msg: msg_a3,
            key: key_a3,
        } = send(&alex_pq_state, &mut rng)?;

        let Send {
            state: blake_pq_state,
            msg: msg_b1,
            key: key_b1,
        } = send(&blake_pq_state, &mut rng)?;
        let Send {
            state: blake_pq_state,
            msg: msg_b2,
            key: key_b2,
        } = send(&blake_pq_state, &mut rng)?;
        let Send {
            state: blake_pq_state,
            msg: msg_b3,
            key: key_b3,
        } = send(&blake_pq_state, &mut rng)?;

        assert_eq!(key_a1, None);
        assert_eq!(key_a2, None);
        assert_eq!(key_a3, None);
        assert_eq!(key_b1, None);
        assert_eq!(key_b2, None);
        assert_eq!(key_b3, None);

        let Recv {
            state: alex_pq_state,
            key: key_b2,
        } = recv(&alex_pq_state, &msg_b2)?;
        assert_eq!(key_b2, None);
        // After our first Recv, keys are now non-empty.
        let Send {
            state: alex_pq_state,
            msg: msg_a4,
            key: key_a4,
        } = send(&alex_pq_state, &mut rng)?;
        assert!(key_a4.is_some());
        let Send {
            state: mut alex_pq_state,
            msg: msg_a5,
            key: key_a5,
        } = send(&alex_pq_state, &mut rng)?;
        assert!(key_a5.is_some());

        let Recv {
            state: blake_pq_state,
            key: key_a1,
        } = recv(&blake_pq_state, &msg_a1)?;
        assert_eq!(key_a1, None);
        // After our first Recv, keys are now non-empty.
        let Send {
            state: blake_pq_state,
            msg: msg_b4,
            key: key_b4,
        } = send(&blake_pq_state, &mut rng)?;
        assert!(key_b4.is_some());
        let Send {
            state: mut blake_pq_state,
            msg: msg_b5,
            key: key_b5,
        } = send(&blake_pq_state, &mut rng)?;
        assert!(key_b5.is_some());

        for (msg, want_key) in [
            (msg_a3, key_a3),
            (msg_a4, key_a4),
            (msg_a2, key_a2),
            (msg_a5, key_a5),
        ] {
            let Recv { state, key } = recv(&blake_pq_state, &msg)?;
            assert_eq!(want_key, key);
            blake_pq_state = state;
        }

        for (msg, want_key) in [
            (msg_b1, key_b1),
            (msg_b3, key_b3),
            (msg_b4, key_b4),
            (msg_b5, key_b5),
        ] {
            let Recv { state, key } = recv(&alex_pq_state, &msg)?;
            assert_eq!(want_key, key);
            alex_pq_state = state;
        }

        Ok(())
    }

    #[test]
    fn min_version_v1_always_creates_keys_a2b() -> Result<(), Error> {
        let mut rng = OsRng.unwrap_err();

        let alex_pq_state = initial_state(Params {
            version: Version::MAX,
            min_version: Version::V1,
            direction: Direction::A2B,
            auth_key: &[41u8; 32],
            chain_params: ChainParams::default(),
        })?;
        let blake_pq_state = initial_state(Params {
            version: Version::MAX,
            min_version: Version::V0,
            direction: Direction::B2A,
            auth_key: &[41u8; 32],
            chain_params: ChainParams::default(),
        })?;
        let Send {
            msg: msg_a1,
            key: key_a1,
            ..
        } = send(&alex_pq_state, &mut rng)?;
        assert!(key_a1.is_some());
        let Send {
            state: blake_pq_state,
            key: key_b1,
            ..
        } = send(&blake_pq_state, &mut rng)?;
        assert!(key_b1.is_none());
        let Recv {
            state: blake_pq_state,
            ..
        } = recv(&blake_pq_state, &msg_a1)?;
        // After our first Recv, keys are now non-empty.
        let Send { key: key_b2, .. } = send(&blake_pq_state, &mut rng)?;
        assert!(key_b2.is_some());
        Ok(())
    }

    #[test]
    fn min_version_v1_always_creates_keys_b2a() -> Result<(), Error> {
        let mut rng = OsRng.unwrap_err();

        let alex_pq_state = initial_state(Params {
            version: Version::MAX,
            min_version: Version::V0,
            direction: Direction::A2B,
            auth_key: &[41u8; 32],
            chain_params: ChainParams::default(),
        })?;
        let blake_pq_state = initial_state(Params {
            version: Version::MAX,
            min_version: Version::V1,
            direction: Direction::B2A,
            auth_key: &[41u8; 32],
            chain_params: ChainParams::default(),
        })?;
        let Send {
            msg: msg_b1,
            key: key_b1,
            ..
        } = send(&blake_pq_state, &mut rng)?;
        assert!(key_b1.is_some());
        let Send {
            state: alex_pq_state,
            key: key_a1,
            ..
        } = send(&alex_pq_state, &mut rng)?;
        assert!(key_a1.is_none());
        let Recv {
            state: alex_pq_state,
            ..
        } = recv(&alex_pq_state, &msg_b1)?;
        // After our first Recv, keys are now non-empty.
        let Send { key: key_a2, .. } = send(&alex_pq_state, &mut rng)?;
        assert!(key_a2.is_some());
        Ok(())
    }

    #[test]
    fn negotiate_to_v0_a2b() -> Result<(), Error> {
        let mut rng = OsRng.unwrap_err();

        let alex_pq_state = initial_state(Params {
            version: Version::MAX,
            min_version: Version::V0,
            direction: Direction::A2B,
            auth_key: &[41u8; 32],
            chain_params: ChainParams::default(),
        })?;
        let blake_pq_state = initial_state(Params {
            version: Version::V0,
            min_version: Version::V0,
            direction: Direction::B2A,
            auth_key: &[41u8; 32],
            chain_params: ChainParams::default(),
        })?;
        assert!(matches!(
            current_version(&alex_pq_state)?,
            CurrentVersion::StillNegotiating {
                version: Version::MAX,
                min_version: Version::V0
            },
        ));
        assert!(matches!(
            current_version(&blake_pq_state)?,
            CurrentVersion::NegotiationComplete(Version::V0),
        ));
        let Send {
            msg: msg_a1,
            state: alex_pq_state,
            ..
        } = send(&alex_pq_state, &mut rng)?;
        let Recv {
            state: blake_pq_state,
            ..
        } = recv(&blake_pq_state, &msg_a1)?;
        let Send { msg: msg_b1, .. } = send(&blake_pq_state, &mut rng)?;
        let Recv {
            state: alex_pq_state,
            ..
        } = recv(&alex_pq_state, &msg_b1)?;
        assert!(matches!(
            current_version(&alex_pq_state)?,
            CurrentVersion::NegotiationComplete(Version::V0),
        ));
        assert!(matches!(
            current_version(&alex_pq_state)?,
            CurrentVersion::NegotiationComplete(Version::V0),
        ));
        Ok(())
    }

    #[test]
    fn negotiate_to_v0_b2a() -> Result<(), Error> {
        let mut rng = OsRng.unwrap_err();

        let alex_pq_state = initial_state(Params {
            version: Version::V0,
            min_version: Version::V0,
            direction: Direction::A2B,
            auth_key: &[41u8; 32],
            chain_params: ChainParams::default(),
        })?;
        let blake_pq_state = initial_state(Params {
            version: Version::MAX,
            min_version: Version::V0,
            direction: Direction::B2A,
            auth_key: &[41u8; 32],
            chain_params: ChainParams::default(),
        })?;
        assert!(matches!(
            current_version(&alex_pq_state)?,
            CurrentVersion::NegotiationComplete(Version::V0),
        ));
        assert!(matches!(
            current_version(&blake_pq_state)?,
            CurrentVersion::StillNegotiating {
                version: Version::MAX,
                min_version: Version::V0
            },
        ));
        let Send {
            msg: msg_a1,
            state: alex_pq_state,
            ..
        } = send(&alex_pq_state, &mut rng)?;
        let Recv {
            state: blake_pq_state,
            ..
        } = recv(&blake_pq_state, &msg_a1)?;
        let Send { msg: msg_b1, .. } = send(&blake_pq_state, &mut rng)?;
        let Recv {
            state: alex_pq_state,
            ..
        } = recv(&alex_pq_state, &msg_b1)?;
        assert!(matches!(
            current_version(&alex_pq_state)?,
            CurrentVersion::NegotiationComplete(Version::V0),
        ));
        assert!(matches!(
            current_version(&alex_pq_state)?,
            CurrentVersion::NegotiationComplete(Version::V0),
        ));
        Ok(())
    }

    #[test]
    fn negotiation_refused_a2b() -> Result<(), Error> {
        let mut rng = OsRng.unwrap_err();

        let alex_pq_state = initial_state(Params {
            version: Version::MAX,
            min_version: Version::V1,
            direction: Direction::A2B,
            auth_key: &[41u8; 32],
            chain_params: ChainParams::default(),
        })?;
        let blake_pq_state = initial_state(Params {
            version: Version::V0,
            min_version: Version::V0,
            direction: Direction::B2A,
            auth_key: &[41u8; 32],
            chain_params: ChainParams::default(),
        })?;
        assert!(matches!(
            current_version(&alex_pq_state)?,
            CurrentVersion::StillNegotiating {
                version: Version::MAX,
                min_version: Version::V1
            },
        ));
        assert!(matches!(
            current_version(&blake_pq_state)?,
            CurrentVersion::NegotiationComplete(Version::V0),
        ));
        let Send {
            msg: msg_a1,
            state: alex_pq_state,
            ..
        } = send(&alex_pq_state, &mut rng)?;
        let Recv {
            state: blake_pq_state,
            ..
        } = recv(&blake_pq_state, &msg_a1)?;
        let Send { msg: msg_b1, .. } = send(&blake_pq_state, &mut rng)?;
        assert!(matches!(
            recv(&alex_pq_state, &msg_b1),
            Err(Error::MinimumVersion),
        ));
        Ok(())
    }

    #[test]
    fn negotiation_refused_b2a() -> Result<(), Error> {
        let mut rng = OsRng.unwrap_err();

        let alex_pq_state = initial_state(Params {
            version: Version::V0,
            min_version: Version::V0,
            direction: Direction::A2B,
            auth_key: &[41u8; 32],
            chain_params: ChainParams::default(),
        })?;
        let blake_pq_state = initial_state(Params {
            version: Version::MAX,
            min_version: Version::V1,
            direction: Direction::B2A,
            auth_key: &[41u8; 32],
            chain_params: ChainParams::default(),
        })?;
        assert!(matches!(
            current_version(&alex_pq_state)?,
            CurrentVersion::NegotiationComplete(Version::V0),
        ));
        assert!(matches!(
            current_version(&blake_pq_state)?,
            CurrentVersion::StillNegotiating {
                version: Version::MAX,
                min_version: Version::V1
            },
        ));
        let Send { msg: msg_a1, .. } = send(&alex_pq_state, &mut rng)?;
        assert!(matches!(
            recv(&blake_pq_state, &msg_a1),
            Err(Error::MinimumVersion)
        ));
        Ok(())
    }
}
