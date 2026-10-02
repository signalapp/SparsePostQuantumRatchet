// Copyright 2025 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

pub(crate) mod authenticator;
#[cfg(feature = "test-utils")]
pub mod chain;
#[cfg(not(feature = "test-utils"))]
pub(crate) mod chain;
#[cfg(feature = "test-utils")]
pub mod encoding;
#[cfg(not(feature = "test-utils"))]
pub(crate) mod encoding;
pub(crate) mod incremental_mlkem768;
pub(crate) mod kdf;
pub(crate) mod serialize;
pub(crate) mod test;
pub(crate) mod util;
mod v1;

#[cfg(feature = "test-utils")]
pub mod proto;
#[cfg(not(feature = "test-utils"))]
mod proto;

use crate::chain::Chain;
pub use crate::chain::ChainParams;
use crate::proto::pq_ratchet as pqrpb;
pub use crate::proto::pq_ratchet::{Direction, Version};
use std::cmp::min;
use std::cmp::Ordering;
// Re-export error types that are part of the public Error enum
pub use crate::authenticator::Error as AuthenticatorError;
pub use crate::encoding::polynomial::PolynomialError;
pub use crate::encoding::EncodingError;
pub use crate::serialize::Error as SerializationError;
use prost::Message;
use rand::{CryptoRng, Rng};
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

impl TryFrom<u8> for Version {
    type Error = String;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Version::V0),
            1 => Ok(Version::V1),
            _ => Err(format!("Expected 0 or 1, got {value}")),
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
    #[cfg(not(hax))]
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

#[hax_lib::ensures(|res| fstar!(r#"
    match res with
    | Core_models.Result.Result_Ok r ->
      (match r.f_key with
       | Core_models.Option.Option_Some k ->
         b2t (Alloc.Vec.impl_1__len k >. mk_usize 0)
       | _ -> True)
    | _ -> True"#))]
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
                    if key.is_some() {
                        return Err(Error::ChainNotAvailable);
                    }
                    (0, vec![], None)
                }
                Some(mut chain) => {
                    if let Some(epoch_secret) = key {
                        chain.add_epoch(epoch_secret)?;
                    }
                    // A well-formed v1 state has epoch >= 1 (the initial epoch is 1);
                    // epoch 0 only arises from a malformed decoded state, so reject it
                    // rather than underflowing.
                    let msg_key_epoch = msg.epoch.checked_sub(1).ok_or(Error::StateDecode)?;
                    let (index, msg_key) = chain.send_key(msg_key_epoch)?;
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
                key: message_key(msg_key),
            })
        }
    }
}

#[hax_lib::ensures(|res| match res {
    Some(k) => k.len() > 0,
    None => true,
})]
fn message_key(k: Vec<u8>) -> MessageKey {
    // hax does not like `filter`
    if k.is_empty() {
        None
    } else {
        Some(k)
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

#[hax_lib::fstar::options("--split_queries always")]
pub fn recv(state: &SerializedState, msg: &SerializedMessage) -> Result<Recv, Error> {
    let msg = msg_preamble(msg)?;

    // Perform version negotiation.  At the beginning of our interaction
    // with a remote party, we are set to allow negotiation.  This
    // allows either side to downgrade the connection to a protocol version
    // that that side supports, while still using the highest protocol
    // version supported by both sides.
    let prenegotiated_state_pb = decode_state(state)?;

    let current_version: u8 = state_version(&prenegotiated_state_pb).into();
    let (min_version, version_still_negotiating) = match prenegotiated_state_pb.version_negotiation
    {
        Some(ref vn) => (vn.min_version as u8, true),
        None => (current_version, current_version == 0),
    };
    if msg.version < min_version {
        return Err(Error::MinimumVersion);
    } else if msg.version != current_version && !version_still_negotiating {
        return Err(Error::VersionMismatch);
    } else if current_version == 0 {
        return Ok(Recv {
            state: vec![],
            key: None,
        });
    }

    let state_pb = match msg.version.cmp(&current_version) {
        Ordering::Greater => {
            // Their version is greater than our own.  This means that we won't be able to
            // decode the (SPQR) message they sent, but we should be able to provide the
            // appropriate key back, and we should stay in a state which allows us to
            // negotiate the version down to ours.
            //
            // We know that both our and their version is greater than zero, so we are required to
            // provide a chain key to our caller.
            //
            // When two endpoints with the same version are talking to each other, they
            // may compute the epoch to pull chain keys from based off of the msg.epoch,
            // their internal state, etc.  We can't perform those calculations here, because
            // we don't know the unsupported protocol yet.  However, we luckily don't need
            // to.  You can only pull a chain key from an epoch you've already reached, and
            // you can't reach an epoch above zero without some back-and-forth communication
            // between two endpoints of the same version.  We know we haven't had that, because
            // their version is higher than ours.  So, even without that per-version computation,
            // we know that we need to pull the chain key from epoch zero.
            const ZERO_EPOCH: Epoch = 0;
            let mut chain = chain_from(
                prenegotiated_state_pb.chain,
                prenegotiated_state_pb.version_negotiation.as_ref(),
            )?;
            let key = message_key(chain.recv_key(ZERO_EPOCH, msg.index)?);

            return Ok(Recv {
                key,
                state: pqrpb::PqRatchetState {
                    chain: Some(chain.into_pb()),
                    // We leave `version_negotiation` in our state to tell future calls to this
                    // function that they're allowed to accept other messages from the greater
                    // version number.
                    version_negotiation: prenegotiated_state_pb.version_negotiation,
                    inner: prenegotiated_state_pb.inner,
                }
                .encode_to_vec(),
            });
        }
        Ordering::Equal => prenegotiated_state_pb,
        Ordering::Less => {
            // Their version is less than ours, and we are allowed to negotiate down
            // to their version.  Do so.
            assert!(current_version > 0 && version_still_negotiating);
            let vn = prenegotiated_state_pb
                .version_negotiation
                .as_ref()
                .expect("still negotiating");
            let v: Version = msg
                .version
                .try_into()
                .expect("should support all lower versions");
            #[cfg(not(hax))]
            log::info!("spqr negotiating version down to {v:?}");
            pqrpb::PqRatchetState {
                inner: init_inner(
                    v,
                    vn.direction.try_into().map_err(|_| Error::StateDecode)?,
                    &vn.auth_key,
                ),
                // This is our sole negotiation; we disallow any further.
                version_negotiation: None,
                chain: Some(chain_from(prenegotiated_state_pb.chain, Some(vn))?.into_pb()),
            }
        }
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
            let scka_msg = v1states::Message::deserialize(msg.epoch, msg.remaining)?;

            let v1states::Recv { key, state } = v1states::States::from_pb(pb)?.recv(&scka_msg)?;

            let msg_key_epoch = msg.epoch - 1;
            let mut chain = chain_from(state_pb.chain, state_pb.version_negotiation.as_ref())?;
            if let Some(epoch_secret) = key {
                chain.add_epoch(epoch_secret)?;
            }
            let msg_key = chain.recv_key(msg_key_epoch, msg.index)?;

            Ok(Recv {
                state: pqrpb::PqRatchetState {
                    inner: Some(pqrpb::pq_ratchet_state::Inner::V1(state.into_pb())),
                    // Receiving clears our version negotiation.
                    version_negotiation: None,
                    chain: Some(chain.into_pb()),
                }
                .encode_to_vec(),
                key: message_key(msg_key),
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

const MAX_VARINT_BYTES_LEN: usize = 10;

#[hax_lib::requires(into.len() <= usize::MAX - MAX_VARINT_BYTES_LEN)]
#[hax_lib::ensures(|_| into.len() <= future(into).len()
    && future(into).len() <= into.len() + MAX_VARINT_BYTES_LEN
    && (into.len() == 0 || future(into)[0] == into[0]))]
fn encode_varint(mut a: u64, into: &mut SerializedMessage) {
    #[cfg(hax)]
    let l0 = into.len();
    #[cfg(hax)]
    let b0 = if l0 == 0 { 0 } else { into[0] };
    for _i in 0..MAX_VARINT_BYTES_LEN {
        hax_lib::loop_invariant!(|i: usize| l0 <= into.len()
            && into.len() <= l0 + i
            && (l0 == 0 || into[0] == b0));
        let byte = (a & 0x7F) as u8;
        if a < 0x80 {
            into.push(byte);
            break;
        } else {
            into.push(0x80 | byte);
            a >>= 7;
        }
    }
}

#[hax_lib::ensures(|res| *at <= *future(at) && if res.is_ok() { *at < from.len() && *future(at) <= from.len() } else { true })]
fn decode_varint(from: &[u8], at: &mut usize) -> Result<u64, Error> {
    let mut out = 0u64;

    let mut i: usize = 0;
    // Helps prevent return in while loop for Hax
    let mut done = false;
    let start_at: usize = *at;
    if start_at >= from.len() {
        return Err(Error::MsgDecode);
    }

    let max_i = min(MAX_VARINT_BYTES_LEN, from.len() - start_at);

    while i < max_i && !done {
        hax_lib::loop_invariant!(i <= max_i && *at == start_at);
        hax_lib::loop_decreases!(max_i - i);

        let byte = from[start_at + i];
        out |= ((byte as u64) & 0x7f) << (7 * i as i32);

        i += 1;
        done = (byte & 0x80) == 0;
    }

    if done {
        *at += i;
        Ok(out)
    } else {
        Err(Error::MsgDecode)
    }
}

struct MsgPreamble<'a> {
    version: u8,
    epoch: Epoch,
    index: u32,
    remaining: &'a [u8],
}

fn msg_preamble<'a>(msg: &'a SerializedMessage) -> Result<MsgPreamble<'a>, Error> {
    if msg.is_empty() {
        return Ok(MsgPreamble {
            version: 0,
            epoch: 0,
            index: 0,
            remaining: b"",
        });
    }
    let version = msg[0];
    let mut at = 1usize;
    let epoch = decode_varint(msg, &mut at)? as Epoch;
    if epoch == 0 {
        return Err(Error::MsgDecode);
    }
    let index: u32 = decode_varint(msg, &mut at)?
        .try_into()
        .map_err(|_| Error::MsgDecode)?;
    if at > msg.len() {
        return Err(Error::MsgDecode);
    }
    Ok(MsgPreamble {
        version,
        epoch,
        index,
        remaining: &msg[at..],
    })
}

#[cfg(test)]
mod lib_test {
    use rand::Rng;
    use rand::TryRngCore;
    use rand_core::OsRng;
    use std::assert_matches;

    use super::*;

    #[test]
    fn ratchet() -> Result<(), Error> {
        let _ = env_logger::builder().is_test(true).try_init();
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
        assert!(msg_b1.is_empty());
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

    /// A test that runs a set number of steps, always sending one message A->B, then
    /// one message B->A, with logging turned on, so we can watch how things work
    /// in the most predictable case.
    #[test]
    fn lockstep_run_with_logging() -> Result<(), Error> {
        let _ = env_logger::builder().is_test(true).try_init();
        let mut rng = OsRng.unwrap_err();

        let version = Version::V1;

        let mut alex_pq_state = initial_state(Params {
            version,
            min_version: version,
            direction: Direction::A2B,
            auth_key: &[41u8; 32],
            chain_params: ChainParams::default(),
        })?;
        let mut blake_pq_state = initial_state(Params {
            version,
            min_version: version,
            direction: Direction::B2A,
            auth_key: &[41u8; 32],
            chain_params: ChainParams::default(),
        })?;

        for i in 0..30 {
            log::info!("step {}", i);
            // Now let's send some messages
            let Send {
                state,
                msg,
                key: alex_key,
            } = send(&alex_pq_state, &mut rng)?;
            alex_pq_state = state;
            let Recv {
                state,
                key: blake_key,
            } = recv(&blake_pq_state, &msg)?;
            blake_pq_state = state;
            assert_eq!(alex_key, blake_key);
            let Send {
                state,
                msg,
                key: blake_key,
            } = send(&blake_pq_state, &mut rng)?;
            blake_pq_state = state;
            let Recv {
                state,
                key: alex_key,
            } = recv(&alex_pq_state, &msg)?;
            alex_pq_state = state;
            assert_eq!(alex_key, blake_key);
        }
        log::info!("alex_state:  {}", hex::encode(alex_pq_state));
        log::info!("blake_state: {}", hex::encode(blake_pq_state));
        Ok(())
    }

    #[test]
    fn regression_test_libcrux_issue_1275_from_generated_states() -> Result<(), Error> {
        let _ = env_logger::builder().is_test(true).try_init();
        let mut rng = OsRng.unwrap_err();

        // These states are generated using the old "portable" logic for libcrux-ml-kem
        // EncapsState serialization prior to libcrux:pr/1276, 30 steps into a lockstep
        // protocol.  The send_ct side has already generated the encapsulation state
        // and stored it locally, but hasn't yet called encapsulate2 on it.  This tests
        // to make sure that the incremental_mlkem code path correctly notices and handles
        // this eventuality.
        let mut alex_pq_state = include_bytes!("issue1275_a_state.in").to_vec();
        let mut blake_pq_state = include_bytes!("issue1275_b_state.in").to_vec();

        // After 20 additional steps, we should be in epoch 2 successfully.  If
        // we're unable to handle the bad state, one of these steps will fail.
        for i in 30..50 {
            log::info!("step {}", i);
            let Send {
                state,
                msg,
                key: alex_key,
            } = send(&alex_pq_state, &mut rng)?;
            alex_pq_state = state;
            let Recv {
                state,
                key: blake_key,
            } = recv(&blake_pq_state, &msg)?;
            blake_pq_state = state;
            assert_eq!(alex_key, blake_key);
            let Send {
                state,
                msg,
                key: blake_key,
            } = send(&blake_pq_state, &mut rng)?;
            blake_pq_state = state;
            let Recv {
                state,
                key: alex_key,
            } = recv(&alex_pq_state, &msg)?;
            alex_pq_state = state;
            assert_eq!(alex_key, blake_key);
        }
        Ok(())
    }

    #[test]
    fn disallow_downgrade_due_to_unsupported_version() -> Result<(), Error> {
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
        let Send { msg: msg_a1, .. } = send(&alex_pq_state, &mut rng)?;
        let Recv {
            state: blake_pq_state,
            ..
        } = recv(&blake_pq_state, &msg_a1)?;
        // Blake has now fully negotiated his version, and he should send keys
        // even if he now receives a higher version number.
        assert_matches!(
            recv(&blake_pq_state, &b"\xff\x01\x01".to_vec()).map(|_| ()),
            Err(Error::VersionMismatch)
        );
        Ok(())
    }

    #[test]
    fn high_version_to_v1_uses_chain_keys() -> Result<(), Error> {
        let mut rng = OsRng.unwrap_err();

        // If a side has min_version > V0, it will send chain keys.
        let alex_pq_state = initial_state(Params {
            version: Version::MAX,
            min_version: Version::V1,
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
            key: key_a1,
            state: alex_pq_state,
            ..
        } = send(&alex_pq_state, &mut rng)?;
        assert!(key_a1.is_some());
        let Send { key: key_a2, .. } = send(&alex_pq_state, &mut rng)?;
        assert!(key_a2.is_some());

        // We receive messages from fictitious SPQR version 0x99, with (epoch=3,index=2) and
        // (epoch=1,index=1) respectively.  Both should return chain keys from epoch=0 to
        // the caller to use for decoding, and both should succeed.
        let Recv { key: key_b2, .. } = recv(&blake_pq_state, &b"\x99\x03\x02".to_vec())?;
        assert_eq!(key_a2, key_b2);
        let Recv { key: key_b1, .. } = recv(&blake_pq_state, &b"\x99\x01\x01".to_vec())?;
        assert_eq!(key_a1, key_b1);
        Ok(())
    }

    #[test]
    fn empty_recv_fails_minv1() -> Result<(), Error> {
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
            min_version: Version::V1,
            direction: Direction::B2A,
            auth_key: &[41u8; 32],
            chain_params: ChainParams::default(),
        })?;
        assert_matches!(
            recv(&alex_pq_state, &b"".to_vec()).map(|_| ()),
            Err(Error::MinimumVersion)
        );
        assert_matches!(
            recv(&blake_pq_state, &b"".to_vec()).map(|_| ()),
            Err(Error::MinimumVersion)
        );
        let Send {
            state: alex_pq_state,
            msg: msg_a1,
            ..
        } = send(&alex_pq_state, &mut rng)?;
        let Recv {
            state: blake_pq_state,
            ..
        } = recv(&blake_pq_state, &msg_a1)?;
        assert_matches!(
            recv(&alex_pq_state, &b"".to_vec()).map(|_| ()),
            Err(Error::MinimumVersion)
        );
        assert_matches!(
            recv(&blake_pq_state, &b"".to_vec()).map(|_| ()),
            Err(Error::MinimumVersion)
        );
        let Send {
            state: blake_pq_state,
            msg: msg_b1,
            ..
        } = send(&blake_pq_state, &mut rng)?;
        let Recv {
            state: alex_pq_state,
            ..
        } = recv(&alex_pq_state, &msg_b1)?;
        assert_matches!(
            recv(&alex_pq_state, &b"".to_vec()).map(|_| ()),
            Err(Error::MinimumVersion)
        );
        assert_matches!(
            recv(&blake_pq_state, &b"".to_vec()).map(|_| ()),
            Err(Error::MinimumVersion)
        );

        Ok(())
    }

    #[test]
    fn newer_version_with_zero_index_gives_no_key() -> Result<(), Error> {
        let mut rng = OsRng.unwrap_err();
        let alex = initial_state(Params {
            version: Version::V1,
            min_version: Version::V0,
            direction: Direction::A2B,
            auth_key: &[41u8; 32],
            chain_params: ChainParams::default(),
        })?;
        let blake = initial_state(Params {
            version: Version::V1,
            min_version: Version::V0,
            direction: Direction::B2A,
            auth_key: &[41u8; 32],
            chain_params: ChainParams::default(),
        })?;
        let Send { msg: mut m, .. } = send(&alex, &mut rng)?;
        m[0] = 2;
        assert_eq!(recv(&blake, &m)?.key, None);
        Ok(())
    }
}
