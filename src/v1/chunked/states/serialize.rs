// Copyright 2025 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use crate::proto::pq_ratchet as pqrpb;
use crate::{Error, SerializedMessage, Version};
use num_enum::IntoPrimitive;

impl States {
    pub fn into_pb(self) -> pqrpb::V1State {
        pqrpb::V1State {
            inner_state: Some(match self {
                // send_ek
                Self::KeysUnsampled(state) => {
                    pqrpb::v1_state::InnerState::KeysUnsampled(state.into_pb())
                }
                Self::KeysSampled(state) => {
                    pqrpb::v1_state::InnerState::KeysSampled(state.into_pb())
                }
                Self::HeaderSent(state) => pqrpb::v1_state::InnerState::HeaderSent(state.into_pb()),
                Self::Ct1Received(state) => {
                    pqrpb::v1_state::InnerState::Ct1Received(state.into_pb())
                }
                Self::EkSentCt1Received(state) => {
                    pqrpb::v1_state::InnerState::EkSentCt1Received(state.into_pb())
                }

                // send_ct
                Self::NoHeaderReceived(state) => {
                    pqrpb::v1_state::InnerState::NoHeaderReceived(state.into_pb())
                }
                Self::HeaderReceived(state) => {
                    pqrpb::v1_state::InnerState::HeaderReceived(state.into_pb())
                }
                Self::Ct1Sampled(state) => pqrpb::v1_state::InnerState::Ct1Sampled(state.into_pb()),
                Self::EkReceivedCt1Sampled(state) => {
                    pqrpb::v1_state::InnerState::EkReceivedCt1Sampled(state.into_pb())
                }
                Self::Ct1Acknowledged(state) => {
                    pqrpb::v1_state::InnerState::Ct1Acknowledged(state.into_pb())
                }
                Self::Ct2Sampled(state) => pqrpb::v1_state::InnerState::Ct2Sampled(state.into_pb()),
            }),
        }
    }

    pub fn from_pb(pb: pqrpb::V1State) -> Result<Self, Error> {
        Ok(match pb.inner_state {
            // send_ek
            Some(pqrpb::v1_state::InnerState::KeysUnsampled(pb)) => {
                Self::KeysUnsampled(send_ek::KeysUnsampled::from_pb(pb)?)
            }
            Some(pqrpb::v1_state::InnerState::KeysSampled(pb)) => {
                Self::KeysSampled(send_ek::KeysSampled::from_pb(pb)?)
            }
            Some(pqrpb::v1_state::InnerState::HeaderSent(pb)) => {
                Self::HeaderSent(send_ek::HeaderSent::from_pb(pb)?)
            }
            Some(pqrpb::v1_state::InnerState::Ct1Received(pb)) => {
                Self::Ct1Received(send_ek::Ct1Received::from_pb(pb)?)
            }
            Some(pqrpb::v1_state::InnerState::EkSentCt1Received(pb)) => {
                Self::EkSentCt1Received(send_ek::EkSentCt1Received::from_pb(pb)?)
            }

            // send_ct
            Some(pqrpb::v1_state::InnerState::NoHeaderReceived(pb)) => {
                Self::NoHeaderReceived(send_ct::NoHeaderReceived::from_pb(pb)?)
            }
            Some(pqrpb::v1_state::InnerState::HeaderReceived(pb)) => {
                Self::HeaderReceived(send_ct::HeaderReceived::from_pb(pb)?)
            }
            Some(pqrpb::v1_state::InnerState::Ct1Sampled(pb)) => {
                Self::Ct1Sampled(send_ct::Ct1Sampled::from_pb(pb)?)
            }
            Some(pqrpb::v1_state::InnerState::EkReceivedCt1Sampled(pb)) => {
                Self::EkReceivedCt1Sampled(send_ct::EkReceivedCt1Sampled::from_pb(pb)?)
            }
            Some(pqrpb::v1_state::InnerState::Ct1Acknowledged(pb)) => {
                Self::Ct1Acknowledged(send_ct::Ct1Acknowledged::from_pb(pb)?)
            }
            Some(pqrpb::v1_state::InnerState::Ct2Sampled(pb)) => {
                Self::Ct2Sampled(send_ct::Ct2Sampled::from_pb(pb)?)
            }

            _ => {
                return Err(Error::StateDecode);
            }
        })
    }
}

#[derive(IntoPrimitive)]
#[repr(u8)]
enum MessageType {
    None = 0,
    Hdr = 1,
    Ek = 2,
    EkCt1Ack = 3,
    Ct1Ack = 4,
    Ct1 = 5,
    Ct2 = 6,
}

#[hax_lib::opaque]
impl TryFrom<u8> for MessageType {
    type Error = String;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(MessageType::None),
            1 => Ok(MessageType::Hdr),
            2 => Ok(MessageType::Ek),
            3 => Ok(MessageType::EkCt1Ack),
            4 => Ok(MessageType::Ct1Ack),
            5 => Ok(MessageType::Ct1),
            6 => Ok(MessageType::Ct2),
            _ => Err("Expected a number between 0 and 6".to_owned()),
        }
    }
}

impl MessageType {
    fn from_payload(mp: &MessagePayload) -> Self {
        match mp {
            MessagePayload::None => Self::None,
            MessagePayload::Hdr(_) => Self::Hdr,
            MessagePayload::Ek(_) => Self::Ek,
            MessagePayload::EkCt1Ack(_) => Self::EkCt1Ack,
            MessagePayload::Ct1Ack(_) => Self::Ct1Ack,
            MessagePayload::Ct1(_) => Self::Ct1,
            MessagePayload::Ct2(_) => Self::Ct2,
        }
    }
}

fn encode_varint(mut a: u64, into: &mut SerializedMessage) {
    for _i in 0..10 {
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

#[hax_lib::opaque] // return in while
fn decode_varint(from: &SerializedMessage, at: &mut usize) -> Result<u64, Error> {
    let mut out = 0u64;
    let mut shift = 0;
    while *at < from.len() {
        let byte = from[*at];
        out |= ((byte as u64) & 0x7f) << shift;
        *at += 1;
        if byte & 0x80 == 0 {
            return Ok(out);
        }
        shift += 7;
    }
    Err(Error::MsgDecode)
}

#[hax_lib::fstar::verification_status(lax)]
fn encode_chunk(c: &Chunk, into: &mut SerializedMessage) {
    encode_varint(c.index as u64, into);
    into.extend_from_slice(&c.data[..]);
}

#[hax_lib::fstar::verification_status(lax)]
fn decode_chunk(from: &SerializedMessage, at: &mut usize) -> Result<Chunk, Error> {
    let index = decode_varint(from, at)?;
    let start = *at;
    *at += 32;
    if *at > from.len() || index > 65535 {
        return Err(Error::MsgDecode);
    }
    Ok(Chunk {
        index: index as u16,
        data: from[start..*at].try_into().expect("correct size"),
    })
}

impl Message {
    /// Serialize a message.
    ///
    /// Messages are serialized as:
    ///
    ///   [version]      - 1 byte
    ///   [epoch]        - varint, 1-10 bytes
    ///   [index]        - varint, 1-5 bytes
    ///   [message_type] - 1 byte
    ///
    /// Many of the message types also have a data chunk concatenated to them, of
    /// the form:
    ///
    ///   [index]        - varint, 1-3 bytes
    ///   [chunk_data]   - 32 bytes
    pub fn serialize(&self, index: u32) -> SerializedMessage {
        hax_lib::fstar!("admit()");
        let mut into = Vec::with_capacity(40);
        into.push(Version::V1.into());
        encode_varint(self.epoch, &mut into);
        encode_varint(index as u64, &mut into);
        into.push(MessageType::from_payload(&self.payload).into());
        encode_chunk(
            match &self.payload {
                MessagePayload::Hdr(ref chunk) => chunk,
                MessagePayload::Ek(ref chunk) => chunk,
                MessagePayload::EkCt1Ack(ref chunk) => chunk,
                MessagePayload::Ct1(ref chunk) => chunk,
                MessagePayload::Ct2(ref chunk) => chunk,
                _ => {
                    return into;
                }
            },
            &mut into,
        );
        into
    }

    pub fn deserialize(from: &SerializedMessage) -> Result<(Self, u32, usize), Error> {
        hax_lib::fstar!("admit()");
        if from.is_empty() || from[0] != Version::V1.into() {
            return Err(Error::MsgDecode);
        }
        let mut at = 1usize;
        let epoch = decode_varint(from, &mut at)? as Epoch;
        let index: u32 = decode_varint(from, &mut at)?
            .try_into()
            .map_err(|_| Error::MsgDecode)?;
        let msg_type = MessageType::try_from(from[at]).map_err(|_| Error::MsgDecode)?;
        at += 1;
        let payload = match msg_type {
            MessageType::None => MessagePayload::None,
            MessageType::Ct1Ack => MessagePayload::Ct1Ack(true),
            MessageType::Hdr => MessagePayload::Hdr(decode_chunk(from, &mut at)?),
            MessageType::Ek => MessagePayload::Ek(decode_chunk(from, &mut at)?),
            MessageType::EkCt1Ack => MessagePayload::EkCt1Ack(decode_chunk(from, &mut at)?),
            MessageType::Ct1 => MessagePayload::Ct1(decode_chunk(from, &mut at)?),
            MessageType::Ct2 => MessagePayload::Ct2(decode_chunk(from, &mut at)?),
        };
        // We allow for there to be additional trailing data in the message, so it's
        // possible that `at < from.len()`.  This allows for us to potentially
        // upgrade sessions in future versions of the protocol.
        Ok((Self { epoch, payload }, index, at))
    }
}

#[cfg(test)]
mod test {
    use super::{decode_varint, encode_varint};
    use rand::RngCore;
    use rand::TryRngCore;
    use rand_core::OsRng;

    #[test]
    fn encoding_varint() {
        let mut v = vec![];
        encode_varint(0x012C, &mut v);
        assert_eq!(&v, &[0xAC, 0x02][..]);
    }

    #[test]
    fn decoding_varint() {
        let v = vec![0xFF, 0xAC, 0x02, 0xFF];
        let mut at = 1usize;
        assert_eq!(0x012C, decode_varint(&v, &mut at).unwrap());
        assert_eq!(at, 3);
    }

    #[test]
    fn roundtrip_varint() {
        let mut rng = OsRng.unwrap_err();
        for _i in 0..10000 {
            let u = rng.next_u64();
            let mut v = vec![];
            encode_varint(u, &mut v);
            let mut at = 0usize;
            assert_eq!(u, decode_varint(&v, &mut at).unwrap());
            assert_eq!(at, v.len());
        }
    }
}
