// Copyright 2025 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

mod serialize;

use super::send_ct;
use super::send_ek;
use crate::encoding::Chunk;
use crate::{EpochSecret, Error};
use rand::{CryptoRng, Rng};
use std::cmp::Ordering;

use crate::Epoch;

#[cfg_attr(test, derive(Clone))]
pub enum States {
    KeysUnsampled(send_ek::KeysUnsampled),
    KeysSampled(send_ek::KeysSampled),
    HeaderSent(send_ek::HeaderSent),
    Ct1Received(send_ek::Ct1Received),
    EkSentCt1Received(send_ek::EkSentCt1Received),

    NoHeaderReceived(send_ct::NoHeaderReceived),
    HeaderReceived(send_ct::HeaderReceived),
    Ct1Sampled(send_ct::Ct1Sampled),
    EkReceivedCt1Sampled(send_ct::EkReceivedCt1Sampled),
    Ct1Acknowledged(send_ct::Ct1Acknowledged),
    Ct2Sampled(send_ct::Ct2Sampled),
}

pub enum MessagePayload {
    None,
    Hdr(Chunk),
    Ek(Chunk),
    EkCt1Ack(Chunk),
    Ct1Ack(bool),
    Ct1(Chunk),
    Ct2(Chunk),
}

pub struct Message {
    pub epoch: Epoch,
    pub payload: MessagePayload,
}

pub struct Send {
    pub msg: Message,
    pub key: Option<EpochSecret>,
    pub state: States,
}

pub struct Recv {
    pub key: Option<EpochSecret>,
    pub state: States,
}

impl States {
    pub(crate) fn init_a(auth_key: &[u8]) -> Self {
        Self::KeysUnsampled(send_ek::KeysUnsampled::new(auth_key))
    }

    pub(crate) fn init_b(auth_key: &[u8]) -> Self {
        Self::NoHeaderReceived(send_ct::NoHeaderReceived::new(auth_key))
    }

    #[cfg(test)]
    pub(crate) fn vulnerable_epochs(&self) -> Vec<Epoch> {
        match self {
            ////////////////////////////////////////////////////////////////////////////////
            // send_ek
            ////////////////////////////////////////////////////////////////////////////////
            States::KeysUnsampled(_) => vec![],
            States::KeysSampled(state) => vec![state.epoch()],
            States::HeaderSent(state) => vec![state.epoch()],
            States::Ct1Received(state) => vec![state.epoch()],
            States::EkSentCt1Received(state) => vec![state.epoch()],

            ////////////////////////////////////////////////////////////////////////////////
            // send_ct
            ////////////////////////////////////////////////////////////////////////////////
            States::NoHeaderReceived(_) => vec![],
            States::HeaderReceived(_) => vec![],
            States::Ct1Sampled(state) => vec![state.epoch()],
            States::EkReceivedCt1Sampled(state) => vec![state.epoch()],
            States::Ct1Acknowledged(state) => vec![state.epoch()],
            States::Ct2Sampled(state) => vec![state.epoch()],
        }
    }

    #[allow(dead_code)]
    #[cfg(test)]
    pub(crate) fn last_emitted_epoch(&self) -> Epoch {
        match self {
            ////////////////////////////////////////////////////////////////////////////////
            // send_ek
            ////////////////////////////////////////////////////////////////////////////////
            States::KeysUnsampled(state) => state.epoch() - 1,
            States::KeysSampled(state) => state.epoch() - 1,
            States::HeaderSent(state) => state.epoch() - 1,
            States::Ct1Received(state) => state.epoch() - 1,
            States::EkSentCt1Received(state) => state.epoch() - 1,

            ////////////////////////////////////////////////////////////////////////////////
            // send_ct
            ////////////////////////////////////////////////////////////////////////////////
            States::NoHeaderReceived(state) => state.epoch() - 1,
            States::HeaderReceived(state) => state.epoch() - 1,
            States::Ct1Sampled(state) => state.epoch() - 1,
            States::EkReceivedCt1Sampled(state) => state.epoch() - 1,
            States::Ct1Acknowledged(state) => state.epoch() - 1,
            States::Ct2Sampled(state) => state.epoch() - 1,
        }
    }

    pub(crate) fn send<R: Rng + CryptoRng>(self, rng: &mut R) -> Result<Send, Error> {
        match self {
            ////////////////////////////////////////////////////////////////////////////////
            // send_ek
            ////////////////////////////////////////////////////////////////////////////////
            Self::KeysUnsampled(state) => {
                let epoch = state.epoch();
                let (state, chunk) = state.send_hdr_chunk(rng);
                Ok(Send {
                    state: Self::KeysSampled(state),
                    msg: Message {
                        epoch,
                        payload: MessagePayload::Hdr(chunk),
                    },
                    key: None,
                })
            }
            Self::KeysSampled(state) => {
                let epoch = state.epoch();
                let (state, chunk) = state.send_hdr_chunk();
                Ok(Send {
                    state: Self::KeysSampled(state),
                    msg: Message {
                        epoch,
                        payload: MessagePayload::Hdr(chunk),
                    },
                    key: None,
                })
            }
            Self::HeaderSent(state) => {
                let epoch = state.epoch();
                let (state, chunk) = state.send_ek_chunk();
                Ok(Send {
                    state: Self::HeaderSent(state),
                    msg: Message {
                        epoch,
                        payload: MessagePayload::Ek(chunk),
                    },
                    key: None,
                })
            }
            Self::Ct1Received(state) => {
                let epoch = state.epoch();
                let (state, chunk) = state.send_ek_chunk();

                Ok(Send {
                    state: Self::Ct1Received(state),
                    msg: Message {
                        epoch,
                        payload: MessagePayload::EkCt1Ack(chunk),
                    },
                    key: None,
                })
            }
            Self::EkSentCt1Received(state) => {
                let epoch = state.epoch();

                Ok(Send {
                    state: Self::EkSentCt1Received(state),
                    msg: Message {
                        epoch,
                        payload: MessagePayload::Ct1Ack(true),
                    },
                    key: None,
                })
            }

            ////////////////////////////////////////////////////////////////////////////////
            // send_ct
            ////////////////////////////////////////////////////////////////////////////////
            Self::NoHeaderReceived(state) => {
                let epoch = state.epoch();

                Ok(Send {
                    state: Self::NoHeaderReceived(state),
                    msg: Message {
                        epoch,
                        payload: MessagePayload::None,
                    },
                    key: None,
                })
            }
            Self::HeaderReceived(state) => {
                let epoch = state.epoch();
                let (state, chunk, epoch_secret) = state.send_ct1_chunk(rng);

                Ok(Send {
                    state: Self::Ct1Sampled(state),
                    msg: Message {
                        epoch,
                        payload: MessagePayload::Ct1(chunk),
                    },
                    key: Some(epoch_secret),
                })
            }
            Self::Ct1Sampled(state) => {
                let epoch = state.epoch();
                let (state, chunk) = state.send_ct1_chunk();

                Ok(Send {
                    state: Self::Ct1Sampled(state),
                    msg: Message {
                        epoch,
                        payload: MessagePayload::Ct1(chunk),
                    },
                    key: None,
                })
            }
            Self::EkReceivedCt1Sampled(state) => {
                let epoch = state.epoch();
                let (state, chunk) = state.send_ct1_chunk();

                Ok(Send {
                    state: Self::EkReceivedCt1Sampled(state),
                    msg: Message {
                        epoch,
                        payload: MessagePayload::Ct1(chunk),
                    },
                    key: None,
                })
            }
            Self::Ct1Acknowledged(state) => {
                let epoch = state.epoch();

                Ok(Send {
                    state: Self::Ct1Acknowledged(state),
                    msg: Message {
                        epoch,
                        payload: MessagePayload::None,
                    },
                    key: None,
                })
            }
            Self::Ct2Sampled(state) => {
                let epoch = state.epoch();
                let (state, chunk) = state.send_ct2_chunk();

                Ok(Send {
                    state: Self::Ct2Sampled(state),
                    msg: Message {
                        epoch,
                        payload: MessagePayload::Ct2(chunk),
                    },
                    key: None,
                })
            }
        }
    }

    pub(crate) fn recv(self, msg: &Message) -> Result<Recv, Error> {
        hax_lib::fstar!("admit()");
        // println!("send_ct recv msg: {:?}", msg);
        let mut key = None;
        let state = match self {
            ////////////////////////////////////////////////////////////////////////////////
            // send_ek
            ////////////////////////////////////////////////////////////////////////////////
            Self::KeysUnsampled(state) => match msg.epoch.cmp(&state.epoch()) {
                Ordering::Greater => {
                    return Err(Error::EpochOutOfRange(msg.epoch));
                }
                Ordering::Less => Self::KeysUnsampled(state),
                Ordering::Equal => Self::KeysUnsampled(state),
            },
            Self::KeysSampled(state) => match msg.epoch.cmp(&state.epoch()) {
                Ordering::Greater => {
                    return Err(Error::EpochOutOfRange(msg.epoch));
                }
                Ordering::Less => Self::KeysSampled(state),
                Ordering::Equal => {
                    if let MessagePayload::Ct1(ref chunk) = msg.payload {
                        Self::HeaderSent(state.recv_ct1_chunk(msg.epoch, chunk))
                    } else {
                        Self::KeysSampled(state)
                    }
                }
            },
            Self::HeaderSent(state) => match msg.epoch.cmp(&state.epoch()) {
                Ordering::Greater => {
                    return Err(Error::EpochOutOfRange(msg.epoch));
                }
                Ordering::Less => Self::HeaderSent(state),
                Ordering::Equal => {
                    if let MessagePayload::Ct1(ref chunk) = msg.payload {
                        match state.recv_ct1_chunk(msg.epoch, chunk) {
                            send_ek::HeaderSentRecvChunk::StillReceiving(state) => {
                                Self::HeaderSent(state)
                            }
                            send_ek::HeaderSentRecvChunk::Done(state) => Self::Ct1Received(state),
                        }
                    } else {
                        Self::HeaderSent(state)
                    }
                }
            },
            Self::Ct1Received(state) => match msg.epoch.cmp(&state.epoch()) {
                Ordering::Greater => {
                    return Err(Error::EpochOutOfRange(msg.epoch));
                }
                Ordering::Less => Self::Ct1Received(state),
                Ordering::Equal => {
                    if let MessagePayload::Ct2(ref chunk) = msg.payload {
                        Self::EkSentCt1Received(state.recv_ct2_chunk(msg.epoch, chunk))
                    } else {
                        Self::Ct1Received(state)
                    }
                }
            },
            Self::EkSentCt1Received(state) => match msg.epoch.cmp(&state.epoch()) {
                Ordering::Greater => {
                    return Err(Error::EpochOutOfRange(msg.epoch));
                }
                Ordering::Less => Self::EkSentCt1Received(state),
                Ordering::Equal => {
                    if let MessagePayload::Ct2(ref chunk) = msg.payload {
                        match state.recv_ct2_chunk(msg.epoch, chunk)? {
                            send_ek::EkSentCt1ReceivedRecvChunk::StillReceiving(state) => {
                                Self::EkSentCt1Received(state)
                            }
                            send_ek::EkSentCt1ReceivedRecvChunk::Done((state, sec)) => {
                                key = Some(sec);
                                Self::NoHeaderReceived(state)
                            }
                        }
                    } else {
                        Self::EkSentCt1Received(state)
                    }
                }
            },

            ////////////////////////////////////////////////////////////////////////////////
            // send_ct
            ////////////////////////////////////////////////////////////////////////////////
            Self::NoHeaderReceived(state) => match msg.epoch.cmp(&state.epoch()) {
                Ordering::Greater => {
                    return Err(Error::EpochOutOfRange(msg.epoch));
                }
                Ordering::Less => Self::NoHeaderReceived(state),
                Ordering::Equal => {
                    if let MessagePayload::Hdr(ref chunk) = msg.payload {
                        match state.recv_hdr_chunk(msg.epoch, chunk)? {
                            send_ct::NoHeaderReceivedRecvChunk::StillReceiving(state) => {
                                Self::NoHeaderReceived(state)
                            }
                            send_ct::NoHeaderReceivedRecvChunk::Done(state) => {
                                Self::HeaderReceived(state)
                            }
                        }
                    } else {
                        Self::NoHeaderReceived(state)
                    }
                }
            },
            Self::HeaderReceived(state) => match msg.epoch.cmp(&state.epoch()) {
                Ordering::Greater => {
                    return Err(Error::EpochOutOfRange(msg.epoch));
                }
                Ordering::Less => Self::HeaderReceived(state),
                Ordering::Equal => Self::HeaderReceived(state),
            },
            Self::Ct1Sampled(state) => match msg.epoch.cmp(&state.epoch()) {
                Ordering::Greater => {
                    return Err(Error::EpochOutOfRange(msg.epoch));
                }
                Ordering::Less => Self::Ct1Sampled(state),
                Ordering::Equal => {
                    let (chunk, ack) = match msg.payload {
                        MessagePayload::Ek(ref chunk) => (Some(chunk), false),
                        MessagePayload::EkCt1Ack(ref chunk) => (Some(chunk), true),
                        _ => (None, false),
                    };
                    if let Some(chunk) = chunk {
                        match state.recv_ek_chunk(msg.epoch, chunk, ack)? {
                            send_ct::Ct1SampledRecvChunk::StillReceivingStillSending(state) => {
                                Self::Ct1Sampled(state)
                            }
                            send_ct::Ct1SampledRecvChunk::StillReceiving(state) => {
                                Self::Ct1Acknowledged(state)
                            }
                            send_ct::Ct1SampledRecvChunk::StillSending(state) => {
                                Self::EkReceivedCt1Sampled(state)
                            }
                            send_ct::Ct1SampledRecvChunk::Done(state) => Self::Ct2Sampled(state),
                        }
                    } else {
                        Self::Ct1Sampled(state)
                    }
                }
            },
            Self::EkReceivedCt1Sampled(state) => match msg.epoch.cmp(&state.epoch()) {
                Ordering::Greater => {
                    return Err(Error::EpochOutOfRange(msg.epoch));
                }
                Ordering::Less => Self::EkReceivedCt1Sampled(state),
                Ordering::Equal => {
                    if matches!(
                        msg.payload,
                        MessagePayload::Ct1Ack(true) | MessagePayload::EkCt1Ack(_)
                    ) {
                        Self::Ct2Sampled(state.recv_ct1_ack(msg.epoch))
                    } else {
                        Self::EkReceivedCt1Sampled(state)
                    }
                }
            },
            Self::Ct1Acknowledged(state) => match msg.epoch.cmp(&state.epoch()) {
                Ordering::Greater => {
                    return Err(Error::EpochOutOfRange(msg.epoch));
                }
                Ordering::Less => Self::Ct1Acknowledged(state),
                Ordering::Equal => {
                    // If we got all messages in order, we would never receive a msg.ek at
                    // this point, since we already got our first msg.ek_ct1_ack.  However,
                    // we can get messages out of order, so let's use the msg.ek chunks if we
                    // get them.
                    let chunk = match msg.payload {
                        MessagePayload::Ek(ref chunk) => Some(chunk),
                        MessagePayload::EkCt1Ack(ref chunk) => Some(chunk),
                        _ => None,
                    };
                    if let Some(chunk) = chunk {
                        match state.recv_ek_chunk(msg.epoch, chunk)? {
                            send_ct::Ct1AcknowledgedRecvChunk::StillReceiving(state) => {
                                Self::Ct1Acknowledged(state)
                            }
                            send_ct::Ct1AcknowledgedRecvChunk::Done(state) => {
                                Self::Ct2Sampled(state)
                            }
                        }
                    } else {
                        Self::Ct1Acknowledged(state)
                    }
                }
            },
            Self::Ct2Sampled(state) => match msg.epoch.cmp(&state.epoch()) {
                Ordering::Greater => {
                    if msg.epoch == state.epoch() + 1 {
                        Self::KeysUnsampled(state.recv_next_epoch(msg.epoch))
                    } else {
                        return Err(Error::EpochOutOfRange(msg.epoch));
                    }
                }
                Ordering::Less => Self::Ct2Sampled(state),
                Ordering::Equal => Self::Ct2Sampled(state),
            },
        };
        Ok(Recv { state, key })
    }
}
