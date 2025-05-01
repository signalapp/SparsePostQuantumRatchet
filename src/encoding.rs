// Copyright 2025 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

pub mod gf;
pub mod polynomial;
pub mod round_robin;

use crate::proto::pq_ratchet as pqrpb;

#[derive(Debug, thiserror::Error, Copy, Clone, PartialEq)]
pub enum EncodingError {
    #[error("Polynomial error: {0}")]
    PolynomialError(polynomial::PolynomialError),
    #[error("Index decoding error")]
    ChunkIndexDecodingError,
    #[error("Data decoding error")]
    ChunkDataDecodingError,
}

impl From<polynomial::PolynomialError> for EncodingError {
    fn from(value: polynomial::PolynomialError) -> Self {
        Self::PolynomialError(value)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Chunk {
    pub index: u16,
    pub data: [u8; 32],
}

impl Chunk {
    pub fn into_pb(self) -> pqrpb::Chunk {
        pqrpb::Chunk {
            index: self.index as u32,
            data: self.data[..].to_vec(),
        }
    }

    pub fn from_pb(pb: pqrpb::Chunk) -> Result<Self, EncodingError> {
        Ok(Self {
            index: pb
                .index
                .try_into()
                .map_err(|_| EncodingError::ChunkIndexDecodingError)?,
            data: pb
                .data
                .as_slice()
                .try_into()
                .map_err(|_| EncodingError::ChunkDataDecodingError)?,
        })
    }
}

pub trait Encoder {
    fn encode_bytes(msg: &[u8]) -> Result<Self, EncodingError>
    where
        Self: Sized;
    fn next_chunk(&mut self) -> Chunk;
    fn data(&self) -> &Vec<u8>;
}

pub trait Decoder {
    fn new(len_bytes: usize) -> Result<Self, EncodingError>
    where
        Self: Sized;
    fn add_chunk(&mut self, chunk: &Chunk);
    fn decoded_message(&self) -> Option<Vec<u8>>;
    //fn take_decoded_message(&mut self) -> Option<Vec<u8>>;
    fn is_complete(&self) -> bool;
}

// XXX: For ease of formal verification with hax, we avoid using
//      functions that return mutable references, such as Option::take.
//      We therefore `take` the value out and store it back for the
//      encoder and decoder.
#[hax_lib::opaque] // Needed for abstract precondition
impl<T: Encoder> Encoder for Option<T> {
    fn encode_bytes(msg: &[u8]) -> Result<Self, EncodingError>
    where
        Self: Sized,
    {
        Ok(Some(T::encode_bytes(msg)?))
    }

    fn next_chunk(&mut self) -> Chunk {
        let mut tmp = self.take().unwrap();
        let chunk = T::next_chunk(&mut tmp);
        *self = Some(tmp);
        chunk
    }

    fn data(&self) -> &Vec<u8> {
        T::data(self.as_ref().unwrap())
    }
}

#[hax_lib::opaque] // Needed for abstract precondition
impl<T: Decoder> Decoder for Option<T> {
    fn new(len_bytes: usize) -> Result<Self, EncodingError>
    where
        Self: Sized,
    {
        Ok(Some(T::new(len_bytes)?))
    }

    fn add_chunk(&mut self, chunk: &Chunk) {
        let mut tmp = self.take().unwrap();
        T::add_chunk(&mut tmp, chunk);
        *self = Some(tmp);
    }

    fn decoded_message(&self) -> Option<Vec<u8>> {
        T::decoded_message(self.as_ref().unwrap())
    }

    /* fn take_decoded_message(&mut self) -> Option<Vec<u8>> {
        let mut tmp = self.take().unwrap();
        let result = T::take_decoded_message(&mut tmp);
        *self = Some(tmp);
        result
    } */

    fn is_complete(&self) -> bool {
        T::is_complete(self.as_ref().unwrap())
    }
}
