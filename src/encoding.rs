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

#[hax_lib::attributes]
pub trait Encoder {
    #[hax_lib::requires(true)]
    fn encode_bytes(msg: &[u8]) -> Result<Self, EncodingError>
    where
        Self: Sized;
    fn next_chunk(&mut self) -> Chunk;
    fn data(&self) -> &Vec<u8>;
}

#[hax_lib::attributes]
pub trait Decoder {
    #[hax_lib::requires(true)]
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
#[hax_lib::attributes]
impl<T: Encoder> Encoder for Option<T> {
    fn encode_bytes(msg: &[u8]) -> Result<Self, EncodingError>
    where
        Self: Sized,
    {
        Ok(Some(T::encode_bytes(msg)?))
    }

    #[hax_lib::requires(self.is_some())]
    fn next_chunk(&mut self) -> Chunk {
        let mut tmp = self.take().unwrap();
        hax_lib::fstar!(
            "Hax_lib.v_assume (f_next_chunk_pre #v_T #FStar.Tactics.Typeclasses.solve tmp)"
        );
        let chunk = T::next_chunk(&mut tmp);
        *self = Some(tmp);
        chunk
    }

    #[hax_lib::requires(self.is_some())]
    fn data(&self) -> &Vec<u8> {
        let value = self.as_ref().unwrap();
        hax_lib::fstar!(
            "Hax_lib.v_assume (f_data_pre #v_T #FStar.Tactics.Typeclasses.solve value)"
        );
        T::data(value)
    }
}

#[hax_lib::attributes]
impl<T: Decoder> Decoder for Option<T> {
    fn new(len_bytes: usize) -> Result<Self, EncodingError>
    where
        Self: Sized,
    {
        Ok(Some(T::new(len_bytes)?))
    }

    #[hax_lib::requires(self.is_some())]
    fn add_chunk(&mut self, chunk: &Chunk) {
        let mut tmp = self.take().unwrap();
        hax_lib::fstar!(
            "Hax_lib.v_assume (f_add_chunk_pre #v_T #FStar.Tactics.Typeclasses.solve tmp chunk)"
        );
        T::add_chunk(&mut tmp, chunk);
        *self = Some(tmp);
    }

    #[hax_lib::requires(self.is_some())]
    fn decoded_message(&self) -> Option<Vec<u8>> {
        let value = self.as_ref().unwrap();
        hax_lib::fstar!(
            "Hax_lib.v_assume (f_decoded_message_pre #v_T #FStar.Tactics.Typeclasses.solve value)"
        );
        T::decoded_message(value)
    }

    /* fn take_decoded_message(&mut self) -> Option<Vec<u8>> {
        let mut tmp = self.take().unwrap();
        let result = T::take_decoded_message(&mut tmp);
        *self = Some(tmp);
        result
    } */

    #[hax_lib::requires(self.is_some())]
    fn is_complete(&self) -> bool {
        let value = self.as_ref().unwrap();
        hax_lib::fstar!(
            "Hax_lib.v_assume (f_is_complete_pre #v_T #FStar.Tactics.Typeclasses.solve value)"
        );
        T::is_complete(value)
    }
}
