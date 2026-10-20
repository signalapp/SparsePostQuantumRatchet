// Copyright 2025 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

pub mod gf;
pub mod polynomial;
pub mod round_robin;

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

#[hax_lib::attributes]
pub trait Encoder {
    #[hax_lib::requires(true)]
    fn encode_bytes(msg: &[u8]) -> Result<Self, EncodingError>
    where
        Self: Sized;
    fn next_chunk(&mut self) -> Chunk;
}

#[hax_lib::attributes]
pub trait Decoder {
    #[hax_lib::requires(true)]
    fn new(len_bytes: usize) -> Result<Self, EncodingError>
    where
        Self: Sized;
    fn add_chunk(&mut self, chunk: &Chunk);
    fn decoded_message(&self) -> Option<Vec<u8>>;
}
