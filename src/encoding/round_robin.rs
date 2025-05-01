// Copyright 2025 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
#![cfg(test)]
use super::{Chunk, Decoder, Encoder};

pub struct RoundRobinEncoder {
    data: Vec<u8>,
    next_idx: u16,
}

impl RoundRobinEncoder {
    fn num_chunks(&self) -> usize {
        self.data.len() / 32 + if self.data.len() % 32 != 0 { 1 } else { 0 }
    }

    fn chunk_at(&self, idx: u16) -> Chunk {
        let index = (idx as usize) % self.num_chunks();
        let lb = index * 32usize;
        let ub = lb + 32usize;

        // Prove the unwrap is safe
        Chunk {
            index: idx,
            data: self.data.as_slice()[lb..ub].try_into().unwrap(),
        }
    }
}

impl Encoder for RoundRobinEncoder {
    fn encode_bytes(msg: &[u8]) -> Result<Self, super::EncodingError> {
        Ok(Self {
            data: msg.to_vec(),
            next_idx: 0,
        })
    }

    fn next_chunk(&mut self) -> Chunk {
        let index = self.next_idx;
        self.next_idx += 1;
        self.chunk_at(index)
    }

    fn data(&self) -> &Vec<u8> {
        &self.data
    }
}

type ChunkData = [u8; 32];
pub struct RoundRobinDecoder {
    chunks: Vec<Option<ChunkData>>,
    is_complete: bool,
}

impl RoundRobinDecoder {
    fn can_reconstruct(&self) -> bool {
        self.chunks.iter().all(|d| d.is_some())
    }
}

impl Decoder for RoundRobinDecoder {
    fn new(len_bytes: usize) -> Result<Self, super::EncodingError> {
        let len_chunks = (len_bytes / 32) + if len_bytes % 32 != 0 { 1 } else { 0 };
        let chunks = vec![None; len_chunks];
        Ok(Self {
            chunks,
            is_complete: false,
        })
    }

    fn add_chunk(&mut self, chunk: &Chunk) {
        let idx = (chunk.index as usize) % self.chunks.len();
        if let Some(data) = self.chunks[idx] {
            assert_eq!(data, chunk.data);
        } else {
            self.chunks[idx] = Some(chunk.data);
        }
    }

    fn decoded_message(&self) -> Option<Vec<u8>> {
        if self.is_complete {
            return None;
        }
        if self.can_reconstruct() {
            let msg: Vec<u8> = self
                .chunks
                .iter()
                .map(|data| data.unwrap())
                .flat_map(|d| d.into_iter())
                .collect();
            Some(msg)
        } else {
            None
        }
    }

    /* fn take_decoded_message(&mut self) -> Option<Vec<u8>> {
        let data = self.decoded_message();
        if data.is_some() {
            self.is_complete = true;
        }
        data
    } */

    fn is_complete(&self) -> bool {
        self.is_complete
    }
}
