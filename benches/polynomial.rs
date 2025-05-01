// Copyright 2025 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#![feature(test)]

extern crate test;

#[cfg(test)]
mod tests {
    use prost::Message;
    use spqr::encoding::polynomial::{PolyDecoder, PolyEncoder};
    use spqr::encoding::{Chunk, Decoder, Encoder};
    use spqr::proto::pq_ratchet as pqrpb;
    use test::{black_box, Bencher};

    #[bench]
    fn encode_bytes(b: &mut Bencher) {
        b.iter(|| {
            black_box(PolyEncoder::encode_bytes(&[3u8; 1088]).expect("encode_bytes"));
        });
    }

    #[bench]
    fn chunk_at_encode(b: &mut Bencher) {
        let chunks_needed = 1088 / 32;
        let mut encoder = PolyEncoder::encode_bytes(&[3u8; 1088]).expect("encode_bytes");
        b.iter(|| {
            black_box(encoder.chunk_at(chunks_needed + 3));
        });
    }

    #[bench]
    fn decode_one_chunk(b: &mut Bencher) {
        let chunks_needed = 1088 / 32;
        let mut chunks = Vec::<Chunk>::new();
        let mut encoder = PolyEncoder::encode_bytes(&[3u8; 1088]).expect("encode_bytes");
        for i in 1..chunks_needed + 1 {
            chunks.push(encoder.chunk_at(i));
        }
        b.iter(|| {
            let mut decoder = PolyDecoder::new(1088).expect("for_message_type");
            for chunk in &chunks {
                decoder.add_chunk(chunk);
            }
            black_box(decoder.decoded_message().unwrap());
        });
    }

    #[bench]
    fn decode_all_chunks(b: &mut Bencher) {
        let chunks_needed = 1088 / 32;
        let mut chunks = Vec::<Chunk>::new();
        let mut encoder = PolyEncoder::encode_bytes(&[3u8; 1088]).expect("encode_bytes");
        for i in chunks_needed..chunks_needed * 2 {
            chunks.push(encoder.chunk_at(i));
        }
        b.iter(|| {
            let mut decoder = PolyDecoder::new(1088).expect("for_message_type");
            for chunk in &chunks {
                decoder.add_chunk(chunk);
            }
            black_box(decoder.decoded_message().unwrap());
        });
    }

    #[bench]
    fn encoder_from_pb(b: &mut Bencher) {
        let encoder = PolyEncoder::encode_bytes(&[3u8; 1088]).expect("encode_bytes");
        let bytes = encoder.into_pb().encode_to_vec();
        b.iter(|| {
            black_box(PolyEncoder::from_pb(
                pqrpb::PolynomialEncoder::decode(bytes.as_slice()).unwrap(),
            ))
        });
    }

    #[bench]
    fn decoder_to_from_pb(b: &mut Bencher) {
        let chunks_needed = 1088 / 32;
        let mut encoder = PolyEncoder::encode_bytes(&[3u8; 1088]).expect("encode_bytes");
        let mut decoder = PolyDecoder::new(1088).expect("for_message_type");
        for i in 1..chunks_needed {
            decoder.add_chunk(&encoder.chunk_at(i));
        }
        let bytes = decoder.into_pb().encode_to_vec();
        b.iter(|| {
            black_box(PolyDecoder::from_pb(
                pqrpb::PolynomialDecoder::decode(bytes.as_slice()).unwrap(),
            ))
        });
    }
}
