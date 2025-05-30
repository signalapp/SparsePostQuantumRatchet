// Copyright 2025 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#![feature(test)]

extern crate test;

#[cfg(test)]
mod tests {
    use spqr::{chain, ChainParams, Direction, EpochSecret};
    use test::{black_box, Bencher};

    #[bench]
    fn add_epoch(b: &mut Bencher) {
        let mut c = chain::Chain::new(b"1", Direction::A2B, ChainParams::default().into_pb())
            .expect("should be valid");
        let mut e: u64 = 0;
        b.iter(|| {
            // Inner closure, the actual test
            e += 1;
            c.add_epoch(EpochSecret {
                epoch: e,
                secret: vec![1],
            });
            black_box(());
        });
    }

    #[bench]
    fn send_key(b: &mut Bencher) {
        let mut c = chain::Chain::new(b"1", Direction::A2B, ChainParams::default().into_pb())
            .expect("should be valid");
        b.iter(|| {
            // Inner closure, the actual test
            black_box(c.send_key(0).unwrap());
        });
    }

    #[bench]
    fn recv_key(b: &mut Bencher) {
        let mut c = chain::Chain::new(b"1", Direction::A2B, ChainParams::default().into_pb())
            .expect("should be valid");
        let mut k: u32 = 0;
        b.iter(|| {
            // Inner closure, the actual test
            k += 1;
            black_box(c.recv_key(0, k).unwrap());
        });
    }

    #[bench]
    fn recv_skip_key(b: &mut Bencher) {
        let mut c = chain::Chain::new(b"1", Direction::A2B, ChainParams::default().into_pb())
            .expect("should be valid");
        let mut k: u32 = 0;
        b.iter(|| {
            // Inner closure, the actual test
            k += 2;
            black_box(c.recv_key(0, k).unwrap());
            black_box(c.recv_key(0, k - 1).unwrap());
        });
    }

    #[bench]
    fn recv_with_truncate(b: &mut Bencher) {
        let mut c = chain::Chain::new(b"1", Direction::A2B, ChainParams::default().into_pb())
            .expect("should be valid");
        let mut k: u32 = 0;
        b.iter(|| {
            // Inner closure, the actual test
            k += 2;
            black_box(c.recv_key(0, k).unwrap());
            // k-1 stays around and will eventually be truncated.
        });
    }
}
