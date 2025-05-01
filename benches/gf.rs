// Copyright 2025 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#![feature(test)]

extern crate test;

#[cfg(test)]
mod tests {
    use spqr::encoding::gf;
    use test::{black_box, Bencher};

    #[bench]
    fn add(b: &mut Bencher) {
        let p1 = gf::GF16 { value: 0x1234 };
        let p2 = gf::GF16 { value: 0x4567 };
        b.iter(|| {
            // Inner closure, the actual test
            black_box(p1 + p2);
        });
    }
    #[bench]
    fn mul(b: &mut Bencher) {
        let p1 = gf::GF16 { value: 0x1234 };
        let p2 = gf::GF16 { value: 0x4567 };
        b.iter(|| {
            // Inner closure, the actual test
            black_box(p1 * p2);
        });
    }
    #[bench]
    fn sub(b: &mut Bencher) {
        let p1 = gf::GF16 { value: 0x1234 };
        let p2 = gf::GF16 { value: 0x4567 };
        b.iter(|| {
            // Inner closure, the actual test
            black_box(p1 - p2);
        });
    }
    #[bench]
    fn div(b: &mut Bencher) {
        let p1 = gf::GF16 { value: 0x1234 };
        let p2 = gf::GF16 { value: 0x4567 };
        b.iter(|| {
            // Inner closure, the actual test
            black_box(p1 / p2);
        });
    }
    #[bench]
    fn parallel_mult_2(b: &mut Bencher) {
        let p1 = gf::GF16 { value: 0x1234 };
        let mut p2 = [gf::GF16 { value: 0x4567 }; 2];
        b.iter(|| {
            // Inner closure, the actual test
            gf::parallel_mult(p1, &mut p2);
            black_box(p2);
        });
    }
    #[bench]
    fn parallel_mult_16(b: &mut Bencher) {
        let p1 = gf::GF16 { value: 0x1234 };
        let mut p2 = [gf::GF16 { value: 0x4567 }; 16];
        b.iter(|| {
            // Inner closure, the actual test
            gf::parallel_mult(p1, &mut p2);
            black_box(p2);
        });
    }
}
