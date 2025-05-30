// Copyright 2025 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#![feature(test)]

extern crate test;

#[cfg(test)]
mod tests {
    use rand::TryRngCore;
    use rand_core::OsRng;
    use spqr::*;
    use test::{black_box, Bencher};

    fn state(dir: Direction) -> SerializedState {
        initial_state(Params {
            version: Version::MAX,
            min_version: Version::MAX,
            auth_key: b"1",
            direction: dir,
            chain_params: ChainParams::default(),
        })
        .expect("should be valid params")
    }

    #[bench]
    fn init_a(b: &mut Bencher) {
        b.iter(|| {
            // Inner closure, the actual test
            black_box(state(Direction::A2B));
        });
    }
    #[bench]
    fn init_b(b: &mut Bencher) {
        b.iter(|| {
            // Inner closure, the actual test
            black_box(state(Direction::B2A));
        });
    }
    #[bench]
    fn send_recv(bench: &mut Bencher) {
        let mut ctr: u64 = 0;
        let mut a = state(Direction::A2B);
        let mut b = state(Direction::B2A);
        let mut rng = OsRng.unwrap_err();
        let mut drop_ctr = 0;
        bench.iter(|| {
            ctr += 1;
            let (x, y) = if ctr % 2 == 1 {
                (&mut a, &mut b)
            } else {
                (&mut b, &mut a)
            };
            let Send {
                state,
                msg,
                key: key_a,
            } = send(x, &mut rng).unwrap();
            *x = state;
            let Recv { state, key: key_b } = recv(y, &msg).unwrap();
            assert_eq!(key_a, key_b);
            if drop_ctr == 0 {
                drop_ctr += 30;
                // We 'drop' a message by not replacing y's state.
            } else {
                drop_ctr -= 1;
                *y = state;
            }
        });
    }

    #[bench]
    fn long_chain_send(bench: &mut Bencher) {
        let mut rng = OsRng.unwrap_err();
        let mut a = state(Direction::A2B);
        let mut b = state(Direction::B2A);

        // Build a state with a lot of unused chain keys.
        for _i in 0..8 {
            for _j in 0..24000 {
                let Send { state, .. } = send(&a, &mut rng).unwrap();
                a = state;
            }
            let Send { state, msg, .. } = send(&a, &mut rng).unwrap();
            a = state;
            let Recv { state, .. } = recv(&b, &msg).unwrap();
            b = state;
        }

        println!("state size: {}", b.len());
        let Send { msg, .. } = send(&a, &mut rng).unwrap();
        bench.iter(|| {
            black_box(recv(&b, &msg).unwrap());
        });
    }
}
