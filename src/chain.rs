// Copyright 2025 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

use super::{Direction, Epoch, EpochSecret, Error};
use crate::kdf;
use crate::proto::pq_ratchet as pqrpb;
use std::cmp::Ordering;
use std::collections::VecDeque;

struct KeyHistory {
    // Keys are stored as [u8; 4][u8; 32], where the first is the index as a BE32
    // and the second is the key.
    // data.len() <= KEY_SIZE*TRIM_SIZE
    data: Vec<u8>,
}

/// ChainEpochDirection keeps track of keys related to either half of send/recv.
struct ChainEpochDirection {
    ctr: u32,
    // next.len() == 32
    next: Vec<u8>,
    prev: KeyHistory,
}

/// ChainEpoch keeps state on a single epoch's keys.
struct ChainEpoch {
    send: ChainEpochDirection,
    recv: ChainEpochDirection,
}

/// Chain keeps track of keys for all epochs.
#[hax_lib::fstar::verification_status(lax)]
pub struct Chain {
    dir: Direction,
    current_epoch: Epoch,
    // links.len() <= EPOCHS_TO_KEEP
    links: VecDeque<ChainEpoch>, // stores [link[current_epoch-N] .. link[current_epoch]]
    // next_root.len() == 32
    next_root: Vec<u8>,
}

/// Disallow requesting a key that is more than MAX_JUMP ahead of `ctr`.
pub const MAX_JUMP: usize = 25_000; // from libsignal/rust/protocol/src/consts.rs
/// Keep around keys back to at least `ctr - MAX_OOO_KEYS`, in case an out-of-order
/// message comes in.  Messages older than this that arrive out-of-order
/// will not be able to be decrypted and will return Error::KeyTrimmed.
pub(crate) const MAX_OOO_KEYS: usize = 2000;
/// When the size of our key history exceeds this amount, we run a
/// garbage collection on it.
pub(crate) const TRIM_SIZE: usize = MAX_OOO_KEYS * 11 / 10;
/// We keep around this many epochs (including the current one) for out-of-order
/// messages.  Currently, since there's O(10s) of messages required to exit a
/// single epoch and our MAX_OOO_KEYS is close to that number as well, we only
/// keep one additional epoch around.
const EPOCHS_TO_KEEP: usize = 2;

#[hax_lib::attributes]
impl KeyHistory {
    /// Size in bytes of a single key stored within a KeyHistory.
    const KEY_SIZE: usize = 4 + 32;

    fn new() -> Self {
        Self {
            data: Vec::with_capacity(Self::KEY_SIZE * 2),
        }
    }

    #[hax_lib::requires(self.data.len() <= KeyHistory::KEY_SIZE * TRIM_SIZE)]
    fn add(&mut self, k: (u32, [u8; 32])) {
        self.data.extend_from_slice(&k.0.to_be_bytes()[..]);
        self.data.extend_from_slice(&k.1[..]);
    }

    #[hax_lib::opaque] // ordering of slices needed
    fn gc(&mut self, current_key: u32) {
        if self.data.len() >= TRIM_SIZE * Self::KEY_SIZE {
            // We assume that k.0 is the highest key index we've ever seen, and base
            // our trimming on that.
            assert!(current_key >= MAX_OOO_KEYS as u32);
            let trim_horizon = &(current_key - MAX_OOO_KEYS as u32).to_be_bytes()[..];

            // This does a single O(n) pass over our list, dropping all keys less than
            // our computed trim horizon.
            let mut i: usize = 0;
            while i < self.data.len() {
                if matches!(
                    trim_horizon.cmp(&self.data[i..i + 4]),
                    std::cmp::Ordering::Greater
                ) {
                    self.remove(i);
                    // Don't advance i here; we could have replaced the value there-in
                    // with another old key.
                } else {
                    i += Self::KEY_SIZE;
                }
            }
        }
    }

    fn clear(&mut self) {
        self.data.clear();
    }

    #[hax_lib::requires(my_array_index <= self.data.len() && self.data.len() <= KeyHistory::KEY_SIZE * TRIM_SIZE)]
    fn remove(&mut self, mut my_array_index: usize) {
        if my_array_index + Self::KEY_SIZE < self.data.len() {
            let new_end = self.data.len() - Self::KEY_SIZE;
            self.data.copy_within(new_end.., my_array_index);
            my_array_index = new_end;
        }
        self.data.truncate(my_array_index);
    }

    #[hax_lib::opaque] // needs a model of step_by loop with return
    fn get(&mut self, at: u32, current_ctr: u32) -> Result<Vec<u8>, Error> {
        assert_eq!(self.data.len() % Self::KEY_SIZE, 0);
        let want = at.to_be_bytes();
        for i in (0..self.data.len()).step_by(Self::KEY_SIZE) {
            if self.data[i..i + 4] == want {
                let out = self.data[i + 4..i + Self::KEY_SIZE].to_vec();
                self.remove(i);
                return Ok(out);
            }
        }
        if at + (MAX_OOO_KEYS as u32) < current_ctr {
            // We've already discarded this because it's too old.
            Err(Error::KeyTrimmed(at))
        } else {
            // This is a key we should have and we don't, so it must have already
            // been requested.
            Err(Error::KeyAlreadyRequested(at))
        }
    }
}

impl ChainEpochDirection {
    fn new(k: &[u8]) -> Self {
        Self {
            ctr: 0,
            prev: KeyHistory::new(),
            next: k.to_vec(),
        }
    }

    fn next_key(&mut self) -> (u32, Vec<u8>) {
        let (idx, key) = Self::next_key_internal(&mut self.next, &mut self.ctr);
        (idx, key.to_vec())
    }

    fn next_key_internal(next: &mut [u8], ctr: &mut u32) -> (u32, [u8; 32]) {
        hax_lib::fstar!("admit()");
        *ctr += 1;
        let mut gen = [0u8; 64];
        kdf::hkdf_to_slice(
            &[0u8; 32], // 32 is the hash output length
            &*next,
            &[
                ctr.to_be_bytes().as_slice(),
                b"Signal PQ Ratchet V1 Chain Next",
            ]
            .concat(),
            &mut gen,
        );
        next.copy_from_slice(&gen[..32]);
        (*ctr, gen[32..].try_into().expect("correct size"))
    }

    fn key(&mut self, at: u32) -> Result<Vec<u8>, Error> {
        hax_lib::fstar!("admit()");
        match at.cmp(&self.ctr) {
            Ordering::Greater => {
                if at - self.ctr > MAX_JUMP as u32 {
                    return Err(Error::KeyJump(self.ctr, at));
                }
            }
            Ordering::Less => {
                return self.prev.get(at, self.ctr);
            }
            Ordering::Equal => {
                // We've already returned this key once, we won't do it again.
                return Err(Error::KeyAlreadyRequested(at));
            }
        }
        if at > self.ctr + (MAX_OOO_KEYS as u32) {
            // We're about to make all currently-held keys obsolete - just remove
            // them all.
            self.prev.clear();
        }
        while at > self.ctr + 1 {
            let k = Self::next_key_internal(&mut self.next, &mut self.ctr);
            // Only add keys into our history if we're not going to immediately GC them.
            if self.ctr + (MAX_OOO_KEYS as u32) >= at {
                self.prev.add(k);
            }
        }
        // After we've potentially added some new keys, see if there's any we
        // want to throw away.
        self.prev.gc(self.ctr);

        Ok(Self::next_key_internal(&mut self.next, &mut self.ctr)
            .1
            .to_vec())
    }

    fn into_pb(self) -> pqrpb::chain::epoch::Direction {
        pqrpb::chain::epoch::Direction {
            ctr: self.ctr,
            next: self.next,
            prev: self.prev.data,
        }
    }

    fn from_pb(pb: pqrpb::chain::epoch::Direction) -> Result<Self, Error> {
        Ok(Self {
            ctr: pb.ctr,
            next: pb.next,
            prev: KeyHistory { data: pb.prev },
        })
    }
}

#[hax_lib::attributes]
impl Chain {
    #[hax_lib::requires(gen.len() == 96)]
    fn ced_for_direction(gen: &[u8], dir: &Direction) -> ChainEpochDirection {
        ChainEpochDirection::new(match dir {
            Direction::A2B => &gen[32..64],
            Direction::B2A => &gen[64..96],
        })
    }

    pub fn new(initial_key: &[u8], dir: Direction) -> Self {
        hax_lib::fstar!("admit ()");
        let mut gen = [0u8; 96];
        kdf::hkdf_to_slice(
            &[0u8; 32],
            initial_key,
            b"Signal PQ Ratchet V1 Chain  Start",
            &mut gen,
        );
        Self {
            dir,
            current_epoch: 0,
            links: VecDeque::from([ChainEpoch {
                send: Self::ced_for_direction(&gen, &dir),
                recv: Self::ced_for_direction(&gen, &dir.switch()),
            }]),
            next_root: gen[0..32].to_vec(),
        }
    }

    pub fn add_epoch(&mut self, epoch_secret: EpochSecret) {
        hax_lib::fstar!("admit ()");
        assert!(epoch_secret.epoch == self.current_epoch + 1);
        let mut gen = [0u8; 96];
        kdf::hkdf_to_slice(
            &self.next_root,
            &epoch_secret.secret,
            b"Signal PQ Ratchet V1 Chain Add Epoch",
            &mut gen,
        );
        self.current_epoch = epoch_secret.epoch;
        self.next_root = gen[0..32].to_vec();
        self.links.push_back(ChainEpoch {
            send: Self::ced_for_direction(&gen, &self.dir),
            recv: Self::ced_for_direction(&gen, &self.dir.switch()),
        });
        if self.links.len() > EPOCHS_TO_KEEP {
            self.links.pop_front();
        }
    }

    fn epoch_idx(&mut self, epoch: Epoch) -> Result<usize, Error> {
        if epoch > self.current_epoch {
            return Err(Error::EpochOutOfRange(epoch));
        }
        let back = (self.current_epoch - epoch) as usize;
        let links = self.links.len();
        if back >= links {
            return Err(Error::EpochOutOfRange(epoch));
        }
        Ok(links - 1 - back)
    }

    pub fn send_key(&mut self, epoch: Epoch) -> Result<(u32, Vec<u8>), Error> {
        hax_lib::fstar!("admit ()");
        let epoch_index = self.epoch_idx(epoch)?;
        Ok(self.links[epoch_index].send.next_key())
    }

    pub fn recv_key(&mut self, epoch: Epoch, index: u32) -> Result<Vec<u8>, Error> {
        hax_lib::fstar!("admit ()");
        let epoch_index = self.epoch_idx(epoch)?;
        self.links[epoch_index].recv.key(index)
    }

    #[hax_lib::opaque] // into_iter for vec_deque
    pub fn into_pb(self) -> pqrpb::Chain {
        pqrpb::Chain {
            a2b: matches!(self.dir, Direction::A2B),
            current_epoch: self.current_epoch,
            links: self
                .links
                .into_iter()
                .map(|link| pqrpb::chain::Epoch {
                    send: Some(link.send.into_pb()),
                    recv: Some(link.recv.into_pb()),
                })
                .collect::<Vec<_>>(),
            next_root: self.next_root,
        }
    }

    #[hax_lib::opaque] // into_iter and map
    pub fn from_pb(pb: pqrpb::Chain) -> Result<Self, Error> {
        Ok(Self {
            dir: if pb.a2b {
                Direction::A2B
            } else {
                Direction::B2A
            },
            current_epoch: pb.current_epoch,
            next_root: pb.next_root,
            links: pb
                .links
                .into_iter()
                .map(|link| {
                    Ok::<ChainEpoch, Error>(ChainEpoch {
                        send: ChainEpochDirection::from_pb(link.send.ok_or(Error::StateDecode)?)?,
                        recv: ChainEpochDirection::from_pb(link.recv.ok_or(Error::StateDecode)?)?,
                    })
                })
                .collect::<Result<VecDeque<_>, _>>()?,
        })
    }
}

#[cfg(test)]
mod test {
    use super::{Chain, MAX_JUMP, MAX_OOO_KEYS, TRIM_SIZE};
    use crate::{Direction, EpochSecret, Error};
    use rand::seq::SliceRandom;
    use rand::TryRngCore;

    #[test]
    fn directions_match() {
        let mut a2b = Chain::new(b"1", Direction::A2B);
        let mut b2a = Chain::new(b"1", Direction::B2A);
        let sk1 = a2b.send_key(0).unwrap();
        assert_eq!(sk1.0, 1);
        assert_eq!(sk1.1, b2a.recv_key(0, 1).unwrap());
        a2b.add_epoch(EpochSecret {
            epoch: 1,
            secret: vec![2],
        });
        b2a.add_epoch(EpochSecret {
            epoch: 1,
            secret: vec![2],
        });
        let sk2 = a2b.send_key(1).unwrap();
        assert_eq!(sk2.0, 1);
        assert_eq!(sk2.1, b2a.recv_key(1, 1).unwrap());
        for _i in 2..10 {
            a2b.send_key(1).unwrap();
        }
        let sk3 = a2b.send_key(1).unwrap();
        assert_eq!(sk3.0, 10);
        assert_eq!(sk3.1, b2a.recv_key(1, 10).unwrap());
    }

    #[test]
    fn previously_returned_key() {
        let mut a2b = Chain::new(b"1", Direction::A2B);
        a2b.recv_key(0, 2).expect("should get key first time");
        assert!(matches!(
            a2b.recv_key(0, 2),
            Err(Error::KeyAlreadyRequested(2))
        ));
    }

    #[test]
    fn very_old_keys_are_trimmed() {
        let mut a2b = Chain::new(b"1", Direction::A2B);
        let mut i = 1u32;
        while (i as usize) < TRIM_SIZE + 1 {
            i += MAX_JUMP as u32 - 1;
            a2b.recv_key(0, i).expect("should allow this jump");
        }
        assert!(matches!(a2b.recv_key(0, 1), Err(Error::KeyTrimmed(1))));
    }

    #[test]
    fn out_of_order_keys() {
        let mut a2b = Chain::new(b"1", Direction::A2B);
        let mut b2a = Chain::new(b"1", Direction::B2A);
        let mut keys = Vec::with_capacity(MAX_OOO_KEYS);
        for _i in 0..MAX_OOO_KEYS {
            keys.push(a2b.send_key(0).unwrap());
        }
        let mut rng = rand::rngs::OsRng.unwrap_err();
        keys.shuffle(&mut rng);
        for (idx, key) in keys {
            assert_eq!(b2a.recv_key(0, idx).unwrap(), key);
        }
    }
}
