// Copyright 2025 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

use super::{Direction, Epoch, EpochSecret, Error};
use crate::kdf;
use crate::proto::pq_ratchet as pqrpb;
use crate::proto::pq_ratchet::ChainParams as ChainParamsPB;
use std::cmp::Ordering;
use std::collections::VecDeque;

/// Parameters for controlling the behavior of PQR key chains.
/// It's recommended to use the Default API for overriding values,
/// as future values may be added to this struct, and Default allows
/// them to be added in a backwards-compatible fashion.
/// IE:  let params = ChainParams{max_jump: 10, ..Default::default()};
#[derive(Clone, Copy)]
pub struct ChainParams {
    /// Disallow requesting a key that is more than MAX_JUMP ahead of `ctr`.
    /// If zero, defaults to the current library-compiled default value.
    pub max_jump: u32,
    /// Keep around keys back to at least `ctr - MAX_OOO_KEYS`, in case an out-of-order
    /// message comes in.  Messages older than this that arrive out-of-order
    /// will not be able to be decrypted and will return Error::KeyTrimmed.
    /// If zero, defaults to the current library-compiled default value.
    /// Values above 2^24 are rejected with Error::InvalidParams.
    pub max_ooo_keys: u32,
}

impl Default for ChainParams {
    fn default() -> Self {
        DEFAULT_CHAIN_PARAMS
    }
}

const DEFAULT_CHAIN_PARAMS: ChainParams = ChainParams {
    max_jump: 25_000,
    max_ooo_keys: 2_000,
};

impl ChainParams {
    pub(crate) fn into_pb(self) -> ChainParamsPB {
        ChainParamsPB {
            max_jump: if self.max_jump == DEFAULT_CHAIN_PARAMS.max_jump {
                0
            } else {
                self.max_jump
            },
            max_ooo_keys: if self.max_ooo_keys == DEFAULT_CHAIN_PARAMS.max_ooo_keys {
                0
            } else {
                self.max_ooo_keys
            },
        }
    }

    /// Public wrapper for test utilities and benchmarks.
    /// For internal use, call `into_pb` directly.
    #[cfg(feature = "test-utils")]
    pub fn into_pb_test(self) -> ChainParamsPB {
        self.into_pb()
    }
}

impl ChainParamsPB {
    // The Default for protobufs is to have everything be zeros.  Therefore,
    // we use some getter functions locally to apply sane defaults to values that
    // are not explicitly set.

    fn max_jump_or_default(&self) -> u32 {
        if self.max_jump > 0 {
            self.max_jump
        } else {
            DEFAULT_CHAIN_PARAMS.max_jump
        }
    }
    fn max_ooo_keys_or_default(&self) -> u32 {
        if self.max_ooo_keys > 0 {
            self.max_ooo_keys
        } else {
            DEFAULT_CHAIN_PARAMS.max_ooo_keys
        }
    }
    /// When the size of our key history exceeds this amount, we run a
    /// garbage collection on it.
    fn trim_size(&self) -> usize {
        let max_ooo = self.max_ooo_keys_or_default();
        let max_ooo = if max_ooo > MAX_OOO_KEYS_LIMIT {
            MAX_OOO_KEYS_LIMIT
        } else {
            max_ooo
        } as usize;
        max_ooo * 11 / 10 + 1
    }

    /// Reject chain parameters that would make `trim_size()` (or `KEY_SIZE *
    /// trim_size()`) overflow a 32-bit `usize`. `max_ooo_keys` is the only field
    /// that feeds that arithmetic; `max_jump` is intentionally unbounded here, since
    /// self-connections legitimately set it to `u32::MAX`. The bound is far above any
    /// real value (production uses 2000).
    pub(crate) fn validate(&self) -> Result<(), Error> {
        if self.max_ooo_keys_or_default() > MAX_OOO_KEYS_LIMIT {
            return Err(Error::InvalidParams("max_ooo_keys too large"));
        }
        Ok(())
    }
}

// 2^24 keys: `MAX_OOO_KEYS_LIMIT * 11 / 10 * KEY_SIZE` stays well under 2^32.
const MAX_OOO_KEYS_LIMIT: u32 = 1 << 24;

struct KeyHistory {
    // Keys are stored as [u8; 4][u8; 32], where the first is the index as a BE32
    // and the second is the key.
    // data.len() % KEY_SIZE == 0. `gc` trims down from KEY_SIZE*TRIM_SIZE rather
    // than holding the length below it.
    data: Vec<u8>,
}

/// ChainEpochDirection keeps track of keys related to either half of send/recv.
struct ChainEpochDirection {
    ctr: u32,
    // next.len() == 32, or next is empty (`clear_next`).
    next: Vec<u8>,
    prev: KeyHistory,
}

/// ChainEpoch keeps state on a single epoch's keys.
struct ChainEpoch {
    send: ChainEpochDirection,
    recv: ChainEpochDirection,
}

/// Chain keeps track of keys for all epochs.
pub struct Chain {
    dir: Direction,
    current_epoch: Epoch,
    send_epoch: Epoch,
    // [link[current_epoch-N] .. link[current_epoch]] as built by `new`/`add_epoch`;
    // `from_pb` reads links and current_epoch as independent fields and does not
    // relate them.
    links: VecDeque<ChainEpoch>,
    // 32 bytes as built by `new`/`add_epoch`; `from_pb` takes it unvalidated. It is
    // only an HKDF salt, which accepts any length.
    next_root: Vec<u8>,
    params: pqrpb::ChainParams,
}

/// We keep around this many epochs to keep prior to the current send epoch.
/// We'll always keep the send epoch and any subsequent epochs.
const EPOCHS_TO_KEEP_PRIOR_TO_SEND_EPOCH: usize = 1;

#[hax_lib::attributes]
impl KeyHistory {
    /// Size in bytes of a single key stored within a KeyHistory.
    const KEY_SIZE: usize = 4 + 32;

    fn new() -> Self {
        Self {
            data: Vec::with_capacity(Self::KEY_SIZE * 2),
        }
    }

    #[hax_lib::requires(self.data.len() <= usize::MAX - KeyHistory::KEY_SIZE)]
    fn add(&mut self, k: (u32, [u8; 32]), _params: &pqrpb::ChainParams) {
        self.data.extend_from_slice(&k.0.to_be_bytes()[..]);
        self.data.extend_from_slice(&k.1[..]);
    }

    #[hax_lib::opaque] // ordering of slices needed
    fn gc(&mut self, current_key: u32, params: &pqrpb::ChainParams) {
        if self.data.len() >= params.trim_size() * Self::KEY_SIZE {
            // We assume that k.0 is the highest key index we've ever seen, and base
            // our trimming on that.
            let trim_horizon = &current_key
                .saturating_sub(params.max_ooo_keys_or_default())
                .to_be_bytes()[..];

            // This does a single O(n) pass over our list, dropping all keys less than
            // our computed trim horizon.
            let mut i: usize = 0;
            while i < self.data.len() {
                if matches!(
                    trim_horizon.cmp(&self.data[i..i + 4]),
                    std::cmp::Ordering::Greater
                ) {
                    self.remove(i, params);
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

    #[hax_lib::requires(my_array_index <= self.data.len() && self.data.len() <= usize::MAX - KeyHistory::KEY_SIZE)]
    fn remove(&mut self, mut my_array_index: usize, _params: &pqrpb::ChainParams) {
        if my_array_index + Self::KEY_SIZE < self.data.len() {
            let new_end = self.data.len() - Self::KEY_SIZE;
            self.data.copy_within(new_end.., my_array_index);
            my_array_index = new_end;
        }
        self.data.truncate(my_array_index);
    }

    #[hax_lib::opaque] // needs a model of step_by loop with return
    fn get(
        &mut self,
        at: u32,
        current_ctr: u32,
        params: &pqrpb::ChainParams,
    ) -> Result<Vec<u8>, Error> {
        assert_eq!(self.data.len() % Self::KEY_SIZE, 0);
        if at.saturating_add(params.max_ooo_keys_or_default()) < current_ctr {
            // We've already discarded this because it's too old.
            return Err(Error::KeyTrimmed(at));
        }
        let want = at.to_be_bytes();
        for i in (0..self.data.len()).step_by(Self::KEY_SIZE) {
            if self.data[i..i + 4] == want {
                let out = self.data.as_slice()[i + 4..i + Self::KEY_SIZE].to_vec();
                self.remove(i, params);
                return Ok(out);
            }
        }
        // This is a key we should have and we don't, so it must have already
        // been requested.
        Err(Error::KeyAlreadyRequested(at))
    }
}

#[hax_lib::attributes]
impl ChainEpochDirection {
    #[hax_lib::requires(k.len() == 32)]
    fn new(k: &[u8]) -> Self {
        Self {
            ctr: 0,
            prev: KeyHistory::new(),
            next: k.to_vec(),
        }
    }

    #[hax_lib::requires(self.next.len() == 32 && self.ctr < u32::MAX)]
    fn next_key(&mut self) -> (u32, Vec<u8>) {
        let (idx, key) = Self::next_key_internal(&mut self.next, &mut self.ctr);
        (idx, key.to_vec())
    }

    #[hax_lib::requires(next.len() == 32 && *ctr < u32::MAX)]
    #[hax_lib::ensures(|_| *future(ctr) == ctr + 1 && future(next).len() == next.len())]
    fn next_key_internal(next: &mut [u8], ctr: &mut u32) -> (u32, [u8; 32]) {
        assert_eq!(next.len(), 32);
        *ctr += 1;
        let mut genr8r = [0u8; 64];
        kdf::hkdf_to_slice(
            &[0u8; 32], // 32 is the hash output length
            &*next,
            [
                ctr.to_be_bytes().as_slice(),
                b"Signal PQ Ratchet V1 Chain Next",
            ]
            .concat()
            .as_slice(),
            &mut genr8r,
        );
        next.copy_from_slice(&genr8r[..32]);
        (*ctr, genr8r[32..].try_into().expect("correct size"))
    }

    fn key(&mut self, at: u32, params: &pqrpb::ChainParams) -> Result<Vec<u8>, Error> {
        match at.cmp(&self.ctr) {
            Ordering::Greater => {
                if at - self.ctr > params.max_jump_or_default() {
                    return Err(Error::KeyJump(self.ctr, at));
                }
            }
            Ordering::Less => {
                return self.prev.get(at, self.ctr, params);
            }
            Ordering::Equal => {
                // We've already returned this key once, we won't do it again.
                return Err(Error::KeyAlreadyRequested(at));
            }
        }
        // A recv direction always carries a 32-byte `next` (only send directions are
        // ever cleared, by `clear_next`). A decoded state with an empty or wrong-length
        // `next` here is malformed and cannot produce keys.
        if self.next.len() != 32 {
            return Err(Error::StateDecode);
        }
        if at > self.ctr.saturating_add(params.max_ooo_keys_or_default()) {
            // We're about to make all currently-held keys obsolete - just remove
            // them all.
            self.prev.clear();
        }
        while at > self.ctr + 1 {
            hax_lib::loop_invariant!(self.ctr < u32::MAX && self.next.len() == 32);
            hax_lib::loop_decreases!(u32::MAX - self.ctr);
            let k = Self::next_key_internal(&mut self.next, &mut self.ctr);
            // Only add keys into our history if we're not going to immediately GC them.
            if self.ctr.saturating_add(params.max_ooo_keys_or_default()) >= at
                && self.prev.data.len() <= usize::MAX - KeyHistory::KEY_SIZE
            {
                self.prev.add(k, params);
            }
        }
        // After we've potentially added some new keys, see if there's any we
        // want to throw away.
        self.prev.gc(self.ctr, params);

        Ok(Self::next_key_internal(&mut self.next, &mut self.ctr)
            .1
            .to_vec())
    }

    fn into_pb(self) -> pqrpb::chain::epoch::EpochDirection {
        pqrpb::chain::epoch::EpochDirection {
            ctr: self.ctr,
            next: self.next,
            prev: self.prev.data,
        }
    }

    fn from_pb(pb: pqrpb::chain::epoch::EpochDirection) -> Result<Self, Error> {
        if !pb.next.is_empty() && pb.next.len() != 32 {
            return Err(Error::StateDecode);
        }
        // `prev` is a flat sequence of KEY_SIZE-byte records; a length that is not a
        // multiple of KEY_SIZE is malformed (otherwise `KeyHistory::get` would panic
        // on the out-of-step slice access).
        if !pb.prev.len().is_multiple_of(KeyHistory::KEY_SIZE) {
            return Err(Error::StateDecode);
        }
        Ok(Self {
            ctr: pb.ctr,
            next: pb.next,
            prev: KeyHistory { data: pb.prev },
        })
    }

    fn clear_next(&mut self) {
        self.next.clear();
    }
}

#[hax_lib::attributes]
impl Chain {
    #[hax_lib::requires(genr8r.len() == 96)]
    fn ced_for_direction(genr8r: &[u8], dir: &Direction) -> ChainEpochDirection {
        ChainEpochDirection::new(match dir {
            Direction::A2B => &genr8r[32..64],
            Direction::B2A => &genr8r[64..96],
        })
    }

    pub fn new(initial_key: &[u8], dir: Direction, params: ChainParamsPB) -> Result<Self, Error> {
        params.validate()?;
        let mut genr8r = [0u8; 96];
        kdf::hkdf_to_slice(
            &[0u8; 32],
            initial_key,
            b"Signal PQ Ratchet V1 Chain  Start",
            &mut genr8r,
        );
        let mut links = VecDeque::new();
        links.push_back(ChainEpoch {
            send: Self::ced_for_direction(&genr8r, &dir),
            recv: Self::ced_for_direction(&genr8r, &dir.switch()),
        });
        Ok(Self {
            dir,
            current_epoch: 0,
            send_epoch: 0,
            links,
            next_root: genr8r[0..32].to_vec(),
            params,
        })
    }

    pub fn add_epoch(&mut self, epoch_secret: EpochSecret) -> Result<(), Error> {
        let next_epoch = self
            .current_epoch
            .checked_add(1)
            .ok_or(Error::EpochOutOfRange(self.current_epoch))?;
        if epoch_secret.epoch != next_epoch || self.links.len() == usize::MAX {
            return Err(Error::EpochOutOfRange(epoch_secret.epoch));
        }
        let mut genr8r = [0u8; 96];
        kdf::hkdf_to_slice(
            &self.next_root,
            &epoch_secret.secret,
            b"Signal PQ Ratchet V1 Chain Add Epoch",
            &mut genr8r,
        );
        self.current_epoch = epoch_secret.epoch;
        self.next_root = genr8r[0..32].to_vec();
        self.links.push_back(ChainEpoch {
            send: Self::ced_for_direction(&genr8r, &self.dir),
            recv: Self::ced_for_direction(&genr8r, &self.dir.switch()),
        });
        Ok(())
    }

    #[hax_lib::ensures(|res| if let Ok(v) = res {v < self.links.len()} else {true})]
    fn epoch_idx(&self, epoch: Epoch) -> Result<usize, Error> {
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
        if epoch < self.send_epoch {
            return Err(Error::SendKeyEpochDecreased(self.send_epoch, epoch));
        }
        let mut epoch_index = self.epoch_idx(epoch)?;
        if self.send_epoch != epoch {
            self.send_epoch = epoch;
            while epoch_index > EPOCHS_TO_KEEP_PRIOR_TO_SEND_EPOCH {
                hax_lib::loop_invariant!(epoch_index < self.links.len());
                hax_lib::loop_decreases!(epoch_index);
                self.links.pop_front();
                epoch_index -= 1;
            }
            #[cfg(hax)]
            let links_len = self.links.len();
            #[allow(clippy::needless_range_loop)]
            for i in 0..epoch_index {
                hax_lib::loop_invariant!(|_: usize| self.links.len() == links_len);
                self.links[i].send.clear_next();
            }
        }
        if self.links[epoch_index].send.next.len() != 32 {
            return Err(Error::StateDecode);
        }
        if self.links[epoch_index].send.ctr == u32::MAX {
            return Err(Error::KeyJump(u32::MAX, u32::MAX));
        }
        Ok(self.links[epoch_index].send.next_key())
    }

    pub fn recv_key(&mut self, epoch: Epoch, index: u32) -> Result<Vec<u8>, Error> {
        if epoch == 0 && index == 0 {
            return Ok(vec![]);
        }
        let epoch_index = self.epoch_idx(epoch)?;
        self.links[epoch_index].recv.key(index, &self.params)
    }

    #[hax_lib::opaque] // into_iter and map
    pub(crate) fn into_pb(self) -> pqrpb::Chain {
        pqrpb::Chain {
            direction: self.dir.into(),
            current_epoch: self.current_epoch,
            send_epoch: self.send_epoch,
            links: self
                .links
                .into_iter()
                .map(|link| pqrpb::chain::Epoch {
                    send: Some(link.send.into_pb()),
                    recv: Some(link.recv.into_pb()),
                })
                .collect::<Vec<_>>(),
            next_root: self.next_root,
            params: Some(self.params),
        }
    }

    #[hax_lib::opaque] // into_iter and map
    pub(crate) fn from_pb(pb: pqrpb::Chain) -> Result<Self, Error> {
        Ok(Self {
            dir: pb.direction.try_into().map_err(|_| Error::StateDecode)?,
            current_epoch: pb.current_epoch,
            send_epoch: pb.send_epoch,
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
            params: {
                let params = pb.params.ok_or(Error::StateDecode)?;
                params.validate()?;
                params
            },
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{Direction, EpochSecret, Error};
    use proptest::prelude::*;
    use rand::seq::SliceRandom;
    use rand::TryRngCore;

    #[test]
    fn directions_match() {
        let mut a2b = Chain::new(b"1", Direction::A2B, ChainParams::default().into_pb()).unwrap();
        let mut b2a = Chain::new(b"1", Direction::B2A, ChainParams::default().into_pb()).unwrap();
        let sk1 = a2b.send_key(0).unwrap();
        assert_eq!(sk1.0, 1);
        assert_eq!(sk1.1, b2a.recv_key(0, 1).unwrap());
        a2b.add_epoch(EpochSecret {
            epoch: 1,
            secret: vec![2],
        })
        .unwrap();
        b2a.add_epoch(EpochSecret {
            epoch: 1,
            secret: vec![2],
        })
        .unwrap();
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
    fn rejects_malformed_next_key_in_serialized_state() {
        let malformed = pqrpb::chain::epoch::EpochDirection {
            next: vec![0; 31],
            ..Default::default()
        };
        assert!(matches!(
            ChainEpochDirection::from_pb(malformed),
            Err(Error::StateDecode)
        ));
    }

    #[test]
    fn previously_returned_key() {
        let mut a2b = Chain::new(b"1", Direction::A2B, ChainParams::default().into_pb()).unwrap();
        a2b.recv_key(0, 2).expect("should get key first time");
        assert!(matches!(
            a2b.recv_key(0, 2),
            Err(Error::KeyAlreadyRequested(2))
        ));
    }

    #[test]
    fn very_old_keys_are_trimmed() {
        let params = ChainParams {
            max_jump: 10,
            max_ooo_keys: 10,
        }
        .into_pb();
        let mut a2b = Chain::new(b"1", Direction::A2B, params).unwrap();
        a2b.recv_key(0, 10).expect("should allow this jump");
        a2b.recv_key(0, 12).expect("should allow progression");
        assert!(matches!(a2b.recv_key(0, 1), Err(Error::KeyTrimmed(1))));
    }

    #[test]
    fn out_of_order_keys() {
        let max_ooo = DEFAULT_CHAIN_PARAMS.max_ooo_keys;
        let mut a2b = Chain::new(b"1", Direction::A2B, ChainParams::default().into_pb()).unwrap();
        let mut b2a = Chain::new(b"1", Direction::B2A, ChainParams::default().into_pb()).unwrap();
        let mut keys = Vec::with_capacity(max_ooo as usize);
        for _i in 0..(max_ooo as usize) {
            keys.push(a2b.send_key(0).unwrap());
        }
        let mut rng = rand::rngs::OsRng.unwrap_err();
        keys.shuffle(&mut rng);
        for (idx, key) in keys {
            assert_eq!(b2a.recv_key(0, idx).unwrap(), key);
        }
    }

    #[test]
    fn clear_old_send_keys() {
        let mut a2b = Chain::new(b"1", Direction::A2B, ChainParams::default().into_pb()).unwrap();
        a2b.send_key(0).unwrap();
        a2b.send_key(0).unwrap();
        a2b.add_epoch(EpochSecret {
            epoch: 1,
            secret: vec![2],
        })
        .unwrap();
        a2b.send_key(1).unwrap();
        assert!(matches!(
            a2b.send_key(0).unwrap_err(),
            Error::SendKeyEpochDecreased(1, 0)
        ));
    }

    #[derive(Clone, Debug)]
    enum KeyHistoryAction {
        AddNewNext,
        AddNewSkip,
        RequestStored(usize),
        RequestNotStored(usize),
        GarbageCollect,
    }

    impl KeyHistoryAction {
        fn strategy() -> impl Strategy<Value = Self> {
            proptest::prop_oneof![
                Just(Self::AddNewNext),
                Just(Self::AddNewSkip),
                any::<usize>().prop_map(Self::RequestStored),
                any::<usize>().prop_map(Self::RequestNotStored),
                Just(Self::GarbageCollect),
            ]
        }
    }

    #[test]
    fn key_history_prop_test() {
        let _ = env_logger::builder().is_test(true).try_init();
        proptest!(|(actions in proptest::collection::vec(KeyHistoryAction::strategy(), ..25))| {
            let mut kh = KeyHistory::new();
            let mut stored = vec![];
            let mut not_stored = vec![];
            let mut ctr = 0u32;
            let params = pqrpb::ChainParams {
                max_ooo_keys: 3u32,
                max_jump: 5u32,
            };
            log::debug!("========= STARTING =========");
            for action in actions {
                match action {
                    KeyHistoryAction::AddNewNext => {
                        log::debug!("adding {}", ctr);
                        kh.add((ctr, [1u8; 32]), &params);
                        stored.push(ctr);
                        ctr += 1;
                    }
                    KeyHistoryAction::AddNewSkip => {
                        log::debug!("skipping {}", ctr);
                        not_stored.push(ctr);
                        ctr += 1;
                    }
                    KeyHistoryAction::RequestStored(i) => {
                        if !stored.is_empty() {
                            let k = stored.swap_remove(i % stored.len());
                            log::debug!("requesting stored {}", k);
                            kh.get(k, ctr, &params).unwrap();
                            not_stored.push(k);
                        }
                    }
                    KeyHistoryAction::RequestNotStored(i) => {
                        if !not_stored.is_empty() {
                            let k = not_stored.swap_remove(i % not_stored.len());
                            log::debug!("requesting not stored {}", k);
                            kh.get(k, ctr, &params).unwrap_err();
                        }
                    }
                    KeyHistoryAction::GarbageCollect => {
                        log::debug!("gc at {}", ctr);
                        kh.gc(ctr, &params);
                    }
                }
                let mut fell_off = vec![];
                (fell_off, stored) = stored.into_iter().partition(
                    |n| n + params.max_ooo_keys < ctr);
                if !fell_off.is_empty() {
                    log::debug!("fell off: {:?}", fell_off);
                }
                not_stored.extend(fell_off.into_iter());
            }
        });
    }

    #[derive(Clone, Debug)]
    enum CEDAction {
        NextKey,
        NextKeyAt(u32),
        RequestStored(usize),
        RequestNotStored(usize),
        TooHigh,
    }

    impl CEDAction {
        fn strategy() -> impl Strategy<Value = Self> {
            proptest::prop_oneof![
                Just(Self::NextKey),
                any::<u32>().prop_map(Self::NextKeyAt),
                any::<usize>().prop_map(Self::RequestStored),
                any::<usize>().prop_map(Self::RequestNotStored),
                Just(Self::TooHigh),
            ]
        }
    }

    #[test]
    fn ced_prop_test() {
        let _ = env_logger::builder().is_test(true).try_init();
        proptest!(|(actions in proptest::collection::vec(CEDAction::strategy(), ..25))| {
            let mut ced = ChainEpochDirection::new(&[1u8; 32]);
            let mut stored = vec![];
            let mut not_stored = vec![0];
            let mut ctr = 0u32;
            let params = pqrpb::ChainParams {
                max_ooo_keys: 3u32,
                max_jump: 5u32,
            };
            log::debug!("========= STARTING =========");
            for action in actions {
                match action {
                    CEDAction::NextKey => {
                        ctr += 1;
                        log::debug!("next_key {}", ctr);
                        let k = ced.next_key().0;
                        not_stored.push(k);
                    }
                    CEDAction::NextKeyAt(i) => {
                        let jump = i % params.max_jump;
                        ctr += 1;
                        for at in ctr..ctr+jump {
                            stored.push(at);
                        }
                        ctr += jump;
                        log::debug!("next_key_at {}", ctr);
                        ced.key(ctr, &params).unwrap();
                        not_stored.push(ctr);
                    }
                    CEDAction::RequestStored(i) => {
                        if !stored.is_empty() {
                            let k = stored.swap_remove(i % stored.len());
                            log::debug!("requesting stored {}", k);
                            ced.key(k, &params).unwrap();
                            not_stored.push(k);
                        }
                    }
                    CEDAction::RequestNotStored(i) => {
                        if !not_stored.is_empty() {
                            let k = not_stored.swap_remove(i % not_stored.len());
                            log::debug!("requesting not stored {}", k);
                            ced.key(k, &params).unwrap_err();
                        }
                    }
                    CEDAction::TooHigh => {
                        let high = ctr + params.max_jump + 1;
                        log::debug!("too high {}", high);
                        ced.key(high, &params).unwrap_err();
                    }
                }
                let mut fell_off = vec![];
                (fell_off, stored) = stored.into_iter().partition(
                    |n| n + params.max_ooo_keys < ctr);
                if !fell_off.is_empty() {
                    log::debug!("fell off: {:?}", fell_off);
                }
                not_stored.extend(fell_off.into_iter());
            }
        });
    }

    // Malformed decoded state must return Err, never panic.

    #[test]
    fn from_pb_rejects_misaligned_prev() {
        // `prev` length not a multiple of KEY_SIZE would desync KeyHistory::get's slicing.
        let ed = pqrpb::chain::epoch::EpochDirection {
            ctr: 0,
            next: vec![0u8; 32],
            prev: vec![0u8; KeyHistory::KEY_SIZE + 1],
        };
        assert!(ChainEpochDirection::from_pb(ed).is_err());
    }

    #[test]
    fn key_rejects_empty_next() {
        // A recv direction with an empty `next` cannot produce keys; must Err, not assert.
        let mut ced = ChainEpochDirection {
            ctr: 5,
            next: vec![],
            prev: KeyHistory::new(),
        };
        assert!(ced.key(10, &ChainParams::default().into_pb()).is_err());
    }

    #[test]
    fn key_no_overflow_near_u32_max() {
        // ctr within max_jump of u32::MAX must not overflow `ctr + max_ooo`.
        let mut ced = ChainEpochDirection {
            ctr: u32::MAX - 1000,
            next: vec![1u8; 32],
            prev: KeyHistory::new(),
        };
        // Must return (Ok or Err) rather than panicking.
        let _ = ced.key(u32::MAX, &ChainParams::default().into_pb());
    }

    #[test]
    fn from_pb_rejects_out_of_range_params() {
        let pb = pqrpb::Chain {
            direction: Direction::A2B.into(),
            current_epoch: 0,
            send_epoch: 0,
            next_root: vec![],
            links: vec![],
            params: Some(pqrpb::ChainParams {
                max_jump: 0,
                max_ooo_keys: u32::MAX,
            }),
        };
        assert!(matches!(Chain::from_pb(pb), Err(Error::InvalidParams(_))));
    }

    #[test]
    fn gc_no_underflow_when_ctr_below_max_ooo() {
        let entries = 2201usize;
        let ed = pqrpb::chain::epoch::EpochDirection {
            ctr: 0,
            next: vec![7u8; 32],
            prev: vec![0u8; entries * KeyHistory::KEY_SIZE],
        };
        let pb = pqrpb::Chain {
            direction: Direction::A2B.into(),
            current_epoch: 0,
            send_epoch: 0,
            next_root: vec![0u8; 32],
            links: vec![pqrpb::chain::Epoch {
                send: Some(pqrpb::chain::epoch::EpochDirection {
                    ctr: 0,
                    next: vec![7u8; 32],
                    prev: vec![],
                }),
                recv: Some(ed),
            }],
            params: Some(ChainParams::default().into_pb()),
        };
        let mut c = Chain::from_pb(pb).expect("state should decode");
        assert!(c.recv_key(0, 100).is_ok());
    }
}
