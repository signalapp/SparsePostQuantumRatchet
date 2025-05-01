// Copyright 2025 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#![allow(clippy::comparison_chain)]
#![cfg(test)]
use crate::test::scka::{
    ReceiveOutput, Scka, SckaInitializer, SckaMessage, SckaVulnerability, SendOutput,
};
use crate::Epoch;
use curve25519_dalek::{
    ristretto::CompressedRistretto, scalar::Scalar, traits::Identity, RistrettoPoint,
};
use rand_08::rngs::OsRng as OsRngFromRand08;
use rand_core::CryptoRng;
use sha2::Digest;

const X25519_KEYTYPE: u8 = 1u8;

pub type Secret = Vec<u8>;

pub struct Message {
    pub epoch: Epoch,
    pub pubkey: [u8; 33],
}

impl SckaMessage for Message {
    fn epoch(&self) -> Epoch {
        self.epoch
    }
}

#[derive(Clone)]
pub enum States {
    Send(Send),
    Recv(Recv),
    UninitSend(UninitSend),
    UninitRecv(UninitRecv),
}

impl From<Send> for States {
    fn from(value: Send) -> Self {
        States::Send(value)
    }
}

impl From<Recv> for States {
    fn from(value: Recv) -> Self {
        States::Recv(value)
    }
}

impl From<UninitSend> for States {
    fn from(value: UninitSend) -> Self {
        States::UninitSend(value)
    }
}

impl From<UninitRecv> for States {
    fn from(value: UninitRecv) -> Self {
        States::UninitRecv(value)
    }
}

impl States {
    pub fn init_a() -> Self {
        States::UninitSend(UninitSend { epoch: 0 })
    }
    pub fn init_b() -> Self {
        States::UninitRecv(UninitRecv { epoch: 0 })
    }

    pub fn sending_epoch(&self) -> Epoch {
        match self {
            States::Send(state) => state.epoch,
            States::Recv(state) => state.epoch - 1,
            States::UninitSend(_state) => 0,
            States::UninitRecv(_state) => 0,
        }
    }

    pub fn receiving_epoch(&self) -> Epoch {
        match self {
            States::Send(state) => state.epoch - 1,
            States::Recv(state) => state.epoch,
            States::UninitSend(_state) => 0,
            States::UninitRecv(_state) => 0,
        }
    }

    pub fn epoch(&self) -> Epoch {
        match self {
            States::Send(state) => state.epoch,
            States::Recv(state) => state.epoch,
            States::UninitSend(state) => state.epoch,
            States::UninitRecv(state) => state.epoch,
        }
    }
}

#[derive(Clone)]
pub struct Send {
    pub(super) epoch: Epoch,
    pub(super) remote_public: RistrettoPoint,
}

impl Send {
    fn send<R: CryptoRng>(self, _rng: &mut R) -> (Option<(Epoch, Secret)>, Message, States) {
        let mut secret = Scalar::random(&mut OsRngFromRand08);
        let public = RistrettoPoint::mul_base(&secret);

        let local_public = serialize_public_key(public);

        let msg = Message {
            epoch: self.epoch,
            pubkey: local_public,
        };

        // compute the shared secret to output
        let shared_secret = (secret * self.remote_public).compress();
        let shared_secret = shared_secret.as_bytes();

        // println!(
        //     "Send secret output ({}, {:?})",
        //     self.epoch,
        //     shared_secret.split_at(5).0
        // );

        // update the private key for forward secrecy
        let secret_hash: [u8; 64] = sha2::Sha512::digest(shared_secret).into();
        let adjustment_scalar = Scalar::from_bytes_mod_order_wide(&secret_hash);
        secret *= adjustment_scalar;

        let next = Recv {
            epoch: self.epoch + 1,
            local_public,
            secret,
        };

        (Some((self.epoch, shared_secret.to_vec())), msg, next.into())
    }

    fn recv(self, _msg: &Message) -> (Option<(Epoch, Secret)>, States) {
        (None, self.into())
    }
}

#[derive(Clone)]
pub struct Recv {
    pub(super) epoch: Epoch,
    pub(super) local_public: [u8; 33],
    pub(super) secret: Scalar,
}

impl Recv {
    fn send<R: CryptoRng>(self, _rng: &mut R) -> (Option<(Epoch, Secret)>, Message, States) {
        let msg = Message {
            epoch: self.epoch - 1,
            pubkey: self.local_public,
        };
        (None, msg, self.into())
    }

    fn recv(self, msg: &Message) -> (Option<(Epoch, Secret)>, States) {
        if msg.pubkey[0] != X25519_KEYTYPE {
            todo!("add error for unrecognized key")
        }

        if msg.epoch < self.epoch {
            println!(
                "recv earlier epoch {} < {}, ignoring",
                msg.epoch, self.epoch
            );
            return (None, self.into());
        } else if msg.epoch > self.epoch {
            todo!("create invalid epoch error");
        }
        let remote_public = CompressedRistretto::from_slice(&msg.pubkey[1..33])
            .expect("ristretto properly serialized")
            .decompress()
            .unwrap();
        let shared_secret = (self.secret * remote_public).compress();
        let shared_secret = shared_secret.as_bytes();

        // println!(
        //     "Recv secret output ({},{:?})",
        //     self.epoch,
        //     shared_secret.split_at(5).0
        // );

        // update the remote public key for forward secrecy
        let secret_hash: [u8; 64] = sha2::Sha512::digest(shared_secret).into();
        let adjustment_scalar = Scalar::from_bytes_mod_order_wide(&secret_hash);
        let remote_public = adjustment_scalar * remote_public;

        let next = Send {
            epoch: self.epoch + 1,
            remote_public,
        };

        (Some((self.epoch, shared_secret.to_vec())), next.into())
    }
}

#[derive(Clone)]
pub struct UninitSend {
    pub(super) epoch: Epoch,
}

impl UninitSend {
    fn send<R: CryptoRng>(self, _rng: &mut R) -> (Option<(Epoch, Secret)>, Message, States) {
        let secret = Scalar::random(&mut OsRngFromRand08);
        let public = RistrettoPoint::mul_base(&secret);

        let local_public = serialize_public_key(public);

        let msg = Message {
            epoch: self.epoch,
            pubkey: local_public,
        };

        let next = Recv {
            epoch: self.epoch + 1,
            local_public,
            secret,
        };

        (None, msg, next.into())
    }

    fn recv(self, _msg: &Message) -> (Option<(Epoch, Secret)>, States) {
        (None, self.into())
    }
}

#[derive(Clone)]
pub struct UninitRecv {
    pub(super) epoch: Epoch,
}

impl UninitRecv {
    fn send<R: CryptoRng>(self, _rng: &mut R) -> (Option<(Epoch, Secret)>, Message, States) {
        println!("UninitRecv::send() epoch {}", self.epoch);
        let msg = Message {
            epoch: self.epoch,
            pubkey: serialize_public_key(RistrettoPoint::identity()),
        };
        (None, msg, self.into())
    }

    fn recv(self, msg: &Message) -> (Option<(Epoch, Secret)>, States) {
        if msg.pubkey[0] != X25519_KEYTYPE {
            todo!("add error for unrecognized key")
        }

        if msg.epoch < self.epoch {
            return (None, self.into());
        } else if msg.epoch > self.epoch {
            todo!("create invalid epoch error");
        }

        let remote_public = CompressedRistretto::from_slice(&msg.pubkey[1..33])
            .expect("ristretto properly serialized")
            .decompress()
            .unwrap();

        let next = Send {
            epoch: self.epoch + 1,
            remote_public,
        };

        (None, next.into())
    }
}

fn serialize_public_key(pubkey: RistrettoPoint) -> [u8; 33] {
    let mut result = [0u8; 33];
    let compressed = pubkey.compress();
    result[0] = X25519_KEYTYPE;
    result[1..].copy_from_slice(compressed.as_bytes());
    result
}

impl Scka for States {
    type Message = Message;

    fn scka_send<R: CryptoRng>(
        self,
        rng: &mut R,
    ) -> Result<(SendOutput, Self::Message, Self), crate::Error>
    where
        Self: Sized,
    {
        let (output_key, msg, state) = match self {
            States::Send(state) => state.send(rng),
            States::Recv(state) => state.send(rng),
            States::UninitSend(state) => state.send(rng),
            States::UninitRecv(state) => state.send(rng),
        };
        let so = SendOutput {
            output_key,
            sending_epoch: state.sending_epoch(),
        };
        Ok((so, msg, state))
    }

    fn scka_recv(self, msg: &Self::Message) -> Result<(ReceiveOutput, Self), crate::Error>
    where
        Self: Sized,
    {
        let (output_key, state) = match self {
            States::Send(state) => state.recv(msg),
            States::Recv(state) => state.recv(msg),
            States::UninitSend(state) => state.recv(msg),
            States::UninitRecv(state) => state.recv(msg),
        };

        let ro = ReceiveOutput {
            output_key,
            receiving_epoch: state.receiving_epoch(),
        };
        Ok((ro, state))
    }
}

#[cfg(test)]
impl SckaInitializer for States {
    fn init_a<R: CryptoRng>(_: &mut R) -> Result<Self, crate::Error>
    where
        Self: Sized,
    {
        Ok(States::init_a())
    }

    fn init_b<R: CryptoRng>(_: &mut R) -> Result<Self, crate::Error>
    where
        Self: Sized,
    {
        Ok(States::init_b())
    }
}

#[cfg(test)]
impl SckaVulnerability for States {
    fn vulnerable_epochs(&self) -> Vec<Epoch> {
        vec![self.epoch()]
    }
}

#[cfg(test)]
mod test {

    use crate::test::messaging_scka::GenericMessagingScka;
    use crate::test::x25519_scka::states;
    use crate::test::{onlineoffline::OnlineOfflineMessagingBehavior, orchestrator};
    use crate::Error;
    use rand::TryRngCore;

    use rand_core::OsRng;

    #[test]
    fn balanced_healing() -> Result<(), Error> {
        type Scka = states::States;
        type Cka = GenericMessagingScka<Scka>;
        let mut rng = OsRng.unwrap_err();
        orchestrator::random_healing_test::<Cka, _>(0.5, &mut rng)
    }

    #[test]
    fn random_balanced() -> Result<(), Error> {
        type Scka = states::States;
        type Cka = GenericMessagingScka<Scka>;
        let mut rng = OsRng.unwrap_err();
        orchestrator::random_balanced::<Cka, _>(&mut rng)
    }

    #[test]
    fn chaos() -> Result<(), Error> {
        type Scka = states::States;
        type Cka = GenericMessagingScka<Scka>;
        let mut rng = OsRng.unwrap_err();
        orchestrator::chaos::<Cka, _>(10000, &mut rng)
    }

    #[test]
    fn onlineoffline_healing() {
        type Scka = states::States;
        type Cka = GenericMessagingScka<Scka>;
        let mut mp = OnlineOfflineMessagingBehavior::new([0.04, 0.04], [0.05, 0.05]);
        let mut rng = OsRng.unwrap_err();
        let hist = orchestrator::controlled_messaging_healing_test::<
            Cka,
            OnlineOfflineMessagingBehavior,
            _,
        >(&mut mp, 10000, &mut rng)
        .expect("should run");

        orchestrator::print_histogram(&hist);
        orchestrator::print_healing_stats(&orchestrator::stats_from_histogram(&hist)[0]);
    }

    #[test]
    fn random_balanced_out_of_order() -> Result<(), Error> {
        type Scka = states::States;
        type Cka = GenericMessagingScka<Scka>;
        let mut rng = OsRng.unwrap_err();
        orchestrator::random_balanced_out_of_order::<Cka, _>(&mut rng)
    }

    #[test]
    fn random_slow_alex_healing() -> Result<(), Error> {
        type Scka = states::States;
        type Cka = GenericMessagingScka<Scka>;
        let mut rng = OsRng.unwrap_err();
        orchestrator::random_healing_test::<Cka, _>(0.33, &mut rng)
    }
}
