// Copyright 2025 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

use rand_core::CryptoRng;

use crate::{Epoch, Error, Secret};

pub struct SendOutput {
    pub output_key: Option<(Epoch, Secret)>,
    pub sending_epoch: Epoch,
}

pub struct ReceiveOutput {
    pub output_key: Option<(Epoch, Secret)>,
    pub receiving_epoch: Epoch,
}

// Sparse continuous key agreement
pub trait Scka {
    type Message: SckaMessage;

    fn scka_send<R: CryptoRng>(
        self,
        rng: &mut R,
    ) -> Result<(SendOutput, Self::Message, Self), Error>
    where
        Self: Sized;
    fn scka_recv(self, msg: &Self::Message) -> Result<(ReceiveOutput, Self), Error>
    where
        Self: Sized;
}

pub trait SckaMessage {
    fn epoch(&self) -> Epoch;
}

pub trait SckaInitializer {
    // Note: in the paper we pass  in an encapsulation key here to support more
    // general protocols. We will add this if it is needed.
    fn init_a<R: CryptoRng>(rng: &mut R) -> Result<Self, Error>
    where
        Self: Sized;

    // Note: in the paper we pass  in an decapsulation key here to support more
    // general protocols. We will add this if it is needed.
    fn init_b<R: CryptoRng>(rng: &mut R) -> Result<Self, Error>
    where
        Self: Sized;
}

pub trait SckaVulnerability {
    fn vulnerable_epochs(&self) -> Vec<Epoch>;
}
