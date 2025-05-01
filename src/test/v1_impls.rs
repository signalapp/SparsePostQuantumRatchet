// Copyright 2025 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

use crate::v1::chunked::states;
use crate::{
    test::scka::{Scka, SckaInitializer, SckaVulnerability},
    Epoch, Error,
};
use rand_core::CryptoRng;

use super::scka::{ReceiveOutput, SckaMessage, SendOutput};

impl Scka for states::States {
    type Message = states::Message;

    fn scka_send<R: CryptoRng>(
        self,
        rng: &mut R,
    ) -> Result<(SendOutput, states::Message, Self), Error> {
        let states::Send { msg, key, state } = self.send(rng)?;

        Ok((
            SendOutput {
                output_key: key.map(|es| (es.epoch, es.secret)),
                sending_epoch: msg.epoch - 1,
            },
            msg,
            state,
        ))
    }

    fn scka_recv(self, msg: &states::Message) -> Result<(ReceiveOutput, Self), Error>
    where
        Self: Sized,
    {
        let states::Recv { key, state } = self.recv(msg)?;
        Ok((
            ReceiveOutput {
                output_key: key.map(|es| (es.epoch, es.secret)),
                receiving_epoch: msg.epoch - 1,
            },
            state,
        ))
    }
}

impl SckaVulnerability for states::States {
    fn vulnerable_epochs(&self) -> Vec<Epoch> {
        states::States::vulnerable_epochs(self)
    }
}

impl SckaInitializer for states::States {
    fn init_a<R: CryptoRng>(_rng: &mut R) -> Result<Self, Error>
    where
        Self: Sized,
    {
        // TODO: pass in real auth key
        Ok(states::States::init_a(b"1"))
    }

    fn init_b<R: CryptoRng>(_rng: &mut R) -> Result<Self, Error>
    where
        Self: Sized,
    {
        // TODO: pass in real auth key
        Ok(states::States::init_b(b"1"))
    }
}

impl SckaMessage for states::Message {
    fn epoch(&self) -> Epoch {
        self.epoch
    }
}
