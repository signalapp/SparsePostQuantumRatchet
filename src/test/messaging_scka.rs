// Copyright 2025 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;

use rand_core::{CryptoRng, OsRng};

use crate::{
    test::scka::{Scka, SckaInitializer, SckaVulnerability},
    Epoch, Error, Secret,
};

pub trait MessagingScka {
    type CkaOutput;
    type Message;

    fn init_a<R: CryptoRng>(rng: &mut R) -> Result<Self, Error>
    where
        Self: Sized;
    fn init_b<R: CryptoRng>(rng: &mut R) -> Result<Self, Error>
    where
        Self: Sized;

    #[allow(clippy::type_complexity)]
    fn messaging_scka_send<R: CryptoRng>(
        &mut self,
        rng: &mut R,
    ) -> Result<(Option<(Epoch, Self::CkaOutput)>, Self::Message), Error>
    where
        Self::CkaOutput: Sized;
    fn messaging_scka_recv(
        &mut self,
        msg: &Self::Message,
        rng: &mut OsRng,
    ) -> Result<Option<(Epoch, Self::CkaOutput)>, Error>
    where
        Self::CkaOutput: Sized;
}

pub trait MessagingCkaVulnerability {
    fn vulnerable_epochs(&self) -> Vec<Epoch>;
    fn last_emitted_epoch(&self) -> Epoch;
}

pub struct GenericMessagingScka<SCKA: Scka> {
    scka: SCKA,
    send_outputs: BTreeMap<Epoch, Secret>,
    recv_outputs: BTreeMap<Epoch, Secret>,
    last_emitted_epoch: Epoch,
}

impl<SCKA: Scka + SckaInitializer + Clone> MessagingScka for GenericMessagingScka<SCKA> {
    type CkaOutput = Secret;

    type Message = SCKA::Message;

    fn init_a<R: CryptoRng>(rng: &mut R) -> Result<Self, Error>
    where
        Self: Sized,
    {
        Ok(Self {
            scka: SCKA::init_a(rng)?,
            send_outputs: BTreeMap::new(),
            recv_outputs: BTreeMap::new(),
            last_emitted_epoch: 0,
        })
    }

    fn init_b<R: CryptoRng>(rng: &mut R) -> Result<Self, Error>
    where
        Self: Sized,
    {
        Ok(Self {
            scka: SCKA::init_b(rng)?,
            send_outputs: BTreeMap::new(),
            recv_outputs: BTreeMap::new(),
            last_emitted_epoch: 0,
        })
    }

    fn messaging_scka_send<R: CryptoRng>(
        &mut self,
        rng: &mut R,
    ) -> Result<(Option<(Epoch, Self::CkaOutput)>, Self::Message), crate::Error>
    where
        Self::CkaOutput: Sized,
    {
        let (so, msg, state) = self.scka.clone().scka_send(rng)?;
        self.scka = state;

        // self.last_emitted_epoch = so.sending_epoch;
        let earliest_send_output = if let Some((ep, _)) = self.send_outputs.first_key_value() {
            *ep
        } else {
            0
        };

        if let Some((ep, k)) = so.output_key {
            self.send_outputs.insert(ep, k);
        }

        let mut take_key = false;
        if let Some(entry) = self.recv_outputs.first_entry() {
            let ep = *entry.key();
            if ep <= so.sending_epoch
                && (earliest_send_output == 0 || ep < earliest_send_output)
                && (self.last_emitted_epoch == 0 || ep == self.last_emitted_epoch + 1)
            {
                take_key = true;
            }
        };
        let output_key = if take_key {
            let entry = self.recv_outputs.first_entry().unwrap();
            let ep = *entry.key();
            self.last_emitted_epoch = ep;
            // info!("messaging scka send outputs: {:?}", entry);
            Some((ep, entry.remove()))
        } else {
            None
        };

        Ok((output_key, msg))
    }

    fn messaging_scka_recv(
        &mut self,
        msg: &Self::Message,
        _rng: &mut OsRng,
    ) -> Result<Option<(Epoch, Self::CkaOutput)>, Error>
    where
        Self::CkaOutput: Sized,
    {
        let (ro, state) = self.scka.clone().scka_recv(msg)?;
        self.scka = state;

        // self.last_emitted_epoch = ro.receiving_epoch;
        let earliest_recv_output = if let Some((ep, _)) = self.recv_outputs.first_key_value() {
            *ep
        } else {
            0
        };

        if let Some((ep, k)) = ro.output_key {
            self.recv_outputs.insert(ep, k);
        }

        let mut take_key = false;
        if let Some(entry) = self.send_outputs.first_entry() {
            let ep = *entry.key();
            if ep <= ro.receiving_epoch
                && (earliest_recv_output == 0 || ep < earliest_recv_output)
                && (self.last_emitted_epoch == 0 || ep == self.last_emitted_epoch + 1)
            {
                take_key = true;
            }
        };

        let output_key = if take_key {
            let entry = self.send_outputs.first_entry().unwrap();
            let ep = *entry.key();
            self.last_emitted_epoch = ep;
            // info!("messaging scka recv outputs: {:?}", entry);
            Some((ep, entry.remove()))
        } else {
            None
        };

        Ok(output_key)
    }
}

#[cfg(test)]
impl<SCKA: Scka + SckaVulnerability> MessagingCkaVulnerability for GenericMessagingScka<SCKA> {
    fn vulnerable_epochs(&self) -> Vec<Epoch> {
        let mut result = self.scka.vulnerable_epochs();
        for (ep, _) in self.send_outputs.iter() {
            result.push(*ep);
        }
        for (ep, _) in self.recv_outputs.iter() {
            result.push(*ep);
        }
        result
    }

    fn last_emitted_epoch(&self) -> Epoch {
        self.last_emitted_epoch
    }
}

#[cfg(test)]
mod test {
    use rand::TryRngCore;
    use rand_core::OsRng;

    use crate::{
        test::{
            messaging_scka::GenericMessagingScka, onlineoffline::OnlineOfflineMessagingBehavior,
            orchestrator, pingpong_messaging_behavior::PingPongMessagingBehavior,
        },
        v1states::States,
    };

    #[test]
    fn random_balanced() {
        type Scka = States;
        type Cka = GenericMessagingScka<Scka>;
        let mut rng = OsRng.unwrap_err();
        orchestrator::random_balanced::<Cka, _>(&mut rng).expect("should run");
    }
    #[test]
    fn random_balanced_out_of_order() {
        type Scka = States;
        type Cka = GenericMessagingScka<Scka>;
        let mut rng = OsRng.unwrap_err();
        orchestrator::random_balanced_out_of_order::<Cka, _>(&mut rng).expect("should run");
    }

    #[test]
    fn random_balanced_healing() {
        type Scka = States;
        type Cka = GenericMessagingScka<Scka>;
        let mut rng = OsRng.unwrap_err();
        orchestrator::random_healing_test::<Cka, _>(0.5, &mut rng).expect("should run");
    }

    #[test]
    fn pingpong_healing() {
        type Scka = States;
        type Cka = GenericMessagingScka<Scka>;
        let mut mp = PingPongMessagingBehavior::new(50, 0);
        let mut rng = OsRng.unwrap_err();
        let hist =
            orchestrator::controlled_messaging_healing_test::<Cka, PingPongMessagingBehavior, _>(
                &mut mp, 10000, &mut rng,
            )
            .expect("should run");
        orchestrator::print_histogram(&hist);
    }

    #[test]
    fn onlineoffline_healing() {
        type Scka = States;
        type Cka = GenericMessagingScka<Scka>;
        let mut mp = OnlineOfflineMessagingBehavior::new([0.04, 0.04], [0.05, 0.05]);
        let mut rng = OsRng.unwrap_err();
        let hist = orchestrator::controlled_messaging_healing_test::<
            Cka,
            OnlineOfflineMessagingBehavior,
            _,
        >(&mut mp, 100000, &mut rng)
        .expect("should run");
        orchestrator::print_histogram(&hist);
        orchestrator::print_healing_stats(&orchestrator::stats_from_histogram(&hist)[0]);
    }
}
