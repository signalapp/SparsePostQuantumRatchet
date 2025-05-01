// Copyright 2025 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

pub(crate) mod chunked;
pub(crate) mod unchunked;

#[cfg(test)]
mod test {
    use crate::test::messaging_scka::GenericMessagingScka;
    use crate::test::{onlineoffline::OnlineOfflineMessagingBehavior, orchestrator};
    use crate::v1::chunked::states;
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
    fn onlineoffline_healing_unidir() {
        type Scka = states::States;
        type Cka = GenericMessagingScka<Scka>;
        let mut mp = OnlineOfflineMessagingBehavior::new([0.04, 0.04], [0.05, 0.05]);
        let mut rng = OsRng.unwrap_err();
        orchestrator::controlled_messaging_healing_test::<Cka, OnlineOfflineMessagingBehavior, _>(
            &mut mp, 100000, &mut rng,
        )
        .expect("should run");
    }

    #[test]
    fn random_balanced_out_of_order() -> Result<(), Error> {
        type Scka = states::States;
        type Cka = GenericMessagingScka<Scka>;
        let mut rng = OsRng.unwrap_err();
        orchestrator::random_balanced_out_of_order::<Cka, _>(&mut rng)
    }

    #[test]
    fn random_slow_alex_healing_auth_bidir() -> Result<(), Error> {
        type Scka = states::States;
        type Cka = GenericMessagingScka<Scka>;
        let mut rng = OsRng.unwrap_err();
        orchestrator::random_healing_test::<Cka, _>(0.33, &mut rng)
    }
}
