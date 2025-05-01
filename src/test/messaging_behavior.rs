// Copyright 2025 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

use rand_core::CryptoRng;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Agent {
    Alex,
    Blake,
}

#[derive(Debug)]
pub enum Command {
    Send(Agent),
    #[allow(dead_code)]
    Receive(Agent),
    ReceiveAll(Agent),
}
pub trait MessagingBehavior {
    fn next_commands<R: CryptoRng>(&mut self, rng: &mut R) -> Vec<Command>;
}
