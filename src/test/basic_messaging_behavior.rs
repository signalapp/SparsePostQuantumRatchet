// Copyright 2025 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

use rand::Rng;
use rand_core::CryptoRng;

use super::messaging_behavior::{self, Agent, Command, MessagingBehavior};

pub struct BasicMessagingBehavior {
    p_a: f64,
    p_b: f64,
    receive_all_probability: f64,
}

impl BasicMessagingBehavior {
    pub fn new(p_a: f64, p_b: f64, receive_all_probability: f64) -> Self {
        Self {
            p_a,
            p_b,
            receive_all_probability,
        }
    }
}

impl MessagingBehavior for BasicMessagingBehavior {
    fn next_commands<R: CryptoRng>(&mut self, rng: &mut R) -> Vec<messaging_behavior::Command> {
        let mut cmds = Vec::new();

        let a_sends = rng.random_bool(self.p_a);
        let b_sends = rng.random_bool(self.p_b);
        let do_receive = rng.random_bool(self.receive_all_probability);

        if do_receive {
            cmds.push(Command::ReceiveAll(Agent::Alex));
            cmds.push(Command::ReceiveAll(Agent::Blake));
        }
        if a_sends {
            cmds.push(Command::Send(Agent::Alex));
        }
        if b_sends {
            cmds.push(Command::Send(Agent::Blake));
        }

        cmds
    }
}
