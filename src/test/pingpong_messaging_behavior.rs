// Copyright 2025 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

use super::messaging_behavior;
use rand_distr::{Binomial, Distribution};

use super::messaging_behavior::{Agent, MessagingBehavior};

pub struct PingPongMessagingBehavior {
    window_size: u64,
    window_variance: u64,
    agent: Agent,
    sends_remaining: u64,
}

impl PingPongMessagingBehavior {
    pub fn new(window_size: u64, window_variance: u64) -> Self {
        assert!(window_variance <= window_size);
        Self {
            window_size,
            window_variance,
            agent: Agent::Blake,
            sends_remaining: 0,
        }
    }

    fn switch_agent(&mut self) {
        self.agent = match self.agent {
            Agent::Alex => Agent::Blake,
            Agent::Blake => Agent::Alex,
        }
    }
}

impl MessagingBehavior for PingPongMessagingBehavior {
    fn next_commands<R: rand_core::CryptoRng>(
        &mut self,
        rng: &mut R,
    ) -> Vec<super::messaging_behavior::Command> {
        let mut cmds = Vec::<messaging_behavior::Command>::new();
        if self.sends_remaining == 0 {
            self.switch_agent();
            cmds.push(messaging_behavior::Command::ReceiveAll(self.agent));

            let bin = Binomial::new(self.window_variance, 0.5).unwrap();
            let delta = bin.sample(rng);
            self.sends_remaining = self.window_size + delta;
        } else {
            cmds.push(messaging_behavior::Command::Send(self.agent));
            self.sends_remaining -= 1;
        }
        cmds
    }
}
