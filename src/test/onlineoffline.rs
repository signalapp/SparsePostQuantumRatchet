// Copyright 2025 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

use rand::Rng;
use rand::TryRngCore;
use rand_core::OsRng;

use super::messaging_behavior::{Agent, Command, MessagingBehavior};

#[derive(Clone)]
enum State {
    Online,
    Offline,
}

impl State {
    fn transition(self, prob_come_online: f64, prob_go_offline: f64) -> Self {
        let mut rng = OsRng.unwrap_err();
        match self {
            State::Online => {
                if rng.random_bool(prob_go_offline) {
                    State::Offline
                } else {
                    State::Online
                }
            }
            State::Offline => {
                if rng.random_bool(prob_come_online) {
                    State::Online
                } else {
                    State::Offline
                }
            }
        }
    }

    fn is_online(&self) -> bool {
        match self {
            State::Online => true,
            State::Offline => false,
        }
    }
}

const ALEX: usize = 0;
const BLAKE: usize = 1;

pub struct OnlineOfflineMessagingBehavior {
    prob_go_offline: [f64; 2],
    prob_come_online: [f64; 2],
    agents: [Agent; 2],
    states: [State; 2],
}

impl OnlineOfflineMessagingBehavior {
    pub fn new(prob_go_offline: [f64; 2], prob_come_online: [f64; 2]) -> Self {
        Self {
            prob_go_offline,
            prob_come_online,
            agents: [Agent::Alex, Agent::Blake],
            states: [State::Online, State::Online],
        }
    }
}

impl MessagingBehavior for OnlineOfflineMessagingBehavior {
    fn next_commands<R: rand_core::CryptoRng>(
        &mut self,
        rng: &mut R,
    ) -> Vec<super::messaging_behavior::Command> {
        let agent = if rng.random_bool(0.5) { ALEX } else { BLAKE };

        self.states[agent] = self.states[agent]
            .clone()
            .transition(self.prob_come_online[agent], self.prob_go_offline[agent]);
        let mut cmds = Vec::new();

        if self.states[agent].is_online() {
            cmds.push(Command::ReceiveAll(self.agents[agent]));
            if rng.random_bool(0.5) {
                cmds.push(Command::Send(self.agents[agent]));
            }
        }

        cmds
    }
}
