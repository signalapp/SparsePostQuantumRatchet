// Copyright 2025 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::fmt::Debug;

use rand::prelude::*;
use rand::rngs::OsRng;
use rand::rngs::StdRng;
use rand_core::CryptoRng;

use crate::test::messaging_behavior::{Agent, Command};
use crate::test::messaging_scka::{MessagingCkaVulnerability, MessagingScka};
use crate::Epoch;
use crate::Error;

use super::basic_messaging_behavior::BasicMessagingBehavior;
use super::messaging_behavior::MessagingBehavior;

pub struct OrchestratorBase<K>
where
    K: MessagingScka,
    <K as MessagingScka>::CkaOutput: PartialEq + Debug,
{
    a2b_msg_queue: VecDeque<K::Message>,
    b2a_msg_queue: VecDeque<K::Message>,
    key_history_a: Vec<K::CkaOutput>,
    key_history_b: Vec<K::CkaOutput>,
    pub alex: K,
    pub blake: K,
    pub last_emitted_epoch_a: Epoch,
    pub last_emitted_epoch_b: Epoch,
    pub a_sent: usize,
    pub b_sent: usize,
    pub a_rcvd: usize,
    pub b_rcvd: usize,
}

impl<K> OrchestratorBase<K>
where
    K: MessagingScka + MessagingCkaVulnerability,
    <K as MessagingScka>::CkaOutput: PartialEq + Debug,
{
    pub fn new<R: CryptoRng>(rng: &mut R) -> Result<Self, Error> {
        let alex = K::init_a(rng)?;
        let blake = K::init_b(rng)?;

        Ok(Self {
            a2b_msg_queue: VecDeque::new(),
            b2a_msg_queue: VecDeque::new(),
            key_history_a: Vec::new(),
            key_history_b: Vec::new(),
            alex,
            blake,
            last_emitted_epoch_a: 0,
            last_emitted_epoch_b: 0,
            a_sent: 0,
            b_sent: 0,
            a_rcvd: 0,
            b_rcvd: 0,
        })
    }

    pub fn key_history_is_consistent(&self) {
        for (ka, kb) in self.key_history_a.iter().zip(self.key_history_b.iter()) {
            assert_eq!(ka, kb);
        }
    }

    #[allow(clippy::type_complexity)]
    fn data_for_agent(
        &mut self,
        is_alex: bool,
    ) -> (
        &mut K,
        &mut VecDeque<K::Message>,
        &mut VecDeque<K::Message>,
        &mut Vec<K::CkaOutput>,
    ) {
        if is_alex {
            (
                &mut self.alex,
                &mut self.b2a_msg_queue,
                &mut self.a2b_msg_queue,
                &mut self.key_history_a,
            )
        } else {
            (
                &mut self.blake,
                &mut self.a2b_msg_queue,
                &mut self.b2a_msg_queue,
                &mut self.key_history_b,
            )
        }
    }

    pub fn send<R: CryptoRng>(&mut self, is_alex: bool, rng: &mut R) -> Result<bool, Error> {
        let mut emitted_key = false;
        let mut emitted_ep: Option<Epoch> = None;
        {
            {
                let (agent, _incoming_msg_queue, outgoing_msg_queue, key_history) =
                    self.data_for_agent(is_alex);
                let (out, msg) = agent.messaging_scka_send(rng)?;
                if let Some((_ep, key)) = out {
                    key_history.push(key);
                    emitted_ep = Some(agent.last_emitted_epoch());
                    emitted_key = true;
                }
                outgoing_msg_queue.push_back(msg);
            }
            if is_alex {
                self.a_sent += 1;
            } else {
                self.b_sent += 1;
            }
        }

        if let Some(ep) = emitted_ep {
            if is_alex {
                self.last_emitted_epoch_a = ep;
            } else {
                self.last_emitted_epoch_b = ep;
            }
        }
        Ok(emitted_key)
    }

    pub fn receive_in_order(&mut self, is_alex: bool) -> Result<bool, Error> {
        let mut emitted_key = false;
        let mut emitted_ep: Option<Epoch> = None;
        {
            let (agent, incoming_message_queue, _omq, key_history) = self.data_for_agent(is_alex);

            let maybe_msg = incoming_message_queue.pop_front();
            if let Some(msg) = maybe_msg {
                let mut rng = OsRng;
                let out = agent.messaging_scka_recv(&msg, &mut rng)?;
                if let Some((_ep, key)) = out {
                    key_history.push(key);
                    emitted_ep = Some(agent.last_emitted_epoch());
                    emitted_key = true
                }
                if is_alex {
                    self.a_rcvd += 1;
                } else {
                    self.b_rcvd += 1;
                }
            }
        }
        if let Some(ep) = emitted_ep {
            if is_alex {
                self.last_emitted_epoch_a = ep;
            } else {
                self.last_emitted_epoch_b = ep;
            }
        }
        Ok(emitted_key)
    }

    pub fn receive_at(&mut self, is_alex: bool, i: usize) -> Result<bool, Error> {
        let mut emitted_key = false;
        let mut emitted_ep: Option<Epoch> = None;
        {
            let (agent, incoming_message_queue, _omq, key_history) = self.data_for_agent(is_alex);

            let maybe_msg = incoming_message_queue.remove(i);
            if let Some(msg) = maybe_msg {
                let mut rng = OsRng;
                let out = agent.messaging_scka_recv(&msg, &mut rng)?;
                if let Some((_ep, key)) = out {
                    key_history.push(key);
                    emitted_ep = Some(agent.last_emitted_epoch());
                    emitted_key = true
                }
                if is_alex {
                    self.a_rcvd += 1;
                } else {
                    self.b_rcvd += 1;
                }
            }
        }
        if let Some(ep) = emitted_ep {
            if is_alex {
                self.last_emitted_epoch_a = ep;
            } else {
                self.last_emitted_epoch_b = ep;
            }
        }
        Ok(emitted_key)
    }

    #[allow(dead_code)]
    pub fn drop_message_at(&mut self, is_alex: bool, i: usize) {
        let (_agent, incoming_message_queue, _omq, _key_history) = self.data_for_agent(is_alex);

        incoming_message_queue.remove(i);
    }

    pub fn incoming_queue_size(&self, is_alex: bool) -> usize {
        if is_alex {
            self.b2a_msg_queue.len()
        } else {
            self.a2b_msg_queue.len()
        }
    }

    pub fn receive_all(&mut self, is_alex: bool) -> Result<bool, Error> {
        let mut emitted_ep: Option<Epoch> = None;
        let mut emitted_key = false;
        let mut num_received = 0usize;
        let (agent, incoming_message_queue, _omq, key_history) = self.data_for_agent(is_alex);
        while !incoming_message_queue.is_empty() {
            let maybe_msg = incoming_message_queue.pop_front();
            if let Some(msg) = maybe_msg {
                let mut rng = OsRng;
                let out = agent.messaging_scka_recv(&msg, &mut rng)?;
                if let Some((_ep, key)) = out {
                    key_history.push(key);
                    emitted_key = true;
                    emitted_ep = Some(agent.last_emitted_epoch());
                }
                num_received += 1;
            }
        }
        if is_alex {
            self.a_rcvd += num_received;
        } else {
            self.b_rcvd += num_received;
        }
        if let Some(ep) = emitted_ep {
            if is_alex {
                self.last_emitted_epoch_a = ep;
            } else {
                self.last_emitted_epoch_b = ep;
            }
        }
        Ok(emitted_key)
    }

    pub fn last_vulnerable_epoch_a(&self) -> Epoch {
        *self.alex.vulnerable_epochs().iter().max().unwrap_or(&0u64)
    }

    pub fn last_vulnerable_epoch_b(&self) -> Epoch {
        *self.blake.vulnerable_epochs().iter().max().unwrap_or(&0u64)
    }

    pub fn qlen(&self, for_alex: bool) -> usize {
        if for_alex {
            self.b2a_msg_queue.len()
        } else {
            self.a2b_msg_queue.len()
        }
    }

    pub fn print_msg_queue_lengths(&self) {
        println!(
            "Alex has {} incoming, Blake has {} incoming",
            self.b2a_msg_queue.len(),
            self.a2b_msg_queue.len()
        );
    }

    pub fn print_key_history_lengths(&self) {
        println!(
            "Alex emitted {} keys, Blake emitted {} keys",
            self.key_history_a.len(),
            self.key_history_b.len()
        );
    }
}

struct Compromise {
    #[allow(dead_code)]
    tick: usize,
    a_sent: usize,
    b_sent: usize,
    a_rcvd: usize,
    b_rcvd: usize,
    #[allow(dead_code)]
    heals_at: Epoch,
    exposed_epochs: Vec<Epoch>,
    active_epoch: Epoch,
}

#[derive(Debug)]
struct EpochVulnsetInfo {
    a_start: usize,
    a_end: usize,
    b_start: usize,
    b_end: usize,
}

pub struct HealingHistogramEntry {
    pub num_msgs: usize,
    pub tot_by_a: usize,
    pub tot_by_b: usize,
}

pub struct HealingStats {
    pub mean: f64,
    pub stddev: f64,
    pub deciles: [usize; 11],
}

pub fn stats_from_histogram(hist: &Vec<HealingHistogramEntry>) -> [HealingStats; 2] {
    // first pass: compute aggregates: count, sum(num_msgs), sum(num_msgs^2)
    let mut count = [0usize; 2];
    let mut sum = [0usize; 2];
    let mut sum_squares = [0usize; 2];
    let mut min = [usize::MAX; 2];
    let mut max = [0usize; 2];
    let mut deciles = [[0usize; 11]; 2];

    let mut mean = [0f64; 2];
    let mut mean_square = [0f64; 2];
    let mut var = [0f64; 2];
    let mut stddev = [0f64; 2];

    for entry in hist {
        count[0] += entry.tot_by_a;
        count[1] += entry.tot_by_b;
        sum[0] += entry.num_msgs * entry.tot_by_a;
        sum[1] += entry.num_msgs * entry.tot_by_b;
        sum_squares[0] += entry.num_msgs * entry.num_msgs * entry.tot_by_a;
        sum_squares[1] += entry.num_msgs * entry.num_msgs * entry.tot_by_b;
        if entry.tot_by_a > 0 {
            min[0] = std::cmp::min(min[0], entry.num_msgs);
            max[0] = std::cmp::max(max[0], entry.num_msgs);
        }
        if entry.tot_by_b > 0 {
            min[1] = std::cmp::min(min[1], entry.num_msgs);
            max[1] = std::cmp::max(max[1], entry.num_msgs);
        }
    }
    for i in 0..2 {
        mean[i] = (sum[i] as f64) / (count[i] as f64);
        mean_square[i] = (sum_squares[i] as f64) / (count[i] as f64);
        var[i] = mean_square[i] - mean[i] * mean[i];
        stddev[i] = var[i].sqrt();
    }

    for i in 0..2 {
        deciles[i][0] = min[i];
        deciles[i][10] = max[i];
        let mut cummulative_count = 0usize;
        let mut ctr = 1usize;
        for entry in hist {
            cummulative_count += if i == 0 {
                entry.tot_by_a
            } else {
                entry.tot_by_b
            };
            let decile_target = (count[i] * ctr) / 10;
            if cummulative_count > decile_target {
                deciles[i][ctr] = entry.num_msgs;
                ctr += 1;
            }
            if ctr == 10 {
                break;
            }
        }
    }

    [
        HealingStats {
            mean: mean[0],
            stddev: stddev[0],
            deciles: deciles[0],
        },
        HealingStats {
            mean: mean[1],
            stddev: stddev[1],
            deciles: deciles[1],
        },
    ]
}

pub fn print_histogram(hist: &Vec<HealingHistogramEntry>) {
    println!("num exposed,msgs exposed by a comp,msgs exposed by b comp,freq a exposed by full,freq b exposed by full,tot exposed by full");
    for entry in hist {
        println!("{},{},{}", entry.num_msgs, entry.tot_by_a, entry.tot_by_b,);
    }
}

pub fn print_healing_stats(stats: &HealingStats) {
    println!("mean, stddev, min,p10,p20,p30,p40,p50,p60,p70,p80,p90,max");
    println!(
        "{},{},{},{},{},{},{},{},{},{},{},{},{}",
        stats.mean,
        stats.stddev,
        stats.deciles[0],
        stats.deciles[1],
        stats.deciles[2],
        stats.deciles[3],
        stats.deciles[4],
        stats.deciles[5],
        stats.deciles[6],
        stats.deciles[7],
        stats.deciles[8],
        stats.deciles[9],
        stats.deciles[10],
    )
}

pub fn random_healing_test<CKA, R: CryptoRng>(ratio: f64, rng: &mut R) -> Result<(), Error>
where
    CKA: MessagingScka + MessagingCkaVulnerability,
    <CKA as MessagingScka>::CkaOutput: PartialEq + Debug,
{
    let base_send_prob = 0.5;
    let p_a = base_send_prob * ratio;
    let p_b = base_send_prob * (1.0 - ratio);
    let mut mp = BasicMessagingBehavior::new(p_a, p_b, 0.9);
    let hist =
        controlled_messaging_healing_test::<CKA, BasicMessagingBehavior, R>(&mut mp, 10000, rng)?;
    print_histogram(&hist);
    print_healing_stats(&stats_from_histogram(&hist)[0]);
    Ok(())
}

pub fn controlled_messaging_healing_test<CKA, MP, R>(
    mp: &mut MP,
    num_ticks: usize,
    rng: &mut R,
) -> Result<Vec<HealingHistogramEntry>, Error>
where
    CKA: MessagingScka + MessagingCkaVulnerability,
    <CKA as MessagingScka>::CkaOutput: PartialEq + Debug,
    MP: MessagingBehavior,
    R: CryptoRng,
{
    let mut message_pattern_rng = StdRng::seed_from_u64(43);

    let mut orchestrator = OrchestratorBase::<CKA>::new(rng)?;
    let mut alex_compromises_that_heal_at = HashMap::<Epoch, Vec<Compromise>>::new();
    let mut blake_compromises_that_heal_at = HashMap::<Epoch, Vec<Compromise>>::new();

    let mut epoch_info = BTreeMap::<Epoch, EpochVulnsetInfo>::new();

    for tick in 0..num_ticks {
        // println!("tick {}", tick);
        let mut emitted_key = false;
        let mut alex_emitted_key = false;
        let mut blake_emitted_key = false;
        let cmds = mp.next_commands(&mut message_pattern_rng);
        for cmd in &cmds {
            match cmd {
                Command::Send(agent) => {
                    let use_alex = agent == &Agent::Alex;
                    let emitted_send = orchestrator.send(use_alex, rng)?;

                    let OrchestratorBase {
                        a_sent,
                        b_sent,
                        a_rcvd,
                        b_rcvd,
                        ..
                    } = orchestrator;

                    emitted_key = emitted_key || emitted_send;
                    alex_emitted_key = alex_emitted_key || (emitted_key && use_alex);
                    blake_emitted_key = blake_emitted_key || (emitted_key && !use_alex);

                    if alex_emitted_key {
                        // alex emitted a key and may have healed
                        let emitted_ep = orchestrator.alex.last_emitted_epoch();
                        epoch_info
                            .entry(emitted_ep)
                            .and_modify(|inf| {
                                inf.a_start = a_sent;
                            })
                            .or_insert(EpochVulnsetInfo {
                                a_start: a_sent,
                                a_end: 0,
                                b_start: usize::MAX,
                                b_end: 0,
                            });
                        if emitted_ep > 0 {
                            epoch_info
                                .entry(emitted_ep - 1)
                                .and_modify(|inf| {
                                    inf.a_end = a_sent;
                                })
                                .or_insert(EpochVulnsetInfo {
                                    a_start: 0,
                                    a_end: a_sent,
                                    b_start: usize::MAX,
                                    b_end: 0,
                                });
                        }
                    }
                    if blake_emitted_key {
                        // blake emitted a key and may have healed
                        // alex emitted a key and may have healed
                        let emitted_ep = orchestrator.blake.last_emitted_epoch();
                        epoch_info
                            .entry(emitted_ep)
                            .and_modify(|inf| {
                                inf.b_start = b_sent;
                            })
                            .or_insert(EpochVulnsetInfo {
                                a_start: usize::MAX,
                                a_end: 0,
                                b_start: b_sent,
                                b_end: 0,
                            });
                        if emitted_ep > 0 {
                            epoch_info
                                .entry(emitted_ep - 1)
                                .and_modify(|inf| {
                                    inf.b_end = b_sent;
                                })
                                .or_insert(EpochVulnsetInfo {
                                    a_start: usize::MAX,
                                    a_end: 0,
                                    b_start: 0,
                                    b_end: b_sent,
                                });
                        }
                    }
                    if use_alex {
                        let heals_at = orchestrator.last_vulnerable_epoch_a() + 1;
                        let comp = Compromise {
                            tick,
                            a_sent,
                            b_sent,
                            a_rcvd,
                            b_rcvd,
                            heals_at,
                            exposed_epochs: orchestrator.alex.vulnerable_epochs(),
                            active_epoch: orchestrator.alex.last_emitted_epoch(),
                        };
                        alex_compromises_that_heal_at
                            .entry(heals_at)
                            .or_default()
                            .push(comp);
                    } else {
                        let heals_at = orchestrator.last_vulnerable_epoch_b() + 1;
                        let comp = Compromise {
                            tick,
                            a_sent,
                            b_sent,
                            a_rcvd,
                            b_rcvd,
                            heals_at,
                            exposed_epochs: orchestrator.blake.vulnerable_epochs(),
                            active_epoch: orchestrator.blake.last_emitted_epoch(),
                        };
                        blake_compromises_that_heal_at
                            .entry(heals_at)
                            .or_default()
                            .push(comp);
                    }
                }
                Command::ReceiveAll(agent) => {
                    let use_alex = agent == &Agent::Alex;
                    let do_compromise = orchestrator.incoming_queue_size(use_alex) > 0;
                    let emitted_recv = orchestrator.receive_all(use_alex)?;

                    let OrchestratorBase {
                        a_sent,
                        b_sent,
                        a_rcvd,
                        b_rcvd,
                        ..
                    } = orchestrator;

                    emitted_key = emitted_key || emitted_recv;
                    alex_emitted_key = alex_emitted_key || (emitted_key && use_alex);
                    blake_emitted_key = blake_emitted_key || (emitted_key && !use_alex);

                    if alex_emitted_key {
                        // alex emitted a key and may have healed
                        let emitted_ep = orchestrator.alex.last_emitted_epoch();
                        epoch_info
                            .entry(emitted_ep)
                            .and_modify(|inf| {
                                inf.a_start = a_sent;
                            })
                            .or_insert(EpochVulnsetInfo {
                                a_start: a_sent,
                                a_end: 0,
                                b_start: usize::MAX,
                                b_end: 0,
                            });
                        if emitted_ep > 0 {
                            epoch_info
                                .entry(emitted_ep - 1)
                                .and_modify(|inf| {
                                    inf.a_end = a_sent;
                                })
                                .or_insert(EpochVulnsetInfo {
                                    a_start: 0,
                                    a_end: a_sent,
                                    b_start: usize::MAX,
                                    b_end: 0,
                                });
                        }
                    }
                    if blake_emitted_key {
                        // blake emitted a key and may have healed
                        // alex emitted a key and may have healed
                        let emitted_ep = orchestrator.blake.last_emitted_epoch();
                        epoch_info
                            .entry(emitted_ep)
                            .and_modify(|inf| {
                                inf.b_start = b_sent;
                            })
                            .or_insert(EpochVulnsetInfo {
                                a_start: usize::MAX,
                                a_end: 0,
                                b_start: b_sent,
                                b_end: 0,
                            });
                        if emitted_ep > 0 {
                            epoch_info
                                .entry(emitted_ep - 1)
                                .and_modify(|inf| {
                                    inf.b_end = b_sent;
                                })
                                .or_insert(EpochVulnsetInfo {
                                    a_start: usize::MAX,
                                    a_end: 0,
                                    b_start: 0,
                                    b_end: b_sent,
                                });
                        }
                    }
                    if do_compromise {
                        if use_alex {
                            let heals_at = orchestrator.last_vulnerable_epoch_a() + 1;
                            let comp = Compromise {
                                tick,
                                a_sent,
                                b_sent,
                                a_rcvd,
                                b_rcvd,
                                heals_at,
                                exposed_epochs: orchestrator.alex.vulnerable_epochs(),
                                active_epoch: orchestrator.alex.last_emitted_epoch(),
                            };
                            alex_compromises_that_heal_at
                                .entry(heals_at)
                                .or_default()
                                .push(comp);
                        } else {
                            let heals_at = orchestrator.last_vulnerable_epoch_b() + 1;
                            let comp = Compromise {
                                tick,
                                a_sent,
                                b_sent,
                                a_rcvd,
                                b_rcvd,
                                heals_at,
                                exposed_epochs: orchestrator.blake.vulnerable_epochs(),
                                active_epoch: orchestrator.blake.last_emitted_epoch(),
                            };
                            blake_compromises_that_heal_at
                                .entry(heals_at)
                                .or_default()
                                .push(comp);
                        }
                    }
                }
                Command::Receive(agent) => {
                    let use_alex = agent == &Agent::Alex;
                    let do_compromise = orchestrator.incoming_queue_size(use_alex) > 0;
                    let emitted_recv = orchestrator.receive_in_order(use_alex)?;

                    let OrchestratorBase {
                        a_sent,
                        b_sent,
                        a_rcvd,
                        b_rcvd,
                        ..
                    } = orchestrator;

                    emitted_key = emitted_key || emitted_recv;
                    alex_emitted_key = alex_emitted_key || (emitted_key && use_alex);
                    blake_emitted_key = blake_emitted_key || (emitted_key && !use_alex);

                    if alex_emitted_key {
                        // alex emitted a key and may have healed
                        let emitted_ep = orchestrator.alex.last_emitted_epoch();
                        epoch_info
                            .entry(emitted_ep)
                            .and_modify(|inf| {
                                inf.a_start = a_sent;
                            })
                            .or_insert(EpochVulnsetInfo {
                                a_start: a_sent,
                                a_end: 0,
                                b_start: usize::MAX,
                                b_end: 0,
                            });
                        if emitted_ep > 0 {
                            epoch_info
                                .entry(emitted_ep - 1)
                                .and_modify(|inf| {
                                    inf.a_end = a_sent;
                                })
                                .or_insert(EpochVulnsetInfo {
                                    a_start: 0,
                                    a_end: a_sent,
                                    b_start: usize::MAX,
                                    b_end: 0,
                                });
                        }
                    }
                    if blake_emitted_key {
                        // blake emitted a key and may have healed
                        // alex emitted a key and may have healed
                        let emitted_ep = orchestrator.blake.last_emitted_epoch();
                        epoch_info
                            .entry(emitted_ep)
                            .and_modify(|inf| {
                                inf.b_start = b_sent;
                            })
                            .or_insert(EpochVulnsetInfo {
                                a_start: usize::MAX,
                                a_end: 0,
                                b_start: b_sent,
                                b_end: 0,
                            });
                        if emitted_ep > 0 {
                            epoch_info
                                .entry(emitted_ep - 1)
                                .and_modify(|inf| {
                                    inf.b_end = b_sent;
                                })
                                .or_insert(EpochVulnsetInfo {
                                    a_start: usize::MAX,
                                    a_end: 0,
                                    b_start: 0,
                                    b_end: b_sent,
                                });
                        }
                    }
                    if do_compromise {
                        if use_alex {
                            let heals_at = orchestrator.last_vulnerable_epoch_a() + 1;
                            let comp = Compromise {
                                tick,
                                a_sent,
                                b_sent,
                                a_rcvd,
                                b_rcvd,
                                heals_at,
                                exposed_epochs: orchestrator.alex.vulnerable_epochs(),
                                active_epoch: orchestrator.alex.last_emitted_epoch(),
                            };
                            alex_compromises_that_heal_at
                                .entry(heals_at)
                                .or_default()
                                .push(comp);
                        } else {
                            let heals_at = orchestrator.last_vulnerable_epoch_b() + 1;
                            let comp = Compromise {
                                tick,
                                a_sent,
                                b_sent,
                                a_rcvd,
                                b_rcvd,
                                heals_at,
                                exposed_epochs: orchestrator.blake.vulnerable_epochs(),
                                active_epoch: orchestrator.blake.last_emitted_epoch(),
                            };
                            blake_compromises_that_heal_at
                                .entry(heals_at)
                                .or_default()
                                .push(comp);
                        }
                    }
                }
            }
        }
        orchestrator.key_history_is_consistent();
    }

    let mut a_comp_hist = BTreeMap::<usize, usize>::new();
    let mut b_comp_hist = BTreeMap::<usize, usize>::new();

    for (_ep, cs) in alex_compromises_that_heal_at {
        for c in cs {
            if let Some(active_ep) = epoch_info.get(&c.active_epoch) {
                if active_ep.a_end < c.a_sent {
                    // println!("skip epoch info A1 ep {}", c.active_epoch);
                    continue;
                }
                let symratchet_exposed_a_msgs = active_ep.a_end.saturating_sub(c.a_sent);

                if active_ep.b_end < c.a_rcvd {
                    // println!("skip epoch info A2 ep {}", c.active_epoch);
                    continue;
                }
                let symratchet_exposed_b_msgs = active_ep.b_end.saturating_sub(c.a_rcvd);
                let mut exposed_a = symratchet_exposed_a_msgs;
                let mut exposed_b = symratchet_exposed_b_msgs;
                for ep in c.exposed_epochs {
                    //(c.active_epoch+1)..c.heals_at { // in c.exposed_epochs
                    if let Some(epinf) = epoch_info.get(&ep) {
                        if epinf.a_end >= epinf.a_start && epinf.b_end >= epinf.b_start {
                            exposed_a += epinf.a_end - epinf.a_start;
                            exposed_b += epinf.b_end - epinf.b_start;
                        } else {
                            // println!("sk epoch info: {:?}", epinf);
                        }
                    } else {
                        // println!("No epoch info ({})", ep)
                    }
                }
                a_comp_hist
                    .entry(exposed_a + exposed_b)
                    .and_modify(|count| *count += 1)
                    .or_insert(1);
            }
        }
    }

    for (_ep, cs) in blake_compromises_that_heal_at {
        for c in cs {
            if let Some(active_ep) = epoch_info.get(&c.active_epoch) {
                if active_ep.b_end < c.b_sent {
                    // println!("skip epoch info B1 ep {}", c.active_epoch);
                    continue;
                }
                let symratchet_exposed_b_msgs = active_ep.b_end.saturating_sub(c.b_sent);

                if active_ep.a_end < c.b_rcvd {
                    // println!("skip epoch info B2 ep {} (a_end: {} b_rcvd: {})", c.active_epoch, active_ep.a_end, c.b_rcvd);
                    continue;
                }
                let symratchet_exposed_a_msgs = active_ep.a_end.saturating_sub(c.b_rcvd);
                let mut exposed_b = symratchet_exposed_b_msgs;
                let mut exposed_a = symratchet_exposed_a_msgs;
                for ep in c.exposed_epochs {
                    //(c.active_epoch+1)..c.heals_at { // in c.exposed_epochs
                    if let Some(epinf) = epoch_info.get(&ep) {
                        if epinf.a_end >= epinf.a_start && epinf.b_end >= epinf.b_start {
                            exposed_a += epinf.a_end - epinf.a_start;
                            exposed_b += epinf.b_end - epinf.b_start;
                        }
                    } else {
                        // println!("No epoch info ({})", ep)
                    }
                }
                b_comp_hist
                    .entry(exposed_a + exposed_b)
                    .and_modify(|count| *count += 1)
                    .or_insert(1);
            }
        }
    }

    let max_exposed = *std::cmp::max(
        a_comp_hist.last_key_value().unwrap().0,
        b_comp_hist.last_key_value().unwrap().0,
    );

    let mut hist = Vec::<HealingHistogramEntry>::new();

    for i in 0..=max_exposed {
        hist.push(HealingHistogramEntry {
            num_msgs: i,
            tot_by_a: *a_comp_hist.get(&i).unwrap_or(&0),
            tot_by_b: *b_comp_hist.get(&i).unwrap_or(&0),
        });
    }
    // orchestrator.print_key_history_lengths();
    // orchestrator.print_msg_queue_lengths();

    Ok(hist)
}

pub fn random_balanced<CKA, R>(rng: &mut R) -> Result<(), Error>
where
    CKA: MessagingScka + MessagingCkaVulnerability,
    <CKA as MessagingScka>::CkaOutput: PartialEq + Debug,
    R: CryptoRng,
{
    let mut a_tot = 0;
    let mut b_tot = 0;
    let mut orchestrator = OrchestratorBase::<CKA>::new(rng)?;
    for _i in 0..10000 {
        let rnd: u32 = rng.next_u32();
        let use_alex = rnd & 0x1 != 0;
        let do_receive = rnd & 0x6 != 0;
        let do_send = rnd & 0x8 != 0;
        if do_receive {
            // orchestrator.receive_in_order(use_alex)?;
            orchestrator.receive_all(use_alex)?;
        }
        if do_send {
            orchestrator.send(use_alex, rng)?;
            if use_alex {
                a_tot += 1;
            } else {
                b_tot += 1;
            }
        }
        orchestrator.key_history_is_consistent();
    }
    orchestrator.print_key_history_lengths();
    orchestrator.print_msg_queue_lengths();
    println!("Alex sent {a_tot}  Blake sent {b_tot}");
    Ok(())
}

pub fn random_balanced_out_of_order<CKA, R>(rng: &mut R) -> Result<(), Error>
where
    CKA: MessagingScka + MessagingCkaVulnerability,
    <CKA as MessagingScka>::CkaOutput: PartialEq + Debug,
    R: CryptoRng,
{
    let mut orchestrator = OrchestratorBase::<CKA>::new(rng)?;
    for _i in 0..10000 {
        let rnd = rng.next_u32();
        let use_alex = rnd & 0x1 == 0;
        let do_send = rnd & 0x2 != 0;
        let do_ooo = rnd & 0x4 == 0;
        let rcv_all = rnd & 0xF8 == 0;
        if do_ooo {
            if orchestrator.qlen(use_alex) > 0 {
                orchestrator.receive_at(
                    use_alex,
                    ((rnd >> 8) as usize) % orchestrator.qlen(use_alex),
                )?;
            }
        } else if rcv_all {
            orchestrator.receive_all(use_alex)?;
        } else {
            orchestrator.receive_in_order(use_alex)?;
        }
        if do_send {
            orchestrator.send(use_alex, rng)?;
        }
        orchestrator.key_history_is_consistent();
    }
    orchestrator.print_key_history_lengths();
    orchestrator.print_msg_queue_lengths();
    Ok(())
}

pub fn chaos<CKA, R>(num_ticks: usize, rng: &mut R) -> Result<(), Error>
where
    CKA: MessagingScka + MessagingCkaVulnerability,
    <CKA as MessagingScka>::CkaOutput: PartialEq + Debug,
    R: CryptoRng,
{
    let ooo_prob = 0.7;
    let send_limit = 10;
    let drop_message_prob = 0.1;
    let mut orchestrator = OrchestratorBase::<CKA>::new(rng)?;
    for i in 0..num_ticks {
        let use_alex = if i % 100 < 50 {
            rng.random_bool(0.25)
        } else {
            rng.random_bool(0.75)
        };

        // receive out of order
        if rng.random_bool(ooo_prob) {
            let qlen = orchestrator.qlen(use_alex);
            if qlen > 0 {
                let _received =
                    orchestrator.receive_at(use_alex, rng.next_u32() as usize % qlen)?;
            }
        }
        let num_to_send = rng.next_u32() % send_limit;
        for _ in 0..num_to_send {
            orchestrator.send(use_alex, rng)?;
            if rng.random_bool(drop_message_prob) {
                orchestrator.drop_message_at(use_alex, 0);
            }
        }

        // don't let queue get too big
        loop {
            let qlen = orchestrator.qlen(use_alex);
            if qlen > 20 {
                let _received =
                    orchestrator.receive_at(use_alex, rng.next_u32() as usize % qlen)?;
            } else {
                break;
            }
        }

        orchestrator.key_history_is_consistent();
    }
    orchestrator.print_key_history_lengths();
    orchestrator.print_msg_queue_lengths();
    Ok(())
}
