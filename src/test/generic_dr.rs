// Copyright 2025 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

use rand_core::CryptoRng;

use crate::{chain, EpochSecret, Error};

use super::scka::{Scka, SckaMessage};

pub struct DoubleRatchet<SCKA: Scka> {
    symratchet: chain::Chain,
    asymratchet: SCKA,
}

pub struct Send<SCKA: Scka> {
    pub dr: DoubleRatchet<SCKA>,
    pub msg: SCKA::Message,
    index: u32,
    key: Option<[u8; 32]>,
}

pub fn dr_send<SCKA: Scka, R: CryptoRng>(
    dr: DoubleRatchet<SCKA>,
    rng: &mut R,
) -> Result<Send<SCKA>, Error> {
    let DoubleRatchet {
        asymratchet,
        mut symratchet,
    } = dr;

    let (so, msg, asymratchet) = asymratchet.scka_send(rng)?;

    if let Some((epoch, key)) = so.output_key {
        symratchet.add_epoch(EpochSecret {
            epoch,
            secret: key.to_vec(),
        });
    }
    let (index, msg_key) = symratchet.send_key(so.sending_epoch)?;

    Ok(Send {
        dr: DoubleRatchet {
            asymratchet,
            symratchet,
        },
        msg,
        index,
        key: Some(msg_key.try_into().expect("msg_key is 32B")),
    })
}

pub struct Recv<SCKA: Scka> {
    pub dr: DoubleRatchet<SCKA>,
    key: Option<[u8; 32]>,
}

pub fn dr_recv<SCKA: Scka>(
    dr: DoubleRatchet<SCKA>,
    msg: &SCKA::Message,
    index: u32,
) -> Result<Recv<SCKA>, Error> {
    let DoubleRatchet {
        asymratchet,
        mut symratchet,
    } = dr;
    let (ro, asymratchet) = asymratchet.scka_recv(msg)?;

    if let Some((epoch, key)) = ro.output_key {
        symratchet.add_epoch(EpochSecret {
            epoch,
            secret: key.to_vec(),
        });
    }

    let msg_key = symratchet.recv_key(msg.epoch(), index)?;

    Ok(Recv {
        dr: DoubleRatchet {
            symratchet,
            asymratchet,
        },
        key: Some(msg_key.try_into().expect("msg_key is 32B")),
    })
}

mod test {
    use rand::Rng;
    use rand::TryRngCore;
    use rand_core::OsRng;

    use crate::{
        chain, initial_state, kdf, recv, send,
        test::{scka::Scka, x25519_scka},
        ChainParams, Direction, Error, Params, Secret, SerializedMessage, SerializedState, Version,
    };

    use super::{dr_recv, dr_send, DoubleRatchet};

    #[allow(clippy::type_complexity)]
    fn send_hybrid_message<SCKA: Scka>(
        pq_state: &SerializedState,
        ec_state: DoubleRatchet<SCKA>,
    ) -> Result<
        (
            SerializedState,
            SerializedMessage,
            DoubleRatchet<SCKA>,
            SCKA::Message,
            u32,
            Secret,
        ),
        Error,
    > {
        let mut rng = OsRng.unwrap_err();
        let (pq_send, ec_send) = (send(pq_state, &mut rng)?, dr_send(ec_state, &mut rng)?);

        let key = kdf::hkdf_to_vec(
            &[0u8; 32],
            &[pq_send.key.unwrap_or(vec![]), ec_send.key.unwrap().to_vec()].concat(),
            b"hybrid ratchet merge",
            32,
        );
        Ok((
            pq_send.state,
            pq_send.msg,
            ec_send.dr,
            ec_send.msg,
            ec_send.index,
            key,
        ))
    }

    fn receive_hybrid_message<SCKA: Scka>(
        pq_state: &SerializedState,
        pq_msg: &SerializedMessage,
        ec_state: DoubleRatchet<SCKA>,
        ec_msg: &SCKA::Message,
        ec_idx: u32,
    ) -> Result<(SerializedState, DoubleRatchet<SCKA>, Secret), Error> {
        let (pq_recv, ec_recv) = (recv(pq_state, pq_msg)?, dr_recv(ec_state, ec_msg, ec_idx)?);

        let key = kdf::hkdf_to_vec(
            &[0u8; 32],
            &[pq_recv.key.unwrap_or(vec![]), ec_recv.key.unwrap().to_vec()].concat(),
            b"hybrid ratchet merge",
            32,
        );
        Ok((pq_recv.state, ec_recv.dr, key))
    }

    #[test]
    fn hybrid_ratchet() -> Result<(), Error> {
        let alex_ec_ratchet = x25519_scka::states::States::init_a();
        let alex_ec_chain = chain::Chain::new(
            &[43u8; 32],
            Direction::A2B,
            ChainParams::default().into_pb(),
        )?;

        let alex_ec_state = DoubleRatchet {
            asymratchet: alex_ec_ratchet,
            symratchet: alex_ec_chain,
        };

        let blake_ec_ratchet = x25519_scka::states::States::init_b();
        let blake_ec_chain = chain::Chain::new(
            &[43u8; 32],
            Direction::B2A,
            ChainParams::default().into_pb(),
        )?;

        let blake_ec_state = DoubleRatchet {
            asymratchet: blake_ec_ratchet,
            symratchet: blake_ec_chain,
        };

        let version = Version::V1;

        let alex_pq_state = initial_state(Params {
            version,
            min_version: version,
            direction: Direction::A2B,
            auth_key: &[41u8; 32],
            chain_params: ChainParams::default(),
        })?;
        let blake_pq_state = initial_state(Params {
            version,
            min_version: version,
            direction: Direction::B2A,
            auth_key: &[41u8; 32],
            chain_params: ChainParams::default(),
        })?;

        // Now let's send some messages
        println!("alex send");
        let (alex_pq_state, pq_msg, alex_ec_state, ec_msg, ec_idx, alex_key) =
            send_hybrid_message(&alex_pq_state, alex_ec_state)?;
        println!("blake recv");
        let (blake_pq_state, blake_ec_state, blake_key) =
            receive_hybrid_message(&blake_pq_state, &pq_msg, blake_ec_state, &ec_msg, ec_idx)?;

        assert_eq!(alex_key, blake_key);

        println!("blake send");
        let (mut blake_pq_state, pq_msg, mut blake_ec_state, ec_msg, ec_idx, blake_key) =
            send_hybrid_message(&blake_pq_state, blake_ec_state)?;
        println!("alex recv");
        let (mut alex_pq_state, mut alex_ec_state, alex_key) =
            receive_hybrid_message(&alex_pq_state, &pq_msg, alex_ec_state, &ec_msg, ec_idx)?;

        assert_eq!(alex_key, blake_key);

        // now let's mix it up a little
        let mut rng = OsRng.unwrap_err();
        for _ in 0..1000 {
            let a_send = rng.random_bool(0.5);
            let b_send = rng.random_bool(0.5);
            let a_recv = rng.random_bool(0.7);
            let b_recv = rng.random_bool(0.7);

            if a_send {
                println!("alex send");
                let (pq_state, pq_msg, ec_state, ec_msg, ec_idx, alex_key) =
                    send_hybrid_message(&alex_pq_state, alex_ec_state)?;
                (alex_pq_state, alex_ec_state) = (pq_state, ec_state);
                if b_recv {
                    println!("blake recv");
                    let (pq_state, ec_state, blake_key) = receive_hybrid_message(
                        &blake_pq_state,
                        &pq_msg,
                        blake_ec_state,
                        &ec_msg,
                        ec_idx,
                    )?;

                    (blake_pq_state, blake_ec_state) = (pq_state, ec_state);

                    assert_eq!(alex_key, blake_key);
                }
            }

            if b_send {
                println!("blake send");
                let (pq_state, pq_msg, ec_state, ec_msg, ec_idx, blake_key) =
                    send_hybrid_message(&blake_pq_state, blake_ec_state)?;
                (blake_pq_state, blake_ec_state) = (pq_state, ec_state);
                if a_recv {
                    println!("alex recv");
                    let (pq_state, ec_state, alex_key) = receive_hybrid_message(
                        &alex_pq_state,
                        &pq_msg,
                        alex_ec_state,
                        &ec_msg,
                        ec_idx,
                    )?;

                    (alex_pq_state, alex_ec_state) = (pq_state, ec_state);

                    assert_eq!(alex_key, blake_key);
                }
            }
        }

        Ok(())
    }
}
