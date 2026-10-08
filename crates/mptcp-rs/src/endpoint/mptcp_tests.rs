use super::*;
use crate::tcp::SendBuf;
use crate::wire::tcp_options::{TcpOpt, walk};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use std::time::Duration;

fn open(ep: &mut Endpoint<ChaCha20Rng>) -> ConnectionHandle {
    ep.connect_mptcp(
        Instant::from_nanos(0),
        "10.0.0.1".parse().unwrap(),
        "10.0.0.2:80".parse().unwrap(),
        ConnectConfig::default(),
    )
    .unwrap()
}

fn transmit(ep: &mut Endpoint<ChaCha20Rng>, now: Instant) -> Vec<u8> {
    let mut out = vec![0; 1500];
    let len = ep.poll_transmit(now, &mut out).expect("packet due");
    out.truncate(len);
    out
}

fn mpc(options: &[u8]) -> Vec<&[u8]> {
    walk(options)
        .filter_map(|o| match o.unwrap() {
            TcpOpt::Mptcp(raw) => Some(raw),
            _ => None,
        })
        .collect()
}

#[test]
fn capable_syn_uses_version_one_and_only_h() {
    let mut ep = Endpoint::new(ChaCha20Rng::seed_from_u64(1));
    open(&mut ep);
    let bytes = transmit(&mut ep, Instant::from_nanos(0));
    let syn = packet::parse(&bytes).unwrap();
    assert_eq!(mpc(syn.options), vec![&[30, 4, 1, 1][..]]);
}

use crate::wire::mptcp::{self, CAP_H, MpCapable, MptcpOption};
const PEER_KEY: u64 = 0x1020304050607080;
fn capable(version: u8, flags: u8) -> Vec<u8> {
    let mut out = [0; 40];
    let n = mptcp::encode(
        &MptcpOption::Capable(MpCapable {
            version,
            flags,
            sender_key: Some(PEER_KEY),
            receiver_key: None,
            data_len: None,
            checksum: None,
        }),
        &mut out,
    )
    .unwrap();
    out[..n].to_vec()
}
fn reply(ep: &mut Endpoint<ChaCha20Rng>, syn: &Segment, options: &[u8], ack: SeqNum) {
    let seg = Segment {
        src: syn.dst,
        dst: syn.src,
        seq: SeqNum(5000),
        ack,
        flags: TcpFlags::SYN | TcpFlags::ACK,
        wnd: 1234,
        options,
        payload: &[],
    };
    let mut out = [0; 1500];
    let n = packet::build(&seg, 0, &mut out).unwrap();
    ep.handle_packet(Instant::from_nanos(1), &out[..n]);
}

#[test]
fn keys_repeat_after_lost_third_ack_and_event_follows_emission() {
    let mut ep = Endpoint::new(ChaCha20Rng::seed_from_u64(2));
    let h = open(&mut ep);
    let bytes = transmit(&mut ep, Instant::from_nanos(0));
    let syn = packet::parse(&bytes).unwrap();
    let options = capable(1, CAP_H);
    reply(&mut ep, &syn, &options, syn.seq.wrapping_add(1));
    assert_eq!(ep.poll_event(), None, "third ACK has not been emitted");
    assert!(
        ep.poll_transmit(Instant::from_nanos(1), &mut [0; 20])
            .is_none()
    );
    assert_eq!(
        ep.poll_event(),
        None,
        "small buffer cannot complete handshake"
    );
    let bytes = transmit(&mut ep, Instant::from_nanos(1));
    let ack = packet::parse(&bytes).unwrap();
    let opts = mpc(ack.options);
    assert_eq!(opts.len(), 1);
    assert_eq!(opts[0].len(), 20);
    let MptcpOption::Capable(c) = mptcp::parse(opts[0]).unwrap() else {
        panic!()
    };
    assert!(c.sender_key.is_some());
    assert_eq!(c.receiver_key, Some(PEER_KEY));
    assert_eq!(ep.poll_event(), Some((h, Event::Connected { mptcp: true })));
    // The server missed that ACK and repeats its SYN/ACK. Every response still carries keys.
    for key in [PEER_KEY, PEER_KEY.wrapping_add(1), PEER_KEY] {
        let mut repeated = options.clone();
        repeated[4..12].copy_from_slice(&key.to_be_bytes());
        reply(&mut ep, &syn, &repeated, syn.seq.wrapping_add(1));
        let bytes = transmit(&mut ep, Instant::from_nanos(2));
        assert_eq!(mpc(packet::parse(&bytes).unwrap().options), opts);
        assert_eq!(ep.poll_event(), None);
    }
}

#[test]
fn invalid_synack_option_falls_back_permanently() {
    let good = capable(1, CAP_H);
    let mut cases = vec![
        vec![],
        vec![30, 4, 1, CAP_H],
        vec![30, 12, 1, CAP_H],
        [good.clone(), good.clone()].concat(),
        [good.clone(), vec![99, 1]].concat(),
    ];
    for version in [0, 2, 15] {
        cases.push(capable(version, CAP_H));
    }
    for flags in [0, 0x81, 0x41, 0x02, 0x03, 0x05, 0x09, 0x11] {
        cases.push(capable(1, flags));
    }
    for options in cases {
        let mut ep = Endpoint::new(ChaCha20Rng::seed_from_u64(2));
        let h = open(&mut ep);
        let bytes = transmit(&mut ep, Instant::from_nanos(0));
        let syn = packet::parse(&bytes).unwrap();
        reply(&mut ep, &syn, &options, syn.seq.wrapping_add(1));
        assert_eq!(ep.poll_event(), None);
        let bytes = transmit(&mut ep, Instant::from_nanos(1));
        assert!(mpc(packet::parse(&bytes).unwrap().options).is_empty());
        assert_eq!(
            ep.poll_event(),
            Some((h, Event::Connected { mptcp: false }))
        );
        reply(&mut ep, &syn, &good, syn.seq.wrapping_add(1));
        let bytes = transmit(&mut ep, Instant::from_nanos(2));
        assert!(mpc(packet::parse(&bytes).unwrap().options).is_empty());
        assert_eq!(ep.poll_event(), None);
    }
}

#[test]
fn original_plus_two_capable_syn_retries_then_plain() {
    let mut ep = Endpoint::new(ChaCha20Rng::seed_from_u64(3));
    open(&mut ep);
    let mut now = Instant::from_nanos(0);
    for attempt in 0..6 {
        let bytes = transmit(&mut ep, now);
        let syn = packet::parse(&bytes).unwrap();
        assert_eq!(mpc(syn.options).len(), usize::from(attempt < 3));
        now = ep.poll_timeout().unwrap();
        ep.handle_timeout(now);
    }
}

#[test]
fn syn_timeout_fallback_still_reports_connected_once_after_ack() {
    let mut ep = Endpoint::new(ChaCha20Rng::seed_from_u64(7));
    let h = open(&mut ep);
    let mut now = Instant::from_nanos(0);
    let mut bytes = Vec::new();
    for _ in 0..4 {
        bytes = transmit(&mut ep, now);
        now = ep.poll_timeout().unwrap();
        ep.handle_timeout(now);
    }
    let syn = packet::parse(&bytes).unwrap();
    reply(&mut ep, &syn, &capable(1, CAP_H), syn.seq.wrapping_add(1));
    assert_eq!(ep.poll_event(), None);
    let bytes = transmit(&mut ep, now);
    assert!(mpc(packet::parse(&bytes).unwrap().options).is_empty());
    assert_eq!(
        ep.poll_event(),
        Some((h, Event::Connected { mptcp: false }))
    );
    assert_eq!(ep.poll_event(), None);
}

fn input(ep: &mut Endpoint<ChaCha20Rng>, seg: &Segment) {
    let mut out = [0; 1500];
    let n = packet::build(seg, 0, &mut out).unwrap();
    ep.handle_packet(Instant::from_nanos(2), &out[..n]);
}
fn data_ack(ack: u64) -> Vec<u8> {
    let mut out = [0; 40];
    let n = mptcp::encode(
        &MptcpOption::Dss(mptcp::Dss {
            data_fin: false,
            data_ack: Some(mptcp::DataAck::Ack64(ack)),
            mapping: None,
        }),
        &mut out,
    )
    .unwrap();
    out[..n].to_vec()
}

#[test]
fn confirmation_requires_tcp_acceptable_well_formed_dss() {
    let mut ep = Endpoint::new(ChaCha20Rng::seed_from_u64(8));
    open(&mut ep);
    let bytes = transmit(&mut ep, Instant::from_nanos(0));
    let syn = packet::parse(&bytes).unwrap();
    reply(
        &mut ep,
        &syn,
        &capable(1, CAP_H | mptcp::CAP_C),
        syn.seq.wrapping_add(1),
    );
    let bytes = transmit(&mut ep, Instant::from_nanos(1));
    let ack = packet::parse(&bytes).unwrap();
    let MptcpOption::Capable(keys) = mptcp::parse(mpc(ack.options)[0]).unwrap() else {
        panic!()
    };
    let data_ack = data_ack(
        crate::crypto::key_token_idsn(keys.sender_key.unwrap())
            .1
            .wrapping_add(1),
    );
    let good = Segment {
        src: syn.dst,
        dst: syn.src,
        seq: SeqNum(5001),
        ack: syn.seq.wrapping_add(1),
        flags: TcpFlags::ACK,
        wnd: 1234,
        options: &data_ack,
        payload: &[],
    };
    for bad in [
        Segment {
            seq: SeqNum(4999),
            ..good.clone()
        },
        Segment {
            ack: syn.seq.wrapping_add(100),
            ..good.clone()
        },
        Segment {
            flags: TcpFlags::default(),
            ..good.clone()
        },
    ] {
        input(&mut ep, &bad);
        // Force an ACK even when TCP silently drops a non-ACK.
        reply(&mut ep, &syn, &capable(1, CAP_H), syn.seq.wrapping_add(1));
        let bytes = transmit(&mut ep, Instant::from_nanos(2));
        assert!(matches!(
            mptcp::parse(mpc(packet::parse(&bytes).unwrap().options)[0]),
            Ok(MptcpOption::Capable(_))
        ));
    }
    for opts in [
        vec![30, 12, 0x20, 3],
        [data_ack.clone(), data_ack.clone()].concat(),
        [data_ack.clone(), vec![99, 1]].concat(),
    ] {
        input(
            &mut ep,
            &Segment {
                options: &opts,
                ..good.clone()
            },
        );
        reply(&mut ep, &syn, &capable(1, CAP_H), syn.seq.wrapping_add(1));
        let bytes = transmit(&mut ep, Instant::from_nanos(2));
        assert!(matches!(
            mptcp::parse(mpc(packet::parse(&bytes).unwrap().options)[0]),
            Ok(MptcpOption::Capable(_))
        ));
    }
    input(&mut ep, &good);
    reply(&mut ep, &syn, &capable(1, CAP_H), syn.seq.wrapping_add(1));
    let bytes = transmit(&mut ep, Instant::from_nanos(2));
    let options = mpc(packet::parse(&bytes).unwrap().options);
    let MptcpOption::Dss(dss) = mptcp::parse(options[0]).unwrap() else {
        panic!("expected confirmed DSS")
    };
    assert_eq!(
        dss.data_ack,
        Some(mptcp::DataAck::Ack64(
            crate::crypto::key_token_idsn(PEER_KEY).1.wrapping_add(1)
        ))
    );
}

#[test]
fn synack_installs_dsn_origins_and_unscaled_credit_only_after_tcp_accepts() {
    let mut ep = Endpoint::new(ChaCha20Rng::seed_from_u64(9));
    let h = open(&mut ep);
    let bytes = transmit(&mut ep, Instant::from_nanos(0));
    let syn = packet::parse(&bytes).unwrap();
    let opts = [capable(1, CAP_H), vec![3, 3, 14, 1]].concat();
    reply(&mut ep, &syn, &opts, syn.seq.wrapping_add(2));
    let m = ep.conns[&h].hooks.negotiation.as_ref().unwrap();
    assert_eq!(m.peer_idsn, None);
    assert_eq!(m.send_right_edge, None);
    // Drain the RFC 9293 reset response to the impossible ACK.
    let bytes = transmit(&mut ep, Instant::from_nanos(1));
    assert_eq!(packet::parse(&bytes).unwrap().flags, TcpFlags::RST);
    assert_eq!(ep.poll_event(), None);
    reply(&mut ep, &syn, &opts, syn.seq.wrapping_add(1));
    let bytes = transmit(&mut ep, Instant::from_nanos(1));
    let ack = packet::parse(&bytes).unwrap();
    let MptcpOption::Capable(c) = mptcp::parse(mpc(ack.options)[0]).unwrap() else {
        panic!()
    };
    let m = ep.conns[&h].hooks.negotiation.as_ref().unwrap();
    let (token, idsn) = crate::crypto::key_token_idsn(c.sender_key.unwrap());
    assert_eq!(m.token, token);
    assert_eq!(m.local_idsn, idsn);
    assert_eq!(m.peer_idsn, Some(crate::crypto::key_token_idsn(PEER_KEY).1));
    assert_eq!(m.send_right_edge, Some(idsn.wrapping_add(1 + 1234)));
}

#[test]
fn dss_before_third_ack_does_not_omit_keys() {
    let mut ep = Endpoint::new(ChaCha20Rng::seed_from_u64(12));
    open(&mut ep);
    let bytes = transmit(&mut ep, Instant::from_nanos(0));
    let syn = packet::parse(&bytes).unwrap();
    reply(&mut ep, &syn, &capable(1, CAP_H), syn.seq.wrapping_add(1));
    let dss = data_ack(0);
    input(
        &mut ep,
        &Segment {
            src: syn.dst,
            dst: syn.src,
            seq: SeqNum(5001),
            ack: syn.seq.wrapping_add(1),
            flags: TcpFlags::ACK,
            wnd: 1234,
            options: &dss,
            payload: &[],
        },
    );
    let bytes = transmit(&mut ep, Instant::from_nanos(2));
    assert!(matches!(
        mptcp::parse(mpc(packet::parse(&bytes).unwrap().options)[0]),
        Ok(MptcpOption::Capable(_))
    ));
}

#[test]
fn token_collision_regenerates_key_and_time_wait_reserves_token() {
    let mut ep = Endpoint::new(ChaCha20Rng::seed_from_u64(13));
    let before_open = ep.rng.clone();
    let a = open(&mut ep);
    let token_a = ep.conns[&a].hooks.negotiation.as_ref().unwrap().token;
    let bytes = transmit(&mut ep, Instant::from_nanos(0));
    let syn = packet::parse(&bytes).unwrap();
    reply(&mut ep, &syn, &capable(1, CAP_H), syn.seq.wrapping_add(1));
    transmit(&mut ep, Instant::from_nanos(1));
    ep.poll_event();
    let local_fin = ep.conns[&a].hooks.data.as_ref().unwrap().send.end;
    let peer_fin = ep.conns[&a].hooks.data.as_ref().unwrap().recv.next;
    ep.connection(a).unwrap().close();
    let bytes = transmit(&mut ep, Instant::from_nanos(2));
    assert!(!packet::parse(&bytes).unwrap().flags.contains(TcpFlags::FIN));
    input(
        &mut ep,
        &peer_data(&syn, 5001, &data_ack(local_fin.wrapping_add(1)), &[]),
    );
    let bytes = transmit(&mut ep, Instant::from_nanos(2));
    assert!(packet::parse(&bytes).unwrap().flags.contains(TcpFlags::FIN));
    let opts = fin_option(peer_fin, 0, 1, Some(local_fin.wrapping_add(1)));
    let seg = Segment {
        ack: syn.seq.wrapping_add(2),
        flags: TcpFlags::ACK | TcpFlags::FIN,
        ..peer_data(&syn, 5001, &opts, &[])
    };
    input(&mut ep, &seg);
    let bytes = transmit(&mut ep, Instant::from_nanos(2));
    assert_eq!(
        dack(&packet::parse(&bytes).unwrap()),
        peer_fin.wrapping_add(1)
    );
    ep.handle_timeout(Instant::from_nanos(2));
    assert_eq!(ep.conns[&a].subflows[0].tcb.state(), TcpState::TimeWait);
    assert_eq!(
        ep.poll_event(),
        None,
        "TCP TIME_WAIT is not connection closure"
    );
    // Lost final DATA_ACK: repeat the FIN below the receive window in TIME_WAIT.
    input(&mut ep, &seg);
    let bytes = transmit(&mut ep, Instant::from_nanos(2));
    assert_eq!(
        dack(&packet::parse(&bytes).unwrap()),
        peer_fin.wrapping_add(1)
    );
    input(
        &mut ep,
        &Segment {
            seq: SeqNum(5002),
            flags: TcpFlags::ACK,
            ..seg.clone()
        },
    );
    let bytes = transmit(&mut ep, Instant::from_nanos(2));
    assert_eq!(
        dack(&packet::parse(&bytes).unwrap()),
        peer_fin.wrapping_add(1)
    );
    // Rewind injected randomness: port probing then generates the exact same first key.
    ep.rng = before_open.clone();
    let b = open(&mut ep);
    assert_ne!(
        ep.conns[&b].hooks.negotiation.as_ref().unwrap().token,
        token_a
    );
    ep.connection(b).unwrap().close();
    ep.handle_timeout(Instant::from_nanos(2));
    assert!(!ep.conns.contains_key(&b));
    let deadline = ep.poll_timeout().unwrap();
    assert_eq!(deadline, Instant::from_nanos(2) + Duration::from_secs(120));
    ep.handle_timeout(deadline);
    // The other connection was closed during SYN-SENT; drain its Normal first.
    assert_eq!(
        ep.poll_event(),
        Some((
            b,
            Event::Closed {
                reason: CloseReason::Normal
            }
        ))
    );
    assert_eq!(
        ep.poll_event(),
        Some((
            a,
            Event::Closed {
                reason: CloseReason::Normal
            }
        ))
    );
    assert_eq!(ep.poll_event(), None);
    assert!(!ep.conns.contains_key(&a));
    ep.rng = before_open;
    let c = open(&mut ep);
    assert_eq!(
        ep.conns[&c].hooks.negotiation.as_ref().unwrap().token,
        token_a,
        "final teardown releases the token"
    );
}

#[test]
fn capable_has_priority_over_sack_and_dsack_within_forty_bytes() {
    let mut ep = Endpoint::new(ChaCha20Rng::seed_from_u64(14));
    open(&mut ep);
    let bytes = transmit(&mut ep, Instant::from_nanos(0));
    let syn = packet::parse(&bytes).unwrap();
    let options = [capable(1, CAP_H), vec![4, 2, 1, 1]].concat();
    reply(&mut ep, &syn, &options, syn.seq.wrapping_add(1));
    transmit(&mut ep, Instant::from_nanos(1));
    // Exercise TCP receipt bookkeeping; interpreting MPTCP payload is Step 2.
    for seq in [5010, 5020, 5030, 5030] {
        input(
            &mut ep,
            &Segment {
                src: syn.dst,
                dst: syn.src,
                seq: SeqNum(seq),
                ack: syn.seq.wrapping_add(1),
                flags: TcpFlags::ACK,
                wnd: 1234,
                options: &[],
                payload: b"x",
            },
        );
        let bytes = transmit(&mut ep, Instant::from_nanos(2));
        let ack = packet::parse(&bytes).unwrap();
        let opts: Vec<_> = walk(ack.options).map(Result::unwrap).collect();
        assert!(matches!(opts[0], TcpOpt::Mptcp(raw) if raw.len() == 20));
        let TcpOpt::Sack(blocks) = opts[1] else {
            panic!()
        };
        assert_eq!(&blocks[..4], &seq.to_be_bytes());
        assert!(blocks.len() <= 16);
        assert!(ack.options.len() <= 40);
        assert_eq!(ack.options.len() % 4, 0);
    }
}

#[test]
fn all_synack_flags_and_option_lengths_are_checked() {
    for flags in 0..=255 {
        let mut ep = Endpoint::new(ChaCha20Rng::seed_from_u64(15));
        let h = open(&mut ep);
        let bytes = transmit(&mut ep, Instant::from_nanos(0));
        let syn = packet::parse(&bytes).unwrap();
        reply(&mut ep, &syn, &capable(1, flags), syn.seq.wrapping_add(1));
        let bytes = transmit(&mut ep, Instant::from_nanos(1));
        let valid = flags == CAP_H || flags == CAP_H | mptcp::CAP_C;
        assert_eq!(
            mpc(packet::parse(&bytes).unwrap().options).len(),
            usize::from(valid)
        );
        assert_eq!(
            ep.poll_event(),
            Some((h, Event::Connected { mptcp: valid }))
        );
    }
    for len in 0..=40 {
        if len == 12 {
            continue;
        }
        let mut opts = vec![0; len.max(2)];
        opts[0] = 30;
        opts[1] = len as u8;
        if len >= 4 {
            opts[2] = 1;
            opts[3] = CAP_H;
        }
        let mut ep = Endpoint::new(ChaCha20Rng::seed_from_u64(16));
        let h = open(&mut ep);
        let bytes = transmit(&mut ep, Instant::from_nanos(0));
        let syn = packet::parse(&bytes).unwrap();
        reply(&mut ep, &syn, &opts, syn.seq.wrapping_add(1));
        transmit(&mut ep, Instant::from_nanos(1));
        assert_eq!(
            ep.poll_event(),
            Some((h, Event::Connected { mptcp: false })),
            "length {len}"
        );
    }
}

fn mapping(ssn: u32, dsn: u64, len: u16) -> Vec<u8> {
    let mut out = [0; 40];
    let n = mptcp::encode(
        &MptcpOption::Dss(mptcp::Dss {
            data_fin: false,
            data_ack: None,
            mapping: Some(mptcp::Mapping {
                ssn,
                dsn: mptcp::Dsn::Dsn64(dsn),
                data_len: len,
                checksum: None,
            }),
        }),
        &mut out,
    )
    .unwrap();
    out[..n].to_vec()
}

#[test]
fn dsn_receive_bypasses_ssn_window_and_acks_only_dsn_window_bytes() {
    let mut ep = Endpoint::new(ChaCha20Rng::seed_from_u64(17));
    let h = open(&mut ep);
    let bytes = transmit(&mut ep, Instant::from_nanos(0));
    let syn = packet::parse(&bytes).unwrap();
    reply(&mut ep, &syn, &capable(1, CAP_H), syn.seq.wrapping_add(1));
    transmit(&mut ep, Instant::from_nanos(1));
    let dsn = crate::crypto::key_token_idsn(PEER_KEY).1.wrapping_add(1);
    // A fresh SSN outside the last subflow window carries the in-order connection head.
    let opts = mapping(5_000_000, dsn, 3);
    let seg = Segment {
        src: syn.dst,
        dst: syn.src,
        seq: SeqNum(5_005_000),
        ack: syn.seq.wrapping_add(1),
        flags: TcpFlags::ACK,
        wnd: 1234,
        options: &opts,
        payload: b"abc",
    };
    input(&mut ep, &seg);
    let bytes = transmit(&mut ep, Instant::from_nanos(2));
    let ack = packet::parse(&bytes).unwrap();
    assert_eq!(ack.ack, SeqNum(5001));
    let MptcpOption::Dss(dss) = mptcp::parse(mpc(ack.options)[0]).unwrap() else {
        panic!()
    };
    assert_eq!(
        dss.data_ack,
        Some(mptcp::DataAck::Ack64(dsn.wrapping_add(3)))
    );
    let mut buf = [0; 3];
    assert_eq!(ep.connection(h).unwrap().read(&mut buf), Ok(3));
    assert_eq!(&buf, b"abc");
    // Out-of-DSN-window data at the TCP head cannot advance TCP ACK.
    let opts = mapping(1, dsn.wrapping_add(10_000_000), 3);
    input(
        &mut ep,
        &Segment {
            seq: SeqNum(5001),
            options: &opts,
            ..seg.clone()
        },
    );
    let bytes = transmit(&mut ep, Instant::from_nanos(2));
    assert_eq!(packet::parse(&bytes).unwrap().ack, SeqNum(5001));
}

#[test]
fn unmapped_data_is_tcp_acked_but_not_delivered() {
    let mut ep = Endpoint::new(ChaCha20Rng::seed_from_u64(18));
    let h = open(&mut ep);
    let bytes = transmit(&mut ep, Instant::from_nanos(0));
    let syn = packet::parse(&bytes).unwrap();
    reply(&mut ep, &syn, &capable(1, CAP_H), syn.seq.wrapping_add(1));
    transmit(&mut ep, Instant::from_nanos(1));
    let seg = Segment {
        src: syn.dst,
        dst: syn.src,
        seq: SeqNum(5001),
        ack: syn.seq.wrapping_add(1),
        flags: TcpFlags::ACK,
        wnd: 1234,
        options: &[],
        payload: b"abc",
    };
    input(&mut ep, &seg);
    let bytes = transmit(&mut ep, Instant::from_nanos(2));
    assert_eq!(packet::parse(&bytes).unwrap().ack, SeqNum(5004));
    assert_eq!(
        ep.connection(h).unwrap().read(&mut [0; 3]),
        Err(crate::connection::ReadError::WouldBlock)
    );
}

fn connected_with_capacity(cap: u32) -> (Endpoint<ChaCha20Rng>, ConnectionHandle, Vec<u8>, u64) {
    let mut ep = Endpoint::new(ChaCha20Rng::seed_from_u64(19));
    let h = ep
        .connect_mptcp(
            Instant::from_nanos(0),
            "10.0.0.1".parse().unwrap(),
            "10.0.0.2:80".parse().unwrap(),
            ConnectConfig {
                recv_buffer: cap,
                ..ConnectConfig::default()
            },
        )
        .unwrap();
    let bytes = transmit(&mut ep, Instant::from_nanos(0));
    let syn = packet::parse(&bytes).unwrap();
    reply(&mut ep, &syn, &capable(1, CAP_H), syn.seq.wrapping_add(1));
    transmit(&mut ep, Instant::from_nanos(1));
    ep.poll_event();
    (
        ep,
        h,
        bytes,
        crate::crypto::key_token_idsn(PEER_KEY).1.wrapping_add(1),
    )
}
fn peer_data<'a>(syn: &Segment, seq: u32, options: &'a [u8], payload: &'a [u8]) -> Segment<'a> {
    Segment {
        src: syn.dst,
        dst: syn.src,
        seq: SeqNum(seq),
        ack: syn.seq.wrapping_add(1),
        flags: TcpFlags::ACK,
        wnd: 1234,
        options,
        payload,
    }
}
fn dack(seg: &Segment) -> u64 {
    let MptcpOption::Dss(d) = mptcp::parse(mpc(seg.options)[0]).unwrap() else {
        panic!()
    };
    let Some(mptcp::DataAck::Ack64(a)) = d.data_ack else {
        panic!()
    };
    a
}

#[test]
fn data_held_beyond_memory_advances_tcp_ack_only() {
    let (mut ep, h, bytes, dsn) = connected_with_capacity(4);
    let syn = packet::parse(&bytes).unwrap();
    ep.conns
        .get_mut(&h)
        .unwrap()
        .hooks
        .data
        .as_mut()
        .unwrap()
        .recv
        .right_edge = dsn.wrapping_add(6);
    input(
        &mut ep,
        &peer_data(&syn, 5001, &mapping(1, dsn, 4), b"abcd"),
    );
    let bytes = transmit(&mut ep, Instant::from_nanos(2));
    assert_eq!(packet::parse(&bytes).unwrap().ack, SeqNum(5005));
    input(
        &mut ep,
        &peer_data(&syn, 5005, &mapping(5, dsn.wrapping_add(4), 2), b"ef"),
    );
    let bytes = transmit(&mut ep, Instant::from_nanos(2));
    let ack = packet::parse(&bytes).unwrap();
    assert_eq!(ack.ack, SeqNum(5007));
    assert_eq!(dack(&ack), dsn.wrapping_add(4));
    let mut out = [0; 8];
    assert_eq!(ep.connection(h).unwrap().read(&mut out), Ok(4));
    assert_eq!(&out[..4], b"abcd");
    // The held copy was delivered by the read; a reinjection on new SSNs is a duplicate.
    input(
        &mut ep,
        &peer_data(&syn, 5007, &mapping(7, dsn.wrapping_add(4), 2), b"ef"),
    );
    let bytes = transmit(&mut ep, Instant::from_nanos(2));
    assert_eq!(dack(&packet::parse(&bytes).unwrap()), dsn.wrapping_add(6));
    assert_eq!(ep.connection(h).unwrap().read(&mut out), Ok(2));
    assert_eq!(&out[..2], b"ef");
}

#[test]
fn conflicting_mapping_resets_only_after_tcp_validity() {
    let (mut ep, h, bytes, dsn) = connected_with_capacity(64);
    let syn = packet::parse(&bytes).unwrap();
    input(&mut ep, &peer_data(&syn, 5001, &mapping(1, dsn, 4), b"ab"));
    transmit(&mut ep, Instant::from_nanos(2));
    let opts = mapping(1, dsn.wrapping_add(1), 4);
    let mut seg = peer_data(&syn, 5003, &opts, b"cd");
    seg.ack = syn.seq.wrapping_add(2); // ACKs unsent sequence space
    input(&mut ep, &seg);
    transmit(&mut ep, Instant::from_nanos(2));
    assert_eq!(ep.poll_event(), None);
    seg.ack = syn.seq.wrapping_add(1);
    input(&mut ep, &seg);
    let bytes = transmit(&mut ep, Instant::from_nanos(2));
    assert!(packet::parse(&bytes).unwrap().flags.contains(TcpFlags::RST));
    assert_eq!(ep.poll_event(), None);
    assert_eq!(ep.conns[&h].subflows[0].tcb.state(), TcpState::Closed);
    assert!(ep.conns[&h].hooks.retained());
}

#[test]
fn unmapped_byte_bound_resets_subflow() {
    let (mut ep, h, bytes, _) = connected_with_capacity(4);
    let syn = packet::parse(&bytes).unwrap();
    input(&mut ep, &peer_data(&syn, 5001, &[], b"abcd"));
    transmit(&mut ep, Instant::from_nanos(2));
    assert_eq!(ep.poll_event(), None);
    input(&mut ep, &peer_data(&syn, 5005, &[], b"e"));
    let bytes = transmit(&mut ep, Instant::from_nanos(2));
    assert!(packet::parse(&bytes).unwrap().flags.contains(TcpFlags::RST));
    assert_eq!(ep.poll_event(), None);
    assert_eq!(ep.conns[&h].subflows[0].tcb.state(), TcpState::Closed);
    assert!(ep.conns[&h].hooks.retained());
}

#[test]
fn initial_mpc_and_equivalent_dss_deliver_once() {
    let (mut ep, h, bytes, dsn) = connected_with_capacity(64);
    let syn = packet::parse(&bytes).unwrap();
    let local_key = {
        reply(&mut ep, &syn, &capable(1, CAP_H), syn.seq.wrapping_add(1));
        let ack = transmit(&mut ep, Instant::from_nanos(2));
        let packet = packet::parse(&ack).unwrap();
        let MptcpOption::Capable(c) = mptcp::parse(mpc(packet.options)[0]).unwrap() else {
            panic!()
        };
        c.sender_key.unwrap()
    };
    let mut opts = [0; 40];
    let n = mptcp::encode(
        &MptcpOption::Capable(MpCapable {
            version: 1,
            flags: CAP_H,
            sender_key: Some(PEER_KEY),
            receiver_key: Some(local_key),
            data_len: Some(4),
            checksum: None,
        }),
        &mut opts,
    )
    .unwrap();
    input(&mut ep, &peer_data(&syn, 5001, &opts[..n], b"ab"));
    transmit(&mut ep, Instant::from_nanos(2));
    input(
        &mut ep,
        &peer_data(&syn, 5001, &mapping(1, dsn, 4), b"abcd"),
    );
    let bytes = transmit(&mut ep, Instant::from_nanos(2));
    assert_eq!(dack(&packet::parse(&bytes).unwrap()), dsn.wrapping_add(4));
    let mut out = [0; 8];
    assert_eq!(ep.connection(h).unwrap().read(&mut out), Ok(4));
    assert_eq!(&out[..4], b"abcd");
    assert_eq!(
        ep.connection(h).unwrap().read(&mut out),
        Err(crate::connection::ReadError::WouldBlock)
    );
}

#[test]
fn ack32_promotion_releases_connection_store_only_with_tcp_ack() {
    let (mut ep, h, bytes, _) = connected_with_capacity(64);
    let syn = packet::parse(&bytes).unwrap();
    let c = ep.conns.get_mut(&h).unwrap();
    let d = c.hooks.data.as_mut().unwrap();
    // Install a wrapped send origin before any application data.
    d.send = crate::mptcp::data::SendStore::new(u64::MAX - 1, 4);
    assert_eq!(d.send.write(b"abcd"), 4);
    assert!(d.send.assign(&mut c.subflows[0].mp.tx, u64::MAX - 1, 4));
    let bytes = transmit(&mut ep, Instant::from_nanos(2));
    assert_eq!(packet::parse(&bytes).unwrap().payload, b"abcd");
    let mut opts = [0; 40];
    let n = mptcp::encode(
        &MptcpOption::Dss(mptcp::Dss {
            data_fin: false,
            data_ack: Some(mptcp::DataAck::Ack32(2)),
            mapping: None,
        }),
        &mut opts,
    )
    .unwrap();
    input(&mut ep, &peer_data(&syn, 5001, &opts[..n], &[]));
    let d = ep.conns.get_mut(&h).unwrap().hooks.data.as_mut().unwrap();
    assert_eq!(d.send.una, 2);
    assert_eq!(d.send.write(b"e"), 0);
    let mut ack = peer_data(&syn, 5001, &[], &[]);
    ack.ack = syn.seq.wrapping_add(5);
    input(&mut ep, &ack);
    let d = ep.conns.get_mut(&h).unwrap().hooks.data.as_mut().unwrap();
    assert_eq!(d.send.write(b"e"), 1);
}

#[test]
fn queued_handshake_bytes_move_into_connection_store() {
    let mut ep = Endpoint::new(ChaCha20Rng::seed_from_u64(20));
    let h = open(&mut ep);
    assert_eq!(ep.connection(h).unwrap().write(b"abcd"), Ok(4));
    let bytes = transmit(&mut ep, Instant::from_nanos(0));
    let syn = packet::parse(&bytes).unwrap();
    reply(&mut ep, &syn, &capable(1, CAP_H), syn.seq.wrapping_add(1));
    let d = ep.conns[&h].hooks.data.as_ref().unwrap();
    assert_eq!(d.send.end.wrapping_sub(d.send.una), 4);
}

#[test]
fn peer_dsn_signed_boundary_preserves_tcp_and_data_ack_rules() {
    for offset in [i64::MAX, i64::MAX - 1, i64::MIN, i64::MIN + 1] {
        let (mut ep, h, bytes, dsn) = connected_with_capacity(64);
        let syn = packet::parse(&bytes).unwrap();
        let opts = mapping(1, dsn.wrapping_add_signed(offset), 2);
        input(&mut ep, &peer_data(&syn, 5001, &opts, b"ab"));
        let bytes = transmit(&mut ep, Instant::from_nanos(2));
        let ack = packet::parse(&bytes).unwrap();
        assert_eq!(ack.ack, SeqNum(if offset > 0 { 5001 } else { 5003 }));
        assert_eq!(dack(&ack), dsn);
        assert_eq!(
            ep.connection(h).unwrap().read(&mut [0; 2]),
            Err(crate::connection::ReadError::WouldBlock)
        );
    }
}

#[test]
fn automatic_initial_mapping_reserves_dss_and_retransmits_immutable_mapping() {
    let (mut ep, h, syn_bytes, _) = connected_with_capacity(64);
    let syn = packet::parse(&syn_bytes).unwrap();
    ep.connection(h).unwrap().write(&vec![7; 1600]).unwrap();
    let bytes = transmit(&mut ep, Instant::from_nanos(2));
    let seg = packet::parse(&bytes).unwrap();
    assert_eq!(seg.payload.len(), 508); // default peer MSS 536 minus DSS layout 28
    assert_eq!(seg.options.len(), 24);
    let MptcpOption::Capable(c) = mptcp::parse(mpc(seg.options)[0]).unwrap() else {
        panic!()
    };
    assert_eq!(c.data_len, Some(1016)); // two full segments fit initial unscaled 1234 credit
    let origin = ep.conns[&h].hooks.data.as_ref().unwrap().send.una;
    let bytes = transmit(&mut ep, Instant::from_nanos(2));
    assert_eq!(packet::parse(&bytes).unwrap().payload.len(), 508);
    assert!(
        ep.poll_transmit(Instant::from_nanos(2), &mut [0; 1500])
            .is_none()
    );
    // Partial TCP ACK confirms DSS; retransmission must retain full original coordinates.
    let mut options = [0; 40];
    let n = mptcp::encode(
        &MptcpOption::Dss(mptcp::Dss {
            data_fin: false,
            data_ack: Some(mptcp::DataAck::Ack64(origin)),
            mapping: None,
        }),
        &mut options,
    )
    .unwrap();
    let mut ack = peer_data(&syn, 5001, &options[..n], &[]);
    ack.ack = syn.seq.wrapping_add(101);
    input(&mut ep, &ack);
    ep.handle_timeout(Instant::from_nanos(2_000_000_000));
    let bytes = transmit(&mut ep, Instant::from_nanos(2_000_000_000));
    let seg = packet::parse(&bytes).unwrap();
    assert_eq!(seg.seq, syn.seq.wrapping_add(101));
    let MptcpOption::Dss(dss) = mptcp::parse(mpc(seg.options)[0]).unwrap() else {
        panic!()
    };
    let mapping = dss.mapping.unwrap();
    assert_eq!(mapping.ssn, 1);
    assert_eq!(mapping.dsn, mptcp::Dsn::Dsn64(origin));
    assert_eq!(mapping.data_len, 1016);
    assert_eq!(seg.options.len(), 28);
}

#[test]
fn shared_window_read_reopens_and_peer_window_requires_valid_data_ack() {
    let (mut ep, h, syn_bytes, dsn) = connected_with_capacity(8);
    let syn = packet::parse(&syn_bytes).unwrap();
    input(
        &mut ep,
        &peer_data(&syn, 5001, &mapping(1, dsn, 8), b"abcdefgh"),
    );
    let bytes = transmit(&mut ep, Instant::from_nanos(2));
    assert_eq!(packet::parse(&bytes).unwrap().wnd, 0);
    ep.connection(h).unwrap().read(&mut [0; 8]).unwrap();
    let bytes = transmit(&mut ep, Instant::from_nanos(2));
    assert_eq!(packet::parse(&bytes).unwrap().wnd, 8);
    input(
        &mut ep,
        &peer_data(&syn, 5009, &mapping(9, dsn.wrapping_add(8), 1), b"i"),
    );
    assert_eq!(ep.connection(h).unwrap().read(&mut [0; 1]), Ok(1));
    let origin = ep.conns[&h].hooks.data.as_ref().unwrap().send.una;
    for (ack, window, expected) in [
        (origin.wrapping_sub(1), 6000, 1234),
        (origin.wrapping_add(1), 6000, 1234),
        (origin, 5000, 5000),
        (origin, 1, 5000),
    ] {
        let mut options = [0; 40];
        let n = mptcp::encode(
            &MptcpOption::Dss(mptcp::Dss {
                data_fin: false,
                data_ack: Some(mptcp::DataAck::Ack64(ack)),
                mapping: None,
            }),
            &mut options,
        )
        .unwrap();
        let mut seg = peer_data(&syn, 5010, &options[..n], &[]);
        seg.wnd = window;
        input(&mut ep, &seg);
        assert_eq!(
            ep.conns[&h]
                .hooks
                .negotiation
                .as_ref()
                .unwrap()
                .send_right_edge,
            Some(origin.wrapping_add(expected))
        );
    }
}

#[test]
fn connection_window_persists_without_assigned_bytes_and_recovers_lost_update() {
    let (mut ep, h, syn_bytes, _) = connected_with_capacity(64);
    let syn = packet::parse(&syn_bytes).unwrap();
    ep.connection(h).unwrap().set_nodelay(true);
    ep.connection(h).unwrap().write(&vec![3; 1235]).unwrap();
    let origin = ep.conns[&h].hooks.data.as_ref().unwrap().send.una;
    for _ in 0..3 {
        transmit(&mut ep, Instant::from_nanos(2));
    }
    let next = origin.wrapping_add(1234);
    let mut options = [0; 40];
    let n = mptcp::encode(
        &MptcpOption::Dss(mptcp::Dss {
            data_fin: false,
            data_ack: Some(mptcp::DataAck::Ack64(next)),
            mapping: None,
        }),
        &mut options,
    )
    .unwrap();
    let mut ack = peer_data(&syn, 5001, &options[..n], &[]);
    ack.ack = syn.seq.wrapping_add(1235);
    ack.wnd = 0;
    input(&mut ep, &ack);
    assert!(
        ep.poll_transmit(Instant::from_nanos(3), &mut [0; 1500])
            .is_none()
    );
    // Even repeated answers for longer than R2 must not close the connection.
    for sec in [2, 5, 10, 20, 40, 80, 140, 200] {
        let now = Instant::from_nanos(sec * 1_000_000_000);
        ep.handle_timeout(now);
        let bytes = transmit(&mut ep, now);
        let probe = packet::parse(&bytes).unwrap();
        assert_eq!(probe.seq, syn.seq.wrapping_add(1234));
        assert!(probe.payload.is_empty());
        assert_eq!(ep.conns[&h].hooks.data.as_ref().unwrap().send.next, next);
        let mut wire = [0; 1500];
        let len = packet::build(&ack, 0, &mut wire).unwrap();
        ep.handle_packet(now, &wire[..len]);
        ep.poll_transmit(now, &mut wire);
    }
    // The initial reopening ACK was lost; a response to a later probe supplies the credit.
    ack.wnd = 16;
    let mut wire = [0; 1500];
    let len = packet::build(&ack, 0, &mut wire).unwrap();
    ep.handle_packet(Instant::from_nanos(201_000_000_000), &wire[..len]);
    let bytes = transmit(&mut ep, Instant::from_nanos(201_000_000_000));
    assert_eq!(packet::parse(&bytes).unwrap().payload, &[3]);
}

#[test]
fn write_boundary_does_not_bypass_sender_sws_and_timeout_releases_whole_window() {
    let (mut ep, h, syn_bytes, _) = connected_with_capacity(64);
    let syn = packet::parse(&syn_bytes).unwrap();
    ep.connection(h).unwrap().write(&[1; 8]).unwrap();
    ep.connection(h).unwrap().write(&[2; 1000]).unwrap();
    let mut ack = peer_data(&syn, 5001, &[], &[]);
    ack.wnd = 100;
    input(&mut ep, &ack);
    assert!(
        ep.poll_transmit(Instant::from_nanos(2), &mut [0; 1500])
            .is_none()
    );
    let deadline = ep
        .poll_timeout()
        .expect("SWS override for unassigned bytes");
    assert!(deadline <= Instant::from_nanos(500_000_002));
    ep.handle_timeout(deadline);
    let bytes = transmit(&mut ep, deadline);
    // One segment fills the window across the write boundary.
    assert_eq!(
        packet::parse(&bytes).unwrap().payload,
        [[1; 8].as_slice(), &[2; 92]].concat()
    );
}

#[test]
fn padded_dss_and_sack_fit_tiny_mss_and_mapping_splits() {
    for mss in [28u16, 29, 40, 64] {
        let mut ep = Endpoint::new(ChaCha20Rng::seed_from_u64(21));
        let h = open(&mut ep);
        let bytes = transmit(&mut ep, Instant::from_nanos(0));
        let syn = packet::parse(&bytes).unwrap();
        let mut opts = capable(1, CAP_H);
        let mut tcp = [0; 8];
        let n = crate::wire::tcp_options::write_mss(&mut tcp, mss);
        opts.extend_from_slice(&tcp[..n]);
        let n = crate::wire::tcp_options::write_sack_permitted(&mut tcp);
        opts.extend_from_slice(&tcp[..n]);
        reply(&mut ep, &syn, &opts, syn.seq.wrapping_add(1));
        transmit(&mut ep, Instant::from_nanos(1));
        ep.connection(h).unwrap().set_nodelay(true);
        ep.connection(h).unwrap().write(&[3; 100]).unwrap();
        let dsn = crate::crypto::key_token_idsn(PEER_KEY).1.wrapping_add(1);
        input(
            &mut ep,
            &peer_data(&syn, 5003, &mapping(3, dsn.wrapping_add(2), 2), b"ab"),
        );
        // The ACK first reports the out-of-order receipt, then data coexists with SACK.
        transmit(&mut ep, Instant::from_nanos(2));
        let mut wire = [0; 1500];
        let n = ep.poll_transmit(Instant::from_nanos(2), &mut wire);
        if mss == 28 {
            assert!(n.is_none());
            continue;
        }
        let seg = packet::parse(&wire[..n.unwrap()]).unwrap();
        assert!(seg.options.len() + seg.payload.len() <= usize::from(mss));
        assert_eq!(seg.options.len(), if mss > 40 { 40 } else { 28 });
        if mss > 40 {
            assert!(walk(seg.options).any(|o| matches!(o, Ok(TcpOpt::Sack(_)))));
        }
        let MptcpOption::Dss(d) = mptcp::parse(mpc(seg.options)[0]).unwrap() else {
            panic!()
        };
        assert!(usize::from(d.mapping.unwrap().data_len) >= seg.payload.len());
    }
}

#[test]
fn shared_window_scaling_rounds_only_to_preserve_edge() {
    let mut recv = crate::mptcp::data::RecvAssembler::new(1000, 10, 4);
    assert_eq!(recv.window_offer(2, 536), 3); // 10-byte promise rounds to 12
    recv.window_sent(3, 2);
    recv.accept(1000, b"abcdefghij");
    assert_eq!(recv.free(), 0);
    assert_eq!(recv.window_offer(2, 536), 1); // preserves promise despite memory pressure
    recv.window_sent(1, 2);
    assert_eq!(recv.right_edge, 1014);
    recv.read(&mut [0; 10]);
    assert_eq!(recv.window_offer(2, 536), 2); // floor(10 / 4), sufficient to move edge
    recv.window_sent(2, 2);
    assert_eq!(recv.right_edge, 1018);
}

/// Data-Level Length of the DSS mapping or MP_CAPABLE data form a segment carries.
fn mapped_len(seg: &Segment) -> u16 {
    match mptcp::parse(mpc(seg.options)[0]).unwrap() {
        MptcpOption::Dss(d) => d.mapping.unwrap().data_len,
        MptcpOption::Capable(c) => c.data_len.unwrap(),
        _ => panic!("no mapping"),
    }
}

#[test]
fn short_write_joins_the_next_write_in_a_full_segment_at_once() {
    let (mut ep, h, syn_bytes, _) = connected_with_capacity(64);
    let syn = packet::parse(&syn_bytes).unwrap();
    ep.connection(h).unwrap().write(&[1; 8]).unwrap();
    ep.connection(h).unwrap().write(&[2; 2000]).unwrap();
    let mut ack = peer_data(&syn, 5001, &[], &[]);
    ack.wnd = 1000;
    input(&mut ep, &ack);
    // A full segment is sendable (RFC 9293 §3.8.6.2.1 (1)): no SWS override wait.
    let bytes = transmit(&mut ep, Instant::from_nanos(2));
    let seg = packet::parse(&bytes).unwrap();
    assert_eq!(seg.payload, [[1; 8].as_slice(), &[2; 500]].concat());
    assert_eq!(mapped_len(&seg), 508, "one mapping spans both writes");
}

/// Cumulative payload octets sent after each 20 ms round of a bulk transfer written in 64 KiB
/// pieces (as the TUN client does), the peer acknowledging every segment through a 4 MiB
/// window. `mptcp = false` answers the SYN without MP_CAPABLE: the plain-TCP path.
fn bulk_rounds(mptcp: bool, rounds: u64) -> Vec<u64> {
    let mut ep = Endpoint::new(ChaCha20Rng::seed_from_u64(26));
    let h = open(&mut ep);
    let syn_bytes = transmit(&mut ep, Instant::from_nanos(0));
    let syn = packet::parse(&syn_bytes).unwrap();
    let mut opts = if mptcp { capable(1, CAP_H) } else { Vec::new() };
    let mut o = [0; 4];
    let n = crate::wire::tcp_options::write_mss(&mut o, 1460);
    opts.extend_from_slice(&o[..n]);
    let n = crate::wire::tcp_options::write_ws(&mut o, 7);
    opts.extend_from_slice(&o[..n]);
    reply(&mut ep, &syn, &opts, syn.seq.wrapping_add(1));
    transmit(&mut ep, Instant::from_nanos(1));
    let data_base = ep.conns[&h].hooks.data.as_ref().map(|d| d.send.una);
    assert_eq!(data_base.is_some(), mptcp);
    let chunk = [5; 65536];
    for _ in 0..6 {
        assert_eq!(ep.connection(h).unwrap().write(&chunk), Ok(chunk.len()));
    }
    let (mut sent, mut cumulative) = (0, Vec::new());
    for round in 0..rounds {
        let now = Instant::from_nanos(1 + round * 20_000_000);
        let mut ends = Vec::new();
        let mut out = [0; 1500];
        while let Some(n) = ep.poll_transmit(now, &mut out) {
            let seg = packet::parse(&out[..n]).unwrap();
            sent += seg.payload.len() as u64;
            ends.push(seg.seq.wrapping_add(seg.payload.len() as u32));
        }
        cumulative.push(sent);
        for end in ends {
            let options = data_base.map_or_else(Vec::new, |base| {
                data_ack(base.wrapping_add(u64::from(end.0.wrapping_sub(syn.seq.0) - 1)))
            });
            let ack = Segment {
                ack: end,
                wnd: 32768,
                ..peer_data(&syn, 5001, &options, &[])
            };
            let mut wire = [0; 1500];
            let n = packet::build(&ack, 0, &mut wire).unwrap();
            ep.handle_packet(now, &wire[..n]);
        }
    }
    cumulative
}

#[test]
fn bulk_send_across_write_boundaries_keeps_pace_with_plain_tcp() {
    // A mapping may cover several application writes: the sub-MSS tail of one 64 KiB write is
    // not a short segment while the next write is queued behind it (RFC 9293 §3.8.6.2.1 (1)),
    // so the sender never idles for the SWS override timer, and its window grows like TCP's.
    let plain = bulk_rounds(false, 8);
    let mptcp = bulk_rounds(true, 8);
    for (round, (p, m)) in plain.iter().zip(&mptcp).enumerate() {
        assert!(
            m + 1460 * (round as u64 + 1) >= *p,
            "round {round}: MPTCP {mptcp:?} vs plain {plain:?}"
        );
    }
}

#[test]
fn signaling_acks_do_not_trigger_fast_retransmit_but_dss_duplicates_do() {
    let (mut ep, h, syn_bytes, _) = connected_with_capacity(64);
    let syn = packet::parse(&syn_bytes).unwrap();
    ep.connection(h).unwrap().write(&[8; 100]).unwrap();
    transmit(&mut ep, Instant::from_nanos(2));
    let origin = ep.conns[&h].hooks.data.as_ref().unwrap().send.una;
    for _ in 0..4 {
        input(&mut ep, &peer_data(&syn, 5001, &capable(1, CAP_H), &[]));
        assert!(
            ep.poll_transmit(Instant::from_nanos(2), &mut [0; 1500])
                .is_none()
        );
    }
    let mut options = [0; 40];
    let n = mptcp::encode(
        &MptcpOption::Dss(mptcp::Dss {
            data_fin: false,
            data_ack: Some(mptcp::DataAck::Ack64(origin)),
            mapping: None,
        }),
        &mut options,
    )
    .unwrap();
    for _ in 0..2 {
        input(&mut ep, &peer_data(&syn, 5001, &options[..n], &[]));
        assert!(
            ep.poll_transmit(Instant::from_nanos(2), &mut [0; 1500])
                .is_none()
        );
    }
    input(&mut ep, &peer_data(&syn, 5001, &options[..n], &[]));
    let bytes = transmit(&mut ep, Instant::from_nanos(2));
    let seg = packet::parse(&bytes).unwrap();
    assert_eq!(seg.seq, syn.seq.wrapping_add(1));
    assert_eq!(seg.payload, &[8; 100]);
}

#[test]
fn syn_credit_is_unscaled_then_data_ack_window_uses_negotiated_scale() {
    let mut ep = Endpoint::new(ChaCha20Rng::seed_from_u64(22));
    let h = open(&mut ep);
    let bytes = transmit(&mut ep, Instant::from_nanos(0));
    let syn = packet::parse(&bytes).unwrap();
    let mut opts = capable(1, CAP_H);
    let mut ws = [0; 4];
    let n = crate::wire::tcp_options::write_ws(&mut ws, 3);
    opts.extend_from_slice(&ws[..n]);
    reply(&mut ep, &syn, &opts, syn.seq.wrapping_add(1));
    transmit(&mut ep, Instant::from_nanos(1));
    let origin = ep.conns[&h].hooks.data.as_ref().unwrap().send.una;
    assert_eq!(
        ep.conns[&h]
            .hooks
            .negotiation
            .as_ref()
            .unwrap()
            .send_right_edge,
        Some(origin.wrapping_add(1234))
    );
    let mut options = [0; 40];
    let n = mptcp::encode(
        &MptcpOption::Dss(mptcp::Dss {
            data_fin: false,
            data_ack: Some(mptcp::DataAck::Ack64(origin)),
            mapping: None,
        }),
        &mut options,
    )
    .unwrap();
    input(&mut ep, &peer_data(&syn, 5001, &options[..n], &[]));
    assert_eq!(
        ep.conns[&h]
            .hooks
            .negotiation
            .as_ref()
            .unwrap()
            .send_right_edge,
        Some(origin.wrapping_add(1234 << 3))
    );
    // A much larger window without DATA_ACK cannot change the connection edge.
    let mut ack = peer_data(&syn, 5001, &[], &[]);
    ack.wnd = 65535;
    input(&mut ep, &ack);
    assert_eq!(
        ep.conns[&h]
            .hooks
            .negotiation
            .as_ref()
            .unwrap()
            .send_right_edge,
        Some(origin.wrapping_add(1234 << 3))
    );
}

#[test]
fn dsack_coexists_with_covering_mapping_when_remainder_is_split() {
    let mut ep = Endpoint::new(ChaCha20Rng::seed_from_u64(23));
    let h = open(&mut ep);
    let syn_bytes = transmit(&mut ep, Instant::from_nanos(0));
    let syn = packet::parse(&syn_bytes).unwrap();
    let mut opts = capable(1, CAP_H);
    let mut sack = [0; 4];
    let n = crate::wire::tcp_options::write_sack_permitted(&mut sack);
    opts.extend_from_slice(&sack[..n]);
    reply(&mut ep, &syn, &opts, syn.seq.wrapping_add(1));
    transmit(&mut ep, Instant::from_nanos(1));
    let dsn = crate::crypto::key_token_idsn(PEER_KEY).1.wrapping_add(1);
    let map = mapping(1, dsn, 2);
    input(&mut ep, &peer_data(&syn, 5001, &map, b"ab"));
    transmit(&mut ep, Instant::from_nanos(2));
    ep.connection(h).unwrap().write(&[4; 1600]).unwrap();
    let bytes = transmit(&mut ep, Instant::from_nanos(2));
    assert_eq!(packet::parse(&bytes).unwrap().payload.len(), 508);
    input(&mut ep, &peer_data(&syn, 5001, &map, b"ab"));
    let bytes = transmit(&mut ep, Instant::from_nanos(2));
    let seg = packet::parse(&bytes).unwrap();
    assert_eq!(seg.options.len(), 40);
    assert_eq!(seg.payload.len(), 496);
    assert!(walk(seg.options).any(|o| matches!(o, Ok(TcpOpt::Sack(_)))));
    let MptcpOption::Dss(d) = mptcp::parse(mpc(seg.options)[0]).unwrap() else {
        panic!()
    };
    let map = d.mapping.unwrap();
    assert_eq!(map.ssn, 1);
    assert_eq!(map.data_len, 1016);
}

#[test]
fn read_advertises_shared_edge_after_sws_threshold_even_with_open_window() {
    let (mut ep, h, syn_bytes, dsn) = connected_with_capacity(10000);
    let syn = packet::parse(&syn_bytes).unwrap();
    input(
        &mut ep,
        &peer_data(&syn, 5001, &mapping(1, dsn, 1000), &[1; 1000]),
    );
    transmit(&mut ep, Instant::from_nanos(2));
    ep.connection(h).unwrap().read(&mut [0; 1000]).unwrap();
    let bytes = transmit(&mut ep, Instant::from_nanos(2));
    assert_eq!(packet::parse(&bytes).unwrap().wnd, 10000);
}

#[test]
fn sws_partial_budget_covers_the_run_across_write_boundaries() {
    let mut ep = Endpoint::new(ChaCha20Rng::seed_from_u64(24));
    let h = open(&mut ep);
    let syn_bytes = transmit(&mut ep, Instant::from_nanos(0));
    let syn = packet::parse(&syn_bytes).unwrap();
    let mut opts = capable(1, CAP_H);
    let mut mss = [0; 4];
    let n = crate::wire::tcp_options::write_mss(&mut mss, 1000);
    opts.extend_from_slice(&mss[..n]);
    reply(&mut ep, &syn, &opts, syn.seq.wrapping_add(1));
    transmit(&mut ep, Instant::from_nanos(1));
    ep.connection(h).unwrap().write(&[1; 8]).unwrap();
    ep.connection(h).unwrap().write(&[2; 2000]).unwrap();
    let origin = ep.conns[&h].hooks.data.as_ref().unwrap().send.next;
    let mut ack = peer_data(&syn, 5001, &[], &[]);
    ack.wnd = 500;
    input(&mut ep, &ack);
    assert!(
        ep.poll_transmit(Instant::from_nanos(2), &mut [0; 1500])
            .is_none()
    );
    assert_eq!(
        ep.conns[&h].hooks.data.as_ref().unwrap().send.next,
        origin,
        "nothing assigned before it can send"
    );
    // Half the largest window (RFC 9293 §3.8.6.2.1 (3)) goes as one segment and one mapping.
    ack.wnd = 800;
    input(&mut ep, &ack);
    let bytes = transmit(&mut ep, Instant::from_nanos(2));
    let seg = packet::parse(&bytes).unwrap();
    assert_eq!(seg.payload, [[1; 8].as_slice(), &[2; 792]].concat());
    assert_eq!(mapped_len(&seg), 800);
}

#[test]
fn connection_probe_demand_does_not_block_already_credited_mapping() {
    let mut ep = Endpoint::new(ChaCha20Rng::seed_from_u64(25));
    let h = open(&mut ep);
    let syn_bytes = transmit(&mut ep, Instant::from_nanos(0));
    let syn = packet::parse(&syn_bytes).unwrap();
    let mut opts = capable(1, CAP_H);
    let mut mss = [0; 4];
    let n = crate::wire::tcp_options::write_mss(&mut mss, 645);
    opts.extend_from_slice(&mss[..n]);
    reply(&mut ep, &syn, &opts, syn.seq.wrapping_add(1));
    transmit(&mut ep, Instant::from_nanos(1));
    ep.connection(h).unwrap().write(&[7; 2000]).unwrap();
    let origin = ep.conns[&h].hooks.data.as_ref().unwrap().send.next;
    let bytes = transmit(&mut ep, Instant::from_nanos(2));
    assert_eq!(packet::parse(&bytes).unwrap().payload.len(), 617);
    assert_eq!(
        ep.conns[&h].hooks.data.as_ref().unwrap().send.next,
        origin.wrapping_add(1234)
    );
    // The first segment is acknowledged before the second is polled. No TCP bytes remain
    // in flight, but the second half of this mapping already owns connection credit.
    let mut opts = [0; 40];
    let n = mptcp::encode(
        &MptcpOption::Dss(mptcp::Dss {
            data_fin: false,
            data_ack: Some(mptcp::DataAck::Ack64(origin.wrapping_add(617))),
            mapping: None,
        }),
        &mut opts,
    )
    .unwrap();
    let mut ack = peer_data(&syn, 5001, &opts[..n], &[]);
    ack.ack = syn.seq.wrapping_add(618);
    ack.wnd = 617;
    input(&mut ep, &ack);
    let bytes = transmit(&mut ep, Instant::from_nanos(3));
    let seg = packet::parse(&bytes).unwrap();
    assert_eq!(seg.seq, syn.seq.wrapping_add(618));
    assert_eq!(seg.payload, &[7; 617]);
    let MptcpOption::Dss(dss) = mptcp::parse(mpc(seg.options)[0]).unwrap() else {
        panic!()
    };
    assert_eq!(dss.mapping.unwrap().data_len, 1234);
    assert_eq!(
        ep.conns[&h].hooks.data.as_ref().unwrap().send.next,
        origin.wrapping_add(1234)
    );
}

#[test]
fn tcp_acked_without_data_ack_reinjects_with_new_ssn_and_backoff() {
    let (mut ep, h, syn, _) = connected_with_capacity(64);
    let syn = packet::parse(&syn).unwrap();
    ep.connection(h).unwrap().write(b"lost").unwrap();
    let first = transmit(&mut ep, Instant::from_nanos(2));
    let first = packet::parse(&first).unwrap();
    let head = ep.conns[&h].hooks.data.as_ref().unwrap().send.una;
    let options = data_ack(head); // TCP received it, DSN assembler discarded it.
    let mut ack = peer_data(&syn, 5001, &options, &[]);
    ack.ack = first.seq.wrapping_add(4);
    input(&mut ep, &ack);
    let deadline = ep.poll_timeout().expect("connection recovery timer");
    ep.handle_timeout(deadline);
    let retry = transmit(&mut ep, deadline);
    let retry = packet::parse(&retry).unwrap();
    assert_eq!(retry.seq, first.seq.wrapping_add(4));
    assert_eq!(retry.payload, b"lost");
    let MptcpOption::Dss(d) = mptcp::parse(mpc(retry.options)[0]).unwrap() else {
        panic!()
    };
    assert_eq!(d.mapping.unwrap().dsn, mptcp::Dsn::Dsn64(head));
    assert!(ep.poll_transmit(deadline, &mut [0; 1500]).is_none());
    ack.ack = retry.seq.wrapping_add(4);
    let mut bytes = [0; 1500];
    let n = packet::build(&ack, 0, &mut bytes).unwrap();
    ep.handle_packet(deadline, &bytes[..n]);
    let second = ep.poll_timeout().unwrap();
    assert!(second - deadline >= std::time::Duration::from_secs(2));
    ep.handle_timeout(second);
    let retry = transmit(&mut ep, second);
    assert_eq!(packet::parse(&retry).unwrap().payload, b"lost");
}

#[test]
fn lost_data_ack_falls_back_once_preserving_both_streams() {
    let (mut ep, h, syn, peer_dsn) = connected_with_capacity(64);
    let syn = packet::parse(&syn).unwrap();
    let opts = mapping(1, peer_dsn, 3);
    input(&mut ep, &peer_data(&syn, 5001, &opts, b"old"));
    transmit(&mut ep, Instant::from_nanos(2));
    ep.connection(h).unwrap().write(b"first").unwrap();
    let sent = transmit(&mut ep, Instant::from_nanos(3));
    let sent = packet::parse(&sent).unwrap();
    ep.connection(h).unwrap().write(b"queued").unwrap();
    let mut ack = peer_data(&syn, 5004, &[], b"new");
    ack.ack = sent.seq.wrapping_add(5);
    input(&mut ep, &ack);
    assert_eq!(
        ep.conns[&h].hooks.negotiation.as_ref().unwrap().state,
        crate::mptcp::State::FellBack
    );
    assert!(
        ep.poll_transmit(Instant::from_nanos(4), &mut [0; 20])
            .is_none()
    );
    let final_dss = transmit(&mut ep, Instant::from_nanos(4));
    let final_dss = packet::parse(&final_dss).unwrap();
    let MptcpOption::Dss(dss) = mptcp::parse(mpc(final_dss.options)[0]).unwrap() else {
        panic!()
    };
    assert_eq!(dss.mapping.unwrap().data_len, 0);
    assert_eq!(dss.data_ack, None);
    let queued = transmit(&mut ep, Instant::from_nanos(4));
    let queued = packet::parse(&queued).unwrap();
    assert_eq!(queued.seq, sent.seq.wrapping_add(5));
    assert_eq!(queued.payload, b"queued");
    assert!(mpc(queued.options).is_empty());
    let mut out = [0; 20];
    assert_eq!(ep.connection(h).unwrap().read(&mut out), Ok(6));
    assert_eq!(&out[..6], b"oldnew");
}

#[test]
fn data_mapping_confirmation_is_distinct_from_receiving_peer_dss() {
    let (mut ep, h, syn, _) = connected_with_capacity(64);
    let syn = packet::parse(&syn).unwrap();
    ep.connection(h).unwrap().write(b"first").unwrap();
    let sent = transmit(&mut ep, Instant::from_nanos(2));
    let sent = packet::parse(&sent).unwrap();
    let head = ep.conns[&h].hooks.data.as_ref().unwrap().send.una;
    let options = data_ack(head + 5);
    let mut ack = peer_data(&syn, 5001, &options, &[]);
    ack.ack = sent.seq.wrapping_add(5);
    input(&mut ep, &ack);
    ep.connection(h).unwrap().write(b"second").unwrap();
    let second = transmit(&mut ep, Instant::from_nanos(3));
    ack.ack = packet::parse(&second).unwrap().seq.wrapping_add(6);
    ack.options = &[];
    input(&mut ep, &ack);
    assert_ne!(
        ep.conns[&h].hooks.negotiation.as_ref().unwrap().state,
        crate::mptcp::State::FellBack
    );
}

#[test]
fn fallback_plain_tcp_does_not_ack_discarded_receive_bytes() {
    let (mut ep, h, syn, dsn) = connected_with_capacity(4);
    let syn = packet::parse(&syn).unwrap();
    let inf = mapping(1, dsn, 0);
    input(&mut ep, &peer_data(&syn, 5001, &inf, b"ab"));
    transmit(&mut ep, Instant::from_nanos(2));
    // Earlier rounding can advertise more than the remaining memory.
    ep.conns
        .get_mut(&h)
        .unwrap()
        .hooks
        .data
        .as_mut()
        .unwrap()
        .recv
        .right_edge = dsn + 8;
    input(&mut ep, &peer_data(&syn, 5003, &[], b"cdef"));
    let ack = transmit(&mut ep, Instant::from_nanos(3));
    assert_eq!(packet::parse(&ack).unwrap().ack, SeqNum(5005));
    let mut out = [0; 4];
    assert_eq!(ep.connection(h).unwrap().read(&mut out), Ok(4));
    assert_eq!(&out, b"abcd");
    input(&mut ep, &peer_data(&syn, 5005, &[], b"ef"));
    assert_eq!(ep.connection(h).unwrap().read(&mut out), Ok(2));
    assert_eq!(&out[..2], b"ef");
}

#[test]
fn fallback_close_drains_unassigned_bytes_before_fin() {
    let (mut ep, h, syn, dsn) = connected_with_capacity(64);
    let syn = packet::parse(&syn).unwrap();
    let inf = mapping(1, dsn, 0);
    input(&mut ep, &peer_data(&syn, 5001, &inf, &[]));
    transmit(&mut ep, Instant::from_nanos(2));
    ep.connection(h).unwrap().write(b"last").unwrap();
    ep.connection(h).unwrap().close();
    let data = transmit(&mut ep, Instant::from_nanos(3));
    let data = packet::parse(&data).unwrap();
    assert_eq!(data.payload, b"last");
    let fin = if data.flags.contains(TcpFlags::FIN) {
        data.seq.wrapping_add(4)
    } else {
        let fin = transmit(&mut ep, Instant::from_nanos(3));
        let fin = packet::parse(&fin).unwrap();
        assert!(fin.flags.contains(TcpFlags::FIN));
        fin.seq
    };
    assert_eq!(fin, syn.seq.wrapping_add(5));
}

#[test]
fn malformed_and_stale_acks_cannot_trigger_or_confirm_fallback() {
    for options in [vec![99, 1], [data_ack(u64::MAX), vec![99, 1]].concat()] {
        let (mut ep, h, syn, _) = connected_with_capacity(64);
        let syn = packet::parse(&syn).unwrap();
        ep.connection(h).unwrap().write(b"abc").unwrap();
        let sent = transmit(&mut ep, Instant::from_nanos(2));
        let sent = packet::parse(&sent).unwrap();
        let mut ack = peer_data(&syn, 5001, &[], &[]);
        ack.ack = sent.seq.wrapping_add(4); // unsent byte
        input(&mut ep, &ack);
        assert_ne!(
            ep.conns[&h].hooks.negotiation.as_ref().unwrap().state,
            crate::mptcp::State::FellBack
        );
        ack.ack = sent.seq.wrapping_add(1);
        ack.options = &options;
        input(&mut ep, &ack); // TCP advances, malformed MPTCP cannot mutate state
        assert_ne!(
            ep.conns[&h].hooks.negotiation.as_ref().unwrap().state,
            crate::mptcp::State::FellBack
        );
        ack.ack = sent.seq;
        ack.options = &[];
        input(&mut ep, &ack);
        assert_ne!(
            ep.conns[&h].hooks.negotiation.as_ref().unwrap().state,
            crate::mptcp::State::FellBack
        );
        ack.ack = sent.seq.wrapping_add(3);
        input(&mut ep, &ack);
        assert_eq!(ep.poll_event(), Some((h, Event::FellBack)));
        let final_dss = transmit(&mut ep, Instant::from_nanos(3));
        assert_eq!(mpc(packet::parse(&final_dss).unwrap().options).len(), 1);
        input(&mut ep, &ack);
        assert_eq!(ep.poll_event(), None);
    }
}

#[test]
fn received_infinite_mapping_is_permanent_and_keeps_inflight_send() {
    let (mut ep, h, syn, peer_dsn) = connected_with_capacity(64);
    let syn = packet::parse(&syn).unwrap();
    ep.connection(h).unwrap().write(b"outstanding").unwrap();
    let sent = transmit(&mut ep, Instant::from_nanos(2));
    let sent = packet::parse(&sent).unwrap();
    let inf = mapping(1, peer_dsn, 0);
    input(&mut ep, &peer_data(&syn, 5001, &inf, b"reply"));
    assert_eq!(ep.poll_event(), Some((h, Event::FellBack)));
    let out = transmit(&mut ep, Instant::from_nanos(3));
    assert_eq!(mpc(packet::parse(&out).unwrap().options).len(), 1);
    input(&mut ep, &peer_data(&syn, 5001, &inf, b"reply"));
    let out = transmit(&mut ep, Instant::from_nanos(3));
    assert!(mpc(packet::parse(&out).unwrap().options).is_empty());
    assert_eq!(ep.poll_event(), None);
    let at = ep.poll_timeout().unwrap();
    ep.handle_timeout(at);
    let retrans = transmit(&mut ep, at);
    let retrans = packet::parse(&retrans).unwrap();
    assert_eq!(retrans.seq, sent.seq);
    assert_eq!(retrans.payload, b"outstanding");
    assert!(mpc(retrans.options).is_empty());
    let mut ack = peer_data(&syn, 5006, &[], &[]);
    ack.ack = sent.seq.wrapping_add(11);
    input(&mut ep, &ack);
    assert_eq!(
        ep.conns[&h].hooks.data.as_ref().unwrap().send.una,
        ep.conns[&h].hooks.data.as_ref().unwrap().send.next
    );
    assert_eq!(ep.poll_timeout(), None);
    let mut out = [0; 5];
    assert_eq!(ep.connection(h).unwrap().read(&mut out), Ok(5));
    assert_eq!(&out, b"reply");
}

#[test]
fn invalid_data_ack_does_not_confirm_mapping() {
    let (mut ep, h, syn, _) = connected_with_capacity(64);
    let syn = packet::parse(&syn).unwrap();
    ep.connection(h).unwrap().write(b"abc").unwrap();
    let sent = transmit(&mut ep, Instant::from_nanos(2));
    let sent = packet::parse(&sent).unwrap();
    let head = ep.conns[&h].hooks.data.as_ref().unwrap().send.una;
    let opts = data_ack(head + 100);
    let mut ack = peer_data(&syn, 5001, &opts, &[]);
    ack.ack = sent.seq.wrapping_add(1);
    input(&mut ep, &ack);
    ack.options = &[];
    ack.ack = sent.seq.wrapping_add(3);
    input(&mut ep, &ack);
    assert_eq!(ep.poll_event(), Some((h, Event::FellBack)));
}

#[test]
fn recovery_reevaluates_head_and_cancels_after_data_ack() {
    let (mut ep, h, syn, _) = connected_with_capacity(64);
    let syn = packet::parse(&syn).unwrap();
    ep.connection(h).unwrap().write(b"abcd").unwrap();
    let sent = transmit(&mut ep, Instant::from_nanos(2));
    let sent = packet::parse(&sent).unwrap();
    let head = ep.conns[&h].hooks.data.as_ref().unwrap().send.una;
    let opts = data_ack(head);
    let mut ack = peer_data(&syn, 5001, &opts, &[]);
    ack.ack = sent.seq.wrapping_add(4);
    input(&mut ep, &ack);
    let old = ep.poll_timeout().unwrap();
    let opts = data_ack(head + 2);
    ack.options = &opts;
    let now = Instant::from_nanos(500_000_000);
    let mut bytes = [0; 1500];
    let n = packet::build(&ack, 0, &mut bytes).unwrap();
    ep.handle_packet(now, &bytes[..n]);
    let new = ep.poll_timeout().unwrap();
    assert!(new > old);
    ep.handle_timeout(old);
    assert!(ep.poll_transmit(old, &mut bytes).is_none());
    ep.handle_timeout(new);
    let retry = transmit(&mut ep, new);
    let retry = packet::parse(&retry).unwrap();
    assert_eq!(retry.payload, b"cd");
    let MptcpOption::Dss(d) = mptcp::parse(mpc(retry.options)[0]).unwrap() else {
        panic!()
    };
    assert_eq!(d.mapping.unwrap().dsn, mptcp::Dsn::Dsn64(head + 2));
    let opts = data_ack(head + 4);
    ack.options = &opts;
    ack.ack = retry.seq.wrapping_add(2);
    let n = packet::build(&ack, 0, &mut bytes).unwrap();
    ep.handle_packet(new, &bytes[..n]);
    assert_eq!(ep.poll_timeout(), None);
}

#[test]
fn reinjection_respects_zero_tcp_window_and_deduplicates_live_copy() {
    let (mut ep, h, syn, _) = connected_with_capacity(64);
    let syn = packet::parse(&syn).unwrap();
    ep.connection(h).unwrap().write(b"data").unwrap();
    let sent = transmit(&mut ep, Instant::from_nanos(2));
    let sent = packet::parse(&sent).unwrap();
    let head = ep.conns[&h].hooks.data.as_ref().unwrap().send.una;
    let opts = data_ack(head);
    let mut ack = peer_data(&syn, 5001, &opts, &[]);
    ack.ack = sent.seq.wrapping_add(4);
    ack.wnd = 0;
    input(&mut ep, &ack);
    let at = ep.poll_timeout().unwrap();
    ep.handle_timeout(at);
    assert!(ep.poll_transmit(at, &mut [0; 1500]).is_none());
    assert_eq!(ep.conns[&h].subflows[0].mp.tx.assigned_end(), 5);
    ack.wnd = 1234;
    let mut bytes = [0; 1500];
    let n = packet::build(&ack, 0, &mut bytes).unwrap();
    ep.handle_packet(at, &bytes[..n]);
    let retry = transmit(&mut ep, at);
    let retry = packet::parse(&retry).unwrap();
    assert_eq!(retry.seq, sent.seq.wrapping_add(4));
    // Live copy remains the only copy; its own TCP RTO reuses the same SSN.
    let at = ep.poll_timeout().unwrap();
    ep.handle_timeout(at);
    let retrans = transmit(&mut ep, at);
    assert_eq!(packet::parse(&retrans).unwrap().seq, retry.seq);
    assert_eq!(ep.conns[&h].subflows[0].mp.tx.assigned_end(), 9);
}

#[test]
fn infinite_receive_mapping_tracks_ssn_wrap() {
    use crate::tcp::SegmentHooks;
    let (mut ep, h, syn, dsn) = connected_with_capacity(64);
    let syn = packet::parse(&syn).unwrap();
    input(&mut ep, &peer_data(&syn, 5001, &mapping(1, dsn, 0), &[]));
    let c = ep.conns.get_mut(&h).unwrap();
    let hooks = &mut crate::mptcp::SubflowHooks {
        conn: &mut c.hooks,
        sf: &mut c.subflows[0].mp,
    };
    // Skip stored payload while simulating bounded successive TCP receipt advances.
    for offset in [0x7000_0000u64, 0xe000_0000, 0x1_5000_0000] {
        let next = dsn.wrapping_add(offset);
        let recv = &mut hooks.conn.data.as_mut().unwrap().recv;
        recv.next = next;
        recv.right_edge = next.wrapping_add(64);
        hooks.receipt_advanced((offset as u32).wrapping_add(1));
        let ssn = (offset as u32).wrapping_add(1);
        assert_eq!(hooks.receive_data(ssn, ssn, b"x"), vec![0..1]);
        assert_eq!(hooks.conn.read(&mut [0; 1]), 1);
    }
}

#[test]
fn corrected_data_ack_confirms_already_tcp_acked_mapping() {
    for corrected in [true, false] {
        let (mut ep, h, syn, _) = connected_with_capacity(64);
        let syn = packet::parse(&syn).unwrap();
        ep.connection(h).unwrap().write(b"abc").unwrap();
        let sent = transmit(&mut ep, Instant::from_nanos(2));
        let sent = packet::parse(&sent).unwrap();
        let head = ep.conns[&h].hooks.data.as_ref().unwrap().send.una;
        let invalid = data_ack(head.wrapping_add(100));
        let mut ack = peer_data(&syn, 5001, &invalid, &[]);
        ack.ack = sent.seq.wrapping_add(3);
        input(&mut ep, &ack);
        assert!(ep.conns[&h].subflows[0].mp.tx.mapping(1).is_none());
        let valid = data_ack(head.wrapping_add(3));
        ack.options = &valid;
        if !corrected {
            ack.ack = sent.seq;
        } // Old SYN-only ACK cannot confirm data.
        input(&mut ep, &ack);
        ep.connection(h).unwrap().write(b"def").unwrap();
        let next = transmit(&mut ep, Instant::from_nanos(3));
        ack.ack = packet::parse(&next).unwrap().seq.wrapping_add(3);
        ack.options = &[];
        input(&mut ep, &ack);
        assert_eq!(
            ep.poll_event(),
            if corrected {
                None
            } else {
                Some((h, Event::FellBack))
            }
        );
    }
}

#[test]
fn current_tcp_ack_without_data_ack_falls_back_after_invalid_data_ack() {
    let (mut ep, h, syn, _) = connected_with_capacity(64);
    let syn = packet::parse(&syn).unwrap();
    ep.connection(h).unwrap().write(b"abc").unwrap();
    let sent = transmit(&mut ep, Instant::from_nanos(2));
    let sent = packet::parse(&sent).unwrap();
    let head = ep.conns[&h].hooks.data.as_ref().unwrap().send.una;
    let invalid = data_ack(head.wrapping_add(100));
    let mut ack = peer_data(&syn, 5001, &invalid, &[]);
    ack.ack = sent.seq.wrapping_add(3);
    input(&mut ep, &ack);
    assert_eq!(ep.poll_event(), None);
    assert!(ep.poll_timeout().is_some());
    ack.options = &[];
    for stale in [sent.seq, sent.seq.wrapping_add(2)] {
        ack.ack = stale;
        input(&mut ep, &ack);
        assert_eq!(ep.poll_event(), None);
    }
    ack.ack = sent.seq.wrapping_add(3);
    input(&mut ep, &ack);
    assert_eq!(ep.poll_event(), Some((h, Event::FellBack)));
    assert_eq!(ep.poll_timeout(), None);
    let final_dss = transmit(&mut ep, Instant::from_nanos(3));
    let final_dss = packet::parse(&final_dss).unwrap();
    let MptcpOption::Dss(dss) = mptcp::parse(mpc(final_dss.options)[0]).unwrap() else {
        panic!()
    };
    assert_eq!(dss.mapping.unwrap().data_len, 0);
    assert!(final_dss.payload.is_empty());
    input(&mut ep, &ack);
    assert_eq!(ep.poll_event(), None);
    assert!(
        ep.poll_transmit(Instant::from_nanos(3), &mut [0; 1500])
            .is_none()
    );
}

fn fin_option(dsn: u64, ssn: u32, len: u16, ack: Option<u64>) -> Vec<u8> {
    let mut out = [0; 40];
    let n = mptcp::encode(
        &MptcpOption::Dss(mptcp::Dss {
            data_fin: true,
            data_ack: ack.map(mptcp::DataAck::Ack64),
            mapping: Some(mptcp::Mapping {
                dsn: mptcp::Dsn::Dsn64(dsn),
                ssn,
                data_len: len,
                checksum: None,
            }),
        }),
        &mut out,
    )
    .unwrap();
    out[..n].to_vec()
}

#[test]
fn standalone_data_fin_is_immediately_acked_and_half_closes_data_only() {
    let (mut ep, h, syn, dsn) = connected_with_capacity(4096);
    let syn = packet::parse(&syn).unwrap();
    input(
        &mut ep,
        &peer_data(&syn, 5001, &fin_option(dsn, 0, 1, None), &[]),
    );
    let packet = transmit(&mut ep, Instant::from_nanos(2));
    let ack = packet::parse(&packet).unwrap();
    assert_eq!(ack.ack, SeqNum(5001));
    assert_eq!(dack(&ack), dsn.wrapping_add(1));
    assert_eq!(ep.connection(h).unwrap().read(&mut [0; 1]), Ok(0));
    assert_eq!(ep.connection(h).unwrap().write(b"reply"), Ok(5));
}

#[test]
fn local_data_fin_is_standalone_and_tcp_fin_waits_for_data_ack() {
    let (mut ep, h, syn, _) = connected_with_capacity(4096);
    let syn = packet::parse(&syn).unwrap();
    let fin_dsn = ep
        .connection(h)
        .unwrap()
        .hooks
        .data
        .as_ref()
        .unwrap()
        .send
        .end;
    ep.connection(h).unwrap().close();
    let bytes = transmit(&mut ep, Instant::from_nanos(3));
    let fin = packet::parse(&bytes).unwrap();
    assert!(!fin.flags.contains(TcpFlags::FIN));
    let MptcpOption::Dss(d) = mptcp::parse(mpc(fin.options)[0]).unwrap() else {
        panic!()
    };
    assert!(d.data_fin);
    assert_eq!(d.mapping.unwrap().ssn, 0);
    assert_eq!(d.mapping.unwrap().data_len, 1);
    input(
        &mut ep,
        &peer_data(&syn, 5001, &data_ack(fin_dsn.wrapping_add(1)), &[]),
    );
    let bytes = transmit(&mut ep, Instant::from_nanos(4));
    assert!(packet::parse(&bytes).unwrap().flags.contains(TcpFlags::FIN));
}

#[test]
fn fastclose_valid_key_closes_once_on_ack_or_rst_after_tcp_validation() {
    for flags in [TcpFlags::ACK, TcpFlags::RST] {
        for valid in [false, true] {
            let (mut ep, h, syn, _) = connected_with_capacity(4096);
            let syn = packet::parse(&syn).unwrap();
            let key_packet = {
                // PreConfirmed ACK repeats the local key.
                reply(&mut ep, &syn, &capable(1, CAP_H), syn.seq.wrapping_add(1));
                transmit(&mut ep, Instant::from_nanos(2))
            };
            let MptcpOption::Capable(keys) =
                mptcp::parse(mpc(packet::parse(&key_packet).unwrap().options)[0]).unwrap()
            else {
                panic!()
            };
            let mut opts = [0; 40];
            let n = mptcp::encode(
                &MptcpOption::FastClose {
                    receiver_key: keys.sender_key.unwrap() ^ u64::from(!valid),
                },
                &mut opts,
            )
            .unwrap();
            let seg = Segment {
                flags,
                ..peer_data(&syn, 5001, &opts[..n], &[])
            };
            for bad in [
                Segment {
                    seq: SeqNum(999_999),
                    ..seg.clone()
                },
                Segment {
                    seq: SeqNum(999_999),
                    payload: b"x",
                    ..seg.clone()
                },
            ] {
                input(&mut ep, &bad);
                assert_eq!(ep.poll_event(), None);
            }
            if flags == TcpFlags::ACK {
                input(
                    &mut ep,
                    &Segment {
                        ack: syn.seq.wrapping_add(100),
                        ..seg.clone()
                    },
                );
                assert_eq!(ep.poll_event(), None);
            }
            input(&mut ep, &seg);
            if valid {
                assert_eq!(
                    ep.poll_event(),
                    Some((
                        h,
                        Event::Closed {
                            reason: CloseReason::Reset
                        }
                    ))
                );
                let bytes = transmit(&mut ep, Instant::from_nanos(3));
                assert!(packet::parse(&bytes).unwrap().flags.contains(TcpFlags::RST));
                input(&mut ep, &seg);
                assert_eq!(ep.poll_event(), None);
            } else {
                assert_eq!(ep.poll_event(), None);
            }
        }
    }
}

#[test]
fn ordinary_rst_keeps_data_until_no_subflow_timeout() {
    let (mut ep, h, syn, _) = connected_with_capacity(4096);
    let syn = packet::parse(&syn).unwrap();
    ep.connection(h).unwrap().write(b"retained").unwrap();
    transmit(&mut ep, Instant::from_nanos(2));
    input(
        &mut ep,
        &Segment {
            flags: TcpFlags::RST,
            ..peer_data(&syn, 5001, &[], &[])
        },
    );
    assert_eq!(ep.poll_event(), None);
    ep.handle_timeout(Instant::from_nanos(3));
    assert!(ep.connection(h).is_some());
    assert_eq!(
        ep.connection(h).unwrap().read(&mut [0; 1]),
        Err(crate::connection::ReadError::WouldBlock)
    );
    let deadline = ep.poll_timeout().unwrap();
    assert_eq!(deadline, Instant::from_nanos(2) + Duration::from_secs(60));
    ep.handle_timeout(deadline);
    assert_eq!(
        ep.poll_event(),
        Some((
            h,
            Event::Closed {
                reason: CloseReason::Timeout
            }
        ))
    );
    assert_eq!(ep.poll_event(), None);
    assert!(ep.connection(h).is_none());
}

#[test]
fn combined_tcp_and_data_fin_allows_reply_and_local_close() {
    let (mut ep, h, syn, dsn) = connected_with_capacity(4096);
    let syn = packet::parse(&syn).unwrap();
    let opts = fin_option(dsn, 0, 1, None);
    input(
        &mut ep,
        &Segment {
            flags: TcpFlags::ACK | TcpFlags::FIN,
            ..peer_data(&syn, 5001, &opts, &[])
        },
    );
    transmit(&mut ep, Instant::from_nanos(2));
    assert_eq!(ep.connection(h).unwrap().read(&mut [0; 1]), Ok(0));
    ep.connection(h).unwrap().write(b"reply").unwrap();
    ep.connection(h).unwrap().close();
    let bytes = transmit(&mut ep, Instant::from_nanos(3));
    let seg = packet::parse(&bytes).unwrap();
    assert_eq!(seg.payload, b"reply");
    let MptcpOption::Dss(d) = mptcp::parse(mpc(seg.options)[0]).unwrap() else {
        panic!()
    };
    assert!(d.data_fin);
    assert_eq!(d.mapping.unwrap().data_len, 6);
    assert!(!seg.flags.contains(TcpFlags::FIN));
}

#[test]
fn data_fin_retry_backs_off_without_consuming_tcp_sequence_space() {
    let (mut ep, h, _, _) = connected_with_capacity(4096);
    ep.connection(h).unwrap().close();
    let first = transmit(&mut ep, Instant::from_nanos(2));
    let first = packet::parse(&first).unwrap();
    let mut previous = Instant::from_nanos(2);
    for interval in [1, 2, 4, 8] {
        let at = ep.poll_timeout().unwrap();
        assert_eq!(at - previous, Duration::from_secs(interval));
        ep.handle_timeout(at);
        let bytes = transmit(&mut ep, at);
        let retry = packet::parse(&bytes).unwrap();
        assert_eq!(retry.seq, first.seq);
        assert_eq!(retry.options, first.options);
        previous = at;
    }
}

#[test]
fn attached_data_fin_waits_for_dsn_hole_and_reads_before_eof() {
    let (mut ep, h, syn, dsn) = connected_with_capacity(4096);
    let syn = packet::parse(&syn).unwrap();
    input(
        &mut ep,
        &peer_data(
            &syn,
            5003,
            &fin_option(dsn.wrapping_add(2), 3, 3, None),
            b"cd",
        ),
    );
    let bytes = transmit(&mut ep, Instant::from_nanos(2));
    assert_eq!(dack(&packet::parse(&bytes).unwrap()), dsn);
    assert_eq!(
        ep.connection(h).unwrap().read(&mut [0; 4]),
        Err(crate::connection::ReadError::WouldBlock)
    );
    input(&mut ep, &peer_data(&syn, 5001, &mapping(1, dsn, 2), b"ab"));
    let bytes = transmit(&mut ep, Instant::from_nanos(3));
    assert_eq!(dack(&packet::parse(&bytes).unwrap()), dsn.wrapping_add(5));
    let mut out = [0; 4];
    assert_eq!(ep.connection(h).unwrap().read(&mut out), Ok(4));
    assert_eq!(&out, b"abcd");
    assert_eq!(ep.connection(h).unwrap().read(&mut out), Ok(0));
}

#[test]
fn malformed_or_out_of_window_data_fin_does_not_close_or_fall_back() {
    for (ssn, len, offset, payload) in [
        (1, 1, 0, &b""[..]),
        (0, 0, 0, &b""[..]),
        (0, 1, 4096, &b""[..]),
        (1, 2, 0, &b""[..]),
    ] {
        let (mut ep, h, syn, dsn) = connected_with_capacity(4096);
        let syn = packet::parse(&syn).unwrap();
        input(
            &mut ep,
            &peer_data(
                &syn,
                5001,
                &fin_option(dsn.wrapping_add(offset), ssn, len, None),
                payload,
            ),
        );
        assert!(ep.conns[&h].hooks.active());
        assert_eq!(
            ep.connection(h).unwrap().read(&mut [0; 1]),
            Err(crate::connection::ReadError::WouldBlock)
        );
        assert_eq!(ep.conns[&h].hooks.data.as_ref().unwrap().recv.next, dsn);
    }
}

#[test]
fn bare_tcp_fin_retires_subflow_without_data_eof_or_new_assignments() {
    let (mut ep, h, syn, _) = connected_with_capacity(4096);
    let syn = packet::parse(&syn).unwrap();
    let head = ep.conns[&h].hooks.data.as_ref().unwrap().send.next;
    ep.connection(h).unwrap().write(b"queued").unwrap();
    input(
        &mut ep,
        &Segment {
            flags: TcpFlags::ACK | TcpFlags::FIN,
            ..peer_data(&syn, 5001, &[], &[])
        },
    );
    assert_eq!(
        ep.connection(h).unwrap().read(&mut [0; 1]),
        Err(crate::connection::ReadError::WouldBlock)
    );
    let bytes = transmit(&mut ep, Instant::from_nanos(3));
    let fin = packet::parse(&bytes).unwrap();
    assert!(fin.flags.contains(TcpFlags::FIN));
    assert!(fin.payload.is_empty());
    assert_eq!(ep.conns[&h].hooks.data.as_ref().unwrap().send.next, head);
    let ack = Segment {
        ack: fin.seq.wrapping_add(1),
        ..peer_data(&syn, 5002, &[], &[])
    };
    input(&mut ep, &ack);
    assert_eq!(ep.poll_event(), None);
    assert_eq!(ep.connection(h).unwrap().write(b"more"), Ok(4));
    let at = ep.poll_timeout().unwrap();
    assert_eq!(at, Instant::from_nanos(2) + Duration::from_secs(60));
    ep.handle_timeout(at);
    assert_eq!(
        ep.poll_event(),
        Some((
            h,
            Event::Closed {
                reason: CloseReason::Timeout
            }
        ))
    );
}

#[test]
fn queued_close_initial_capable_mapping_gets_separate_data_fin() {
    let (mut ep, h, _, _) = connected_with_capacity(4096);
    ep.connection(h).unwrap().write(b"initial").unwrap();
    ep.connection(h).unwrap().close();
    let bytes = transmit(&mut ep, Instant::from_nanos(2));
    let first = packet::parse(&bytes).unwrap();
    assert_eq!(first.payload, b"initial");
    assert!(matches!(
        mptcp::parse(mpc(first.options)[0]).unwrap(),
        MptcpOption::Capable(_)
    ));
    assert!(!first.flags.contains(TcpFlags::FIN));
    let bytes = transmit(&mut ep, Instant::from_nanos(2));
    let second = packet::parse(&bytes).unwrap();
    let MptcpOption::Dss(d) = mptcp::parse(mpc(second.options)[0]).unwrap() else {
        panic!()
    };
    assert!(d.data_fin);
    assert_eq!(d.mapping.unwrap().ssn, 0);
    assert_eq!(d.mapping.unwrap().data_len, 1);
    assert_eq!(second.seq, first.seq.wrapping_add(7));
}

#[test]
fn fallback_cancels_data_fin_timer_and_keeps_tcp_halfclose_reply() {
    let (mut ep, h, syn, _) = connected_with_capacity(4096);
    let syn = packet::parse(&syn).unwrap();
    ep.connection(h).unwrap().write(b"initial").unwrap();
    ep.connection(h).unwrap().close();
    transmit(&mut ep, Instant::from_nanos(2));
    transmit(&mut ep, Instant::from_nanos(2)); // standalone DATA_FIN
    let seg = Segment {
        ack: syn.seq.wrapping_add(8),
        ..peer_data(&syn, 5001, &[], &[])
    };
    input(&mut ep, &seg); // options stripped: TCP fallback
    assert!(!ep.conns[&h].hooks.active());
    assert!(ep.conns[&h].hooks.recovery_deadline().is_none());
    assert_eq!(ep.poll_event(), Some((h, Event::FellBack)));
    let bytes = transmit(&mut ep, Instant::from_nanos(3));
    assert!(packet::parse(&bytes).unwrap().flags.contains(TcpFlags::FIN));

    let (mut ep, h, syn, _) = connected_with_capacity(4096);
    let syn = packet::parse(&syn).unwrap();
    ep.connection(h).unwrap().write(b"initial").unwrap();
    transmit(&mut ep, Instant::from_nanos(2));
    input(
        &mut ep,
        &Segment {
            ack: syn.seq.wrapping_add(8),
            flags: TcpFlags::ACK | TcpFlags::FIN,
            ..peer_data(&syn, 5001, &[], &[])
        },
    );
    transmit(&mut ep, Instant::from_nanos(3));
    ep.connection(h).unwrap().write(b"reply").unwrap();
    let bytes = transmit(&mut ep, Instant::from_nanos(4));
    assert_eq!(packet::parse(&bytes).unwrap().payload, b"reply");
}

#[test]
fn attached_data_fin_reinjects_with_data_before_standalone_retry() {
    let (mut ep, h, syn, _) = connected_with_capacity(4096);
    let syn = packet::parse(&syn).unwrap();
    let head = ep.conns[&h].hooks.data.as_ref().unwrap().send.una;
    input(&mut ep, &peer_data(&syn, 5001, &data_ack(head), &[]));
    ep.connection(h).unwrap().write(b"final").unwrap();
    ep.connection(h).unwrap().close();
    let bytes = transmit(&mut ep, Instant::from_nanos(2));
    let data = packet::parse(&bytes).unwrap();
    let MptcpOption::Dss(d) = mptcp::parse(mpc(data.options)[0]).unwrap() else {
        panic!()
    };
    assert!(d.data_fin);
    input(
        &mut ep,
        &Segment {
            ack: data.seq.wrapping_add(5),
            ..peer_data(&syn, 5001, &data_ack(head), &[])
        },
    );
    let at = ep.poll_timeout().unwrap();
    ep.handle_timeout(at);
    let bytes = transmit(&mut ep, at);
    let retry = packet::parse(&bytes).unwrap();
    assert_eq!(retry.payload, b"final");
    let MptcpOption::Dss(d) = mptcp::parse(mpc(retry.options)[0]).unwrap() else {
        panic!()
    };
    assert!(d.data_fin);
    assert_eq!(d.mapping.unwrap().data_len, 6);
    assert_eq!(d.mapping.unwrap().ssn, 6);
    // DATA_ACK for the bytes alone leaves only the FIN to retransmit.
    input(
        &mut ep,
        &Segment {
            ack: retry.seq.wrapping_add(5),
            ..peer_data(&syn, 5001, &data_ack(head.wrapping_add(5)), &[])
        },
    );
    let at = ep.poll_timeout().unwrap();
    ep.handle_timeout(at);
    let bytes = transmit(&mut ep, at);
    let fin = packet::parse(&bytes).unwrap();
    assert!(fin.payload.is_empty());
    let MptcpOption::Dss(d) = mptcp::parse(mpc(fin.options)[0]).unwrap() else {
        panic!()
    };
    assert!(d.data_fin);
    assert_eq!(d.mapping.unwrap().ssn, 0);
}

#[test]
fn combined_fin_with_dsn_hole_keeps_local_half_open() {
    let (mut ep, h, syn, dsn) = connected_with_capacity(4096);
    let syn = packet::parse(&syn).unwrap();
    let opts = fin_option(dsn.wrapping_add(2), 1, 3, None);
    input(
        &mut ep,
        &Segment {
            flags: TcpFlags::ACK | TcpFlags::FIN,
            ..peer_data(&syn, 5001, &opts, b"cd")
        },
    );
    let bytes = transmit(&mut ep, Instant::from_nanos(3));
    assert!(!packet::parse(&bytes).unwrap().flags.contains(TcpFlags::FIN));
    assert_eq!(
        ep.connection(h).unwrap().read(&mut [0; 4]),
        Err(crate::connection::ReadError::WouldBlock)
    );
    ep.connection(h).unwrap().write(b"reply").unwrap();
    let bytes = transmit(&mut ep, Instant::from_nanos(4));
    assert_eq!(packet::parse(&bytes).unwrap().payload, b"reply");
}

#[test]
fn fastclose_outside_closed_tcp_window_is_not_an_ack_only_probe() {
    let (mut ep, h, syn, dsn) = connected_with_capacity(1);
    let syn = packet::parse(&syn).unwrap();
    reply(&mut ep, &syn, &capable(1, CAP_H), syn.seq.wrapping_add(1));
    let bytes = transmit(&mut ep, Instant::from_nanos(2));
    let MptcpOption::Capable(keys) =
        mptcp::parse(mpc(packet::parse(&bytes).unwrap().options)[0]).unwrap()
    else {
        panic!()
    };
    input(&mut ep, &peer_data(&syn, 5001, &mapping(1, dsn, 1), b"x"));
    let bytes = transmit(&mut ep, Instant::from_nanos(2));
    assert_eq!(packet::parse(&bytes).unwrap().wnd, 0);
    let mut opts = [0; 40];
    let n = mptcp::encode(
        &MptcpOption::FastClose {
            receiver_key: keys.sender_key.unwrap(),
        },
        &mut opts,
    )
    .unwrap();
    input(&mut ep, &peer_data(&syn, 5003, &opts[..n], &[]));
    assert_eq!(ep.poll_event(), None);
    assert!(ep.conns[&h].hooks.retained());
}

#[test]
fn close_before_third_ack_preserves_keys_and_fin_progress() {
    let mut ep = Endpoint::new(ChaCha20Rng::seed_from_u64(2));
    let h = open(&mut ep);
    let bytes = transmit(&mut ep, Instant::from_nanos(0));
    let syn = packet::parse(&bytes).unwrap();
    reply(&mut ep, &syn, &capable(1, CAP_H), syn.seq.wrapping_add(1));
    ep.connection(h).unwrap().close();
    assert!(
        ep.poll_transmit(Instant::from_nanos(2), &mut [0; 20])
            .is_none()
    );
    assert_eq!(ep.poll_event(), None);
    // No peer DSS is needed to finish an empty stream. Repeated SYN/ACKs
    // must still get keys, even when the DATA_FIN retry is simultaneously due.
    for now in [Instant::from_nanos(2), Instant::from_nanos(2_000_000_000)] {
        if now != Instant::from_nanos(2) {
            reply(&mut ep, &syn, &capable(1, CAP_H), syn.seq.wrapping_add(1));
        }
        let bytes = transmit(&mut ep, now);
        let ack = packet::parse(&bytes).unwrap();
        assert!(matches!(mptcp::parse(mpc(ack.options)[0]),
            Ok(MptcpOption::Capable(c)) if c.sender_key.is_some() && c.receiver_key == Some(PEER_KEY)));
        let bytes = transmit(&mut ep, now);
        let fin = packet::parse(&bytes).unwrap();
        assert!(matches!(mptcp::parse(mpc(fin.options)[0]),
            Ok(MptcpOption::Dss(d)) if d.data_fin && d.mapping.unwrap().ssn == 0));
        assert!(!fin.flags.contains(TcpFlags::FIN));
        assert!(ep.poll_transmit(now, &mut [0; 1500]).is_none());
    }
    assert_eq!(ep.poll_event(), Some((h, Event::Connected { mptcp: true })));
    assert_eq!(ep.poll_event(), None);
}

#[test]
fn fastclose_reset_survives_timeout_drive() {
    for flags in [TcpFlags::ACK, TcpFlags::RST] {
        let (mut ep, h, syn, _) = connected_with_capacity(4096);
        let syn = packet::parse(&syn).unwrap();
        reply(&mut ep, &syn, &capable(1, CAP_H), syn.seq.wrapping_add(1));
        let keys = transmit(&mut ep, Instant::from_nanos(2));
        let MptcpOption::Capable(keys) =
            mptcp::parse(mpc(packet::parse(&keys).unwrap().options)[0]).unwrap()
        else {
            panic!()
        };
        let mut opts = [0; 40];
        let n = mptcp::encode(
            &MptcpOption::FastClose {
                receiver_key: keys.sender_key.unwrap(),
            },
            &mut opts,
        )
        .unwrap();
        input(
            &mut ep,
            &Segment {
                flags,
                ..peer_data(&syn, 5001, &opts[..n], &[])
            },
        );
        assert_eq!(
            ep.poll_event(),
            Some((
                h,
                Event::Closed {
                    reason: CloseReason::Reset
                }
            ))
        );
        let now = Instant::from_nanos(3);
        ep.handle_timeout(now);
        assert!(ep.poll_transmit(now, &mut [0; 20]).is_none());
        ep.handle_timeout(now);
        assert!(
            ep.connection(h).is_some(),
            "retain until RST actually fits the output buffer"
        );
        let bytes = transmit(&mut ep, now);
        assert!(packet::parse(&bytes).unwrap().flags.contains(TcpFlags::RST));
        assert!(ep.poll_transmit(now, &mut [0; 1500]).is_none());
        let cleanup = ep
            .poll_timeout()
            .expect("closed connection must schedule cleanup");
        assert!(cleanup <= now);
        ep.handle_timeout(now);
        assert!(ep.connection(h).is_none());
        assert_eq!(ep.poll_timeout(), None);
        assert_eq!(ep.poll_event(), None);
    }
}

/// A peer that fills the advertised data-level window with segments of `size(i)` octets while
/// the application does not read, as Linux does when the TUN driver floods before `read()`.
/// Returns the octets sent and the last subflow ACK seen.
fn flood_unread(
    ep: &mut Endpoint<ChaCha20Rng>,
    syn: &Segment,
    dsn: u64,
    scale: u8,
    mut size: impl FnMut(u64) -> usize,
) -> (u64, SeqNum) {
    let (mut sent, mut edge, mut tcp_ack) = (0u64, dsn.wrapping_add(65535), SeqNum(5001));
    let payload = vec![7; 4096];
    let mut now = Instant::from_nanos(2);
    for i in 0.. {
        let room = edge.wrapping_sub(dsn.wrapping_add(sent));
        if room > 0 {
            let len = (size(i) as u64).min(room) as usize;
            let opts = mapping(1 + sent as u32, dsn.wrapping_add(sent), len as u16);
            let seg = peer_data(syn, 5001 + sent as u32, &opts, &payload[..len]);
            let mut wire = [0; 4200];
            let n = packet::build(&seg, 0, &mut wire).unwrap();
            ep.handle_packet(now, &wire[..n]);
            sent += len as u64;
        } else {
            // Window used up: let a delayed ACK go out; stop once it opens nothing.
            now = now + Duration::from_secs(1);
            ep.handle_timeout(now);
        }
        let before = edge;
        let mut out = [0; 1500];
        while let Some(n) = ep.poll_transmit(now, &mut out) {
            let ack = packet::parse(&out[..n]).unwrap();
            tcp_ack = ack.ack;
            let advertised = dack(&ack).wrapping_add(u64::from(ack.wnd) << scale);
            if advertised.wrapping_sub(edge) as i64 > 0 {
                edge = advertised;
            }
        }
        if room == 0 && edge == before {
            break;
        }
        now = now + Duration::from_micros(10);
    }
    (sent, tcp_ack)
}

fn connected_scaled(
    cap: u32,
) -> (
    Endpoint<ChaCha20Rng>,
    ConnectionHandle,
    Segment<'static>,
    u64,
) {
    let mut ep = Endpoint::new(ChaCha20Rng::seed_from_u64(31));
    let h = ep
        .connect_mptcp(
            Instant::from_nanos(0),
            "10.0.0.1".parse().unwrap(),
            "10.0.0.2:80".parse().unwrap(),
            ConnectConfig {
                recv_buffer: cap,
                ..ConnectConfig::default()
            },
        )
        .unwrap();
    let syn_bytes = transmit(&mut ep, Instant::from_nanos(0)).leak();
    let syn = packet::parse(syn_bytes).unwrap();
    let mut opts = capable(1, CAP_H);
    let mut o = [0; 4];
    let n = crate::wire::tcp_options::write_mss(&mut o, 1460);
    opts.extend_from_slice(&o[..n]);
    let n = crate::wire::tcp_options::write_ws(&mut o, 7);
    opts.extend_from_slice(&o[..n]);
    reply(&mut ep, &syn, &opts, syn.seq.wrapping_add(1));
    transmit(&mut ep, Instant::from_nanos(1));
    ep.poll_event();
    let dsn = crate::crypto::key_token_idsn(PEER_KEY).1.wrapping_add(1);
    (ep, h, syn, dsn)
}

fn read_all(ep: &mut Endpoint<ChaCha20Rng>, h: ConnectionHandle) -> u64 {
    let mut total = 0;
    let mut buf = [0; 65536];
    while let Ok(n) = ep.connection(h).unwrap().read(&mut buf) {
        total += n as u64;
    }
    total
}

#[test]
fn unread_flood_keeps_data_up_to_the_rounded_data_level_edge() {
    // Scale 3 rounds the shared edge to 8 octets; 1001-octet segments leave 7 octets of
    // rounding per DATA_ACK, so the advertised edge passes the 256 KiB memory edge.
    let cap = 1 << 18;
    let (mut ep, h, syn, dsn) = connected_scaled(cap);
    let (sent, tcp_ack) = flood_unread(&mut ep, &syn, dsn, 3, |_| 1001);
    assert!(
        sent > u64::from(cap),
        "the rounded edge promised {sent} octets"
    );
    // Every octet the peer sent was inside the advertised window and is subflow-ACKed ...
    assert_eq!(tcp_ack, SeqNum(5001 + sent as u32));
    // ... so it must be delivered and DATA_ACKed without a connection-level retransmission.
    assert_eq!(read_all(&mut ep, h), sent);
    let ack = transmit(&mut ep, Instant::from_nanos(3));
    assert_eq!(dack(&packet::parse(&ack).unwrap()), dsn.wrapping_add(sent));
}
