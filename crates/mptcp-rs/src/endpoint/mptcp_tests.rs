use super::*;
use crate::wire::tcp_options::{TcpOpt, walk};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

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
    ep.connection(a).unwrap().close();
    let bytes = transmit(&mut ep, Instant::from_nanos(2));
    assert!(packet::parse(&bytes).unwrap().flags.contains(TcpFlags::FIN));
    input(
        &mut ep,
        &Segment {
            src: syn.dst,
            dst: syn.src,
            seq: SeqNum(5001),
            ack: syn.seq.wrapping_add(2),
            flags: TcpFlags::ACK | TcpFlags::FIN,
            wnd: 1234,
            options: &[],
            payload: &[],
        },
    );
    transmit(&mut ep, Instant::from_nanos(2));
    ep.handle_timeout(Instant::from_nanos(2));
    assert_eq!(ep.conns[&a].tcb.state(), TcpState::TimeWait);
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
    ep.handle_timeout(deadline);
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
