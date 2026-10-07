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
fn discarded_full_memory_data_advances_tcp_ack_only() {
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
    // New SSNs recover data that was discarded but already TCP-ACKed.
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
    assert_eq!(
        ep.poll_event(),
        Some((
            h,
            Event::Closed {
                reason: CloseReason::Reset
            }
        ))
    );
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
    assert_eq!(
        ep.poll_event(),
        Some((
            h,
            Event::Closed {
                reason: CloseReason::Reset
            }
        ))
    );
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
    let d = ep.conns.get_mut(&h).unwrap().hooks.data.as_mut().unwrap();
    // Install a wrapped send origin before any application data.
    d.send = crate::mptcp::data::SendStore::new(u64::MAX - 1, 4);
    assert_eq!(d.send.write(b"abcd"), 4);
    assert!(d.send.assign(&mut d.tx, u64::MAX - 1, 4));
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
fn stored_chunk_boundary_does_not_bypass_sender_sws_and_timeout_releases_it() {
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
    assert_eq!(packet::parse(&bytes).unwrap().payload, &[1; 8]);
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

#[test]
fn short_chunk_waits_for_sws_override_even_with_full_segment_budget() {
    let (mut ep, h, syn_bytes, _) = connected_with_capacity(64);
    let syn = packet::parse(&syn_bytes).unwrap();
    ep.connection(h).unwrap().write(&[1; 8]).unwrap();
    ep.connection(h).unwrap().write(&[2; 2000]).unwrap();
    let mut ack = peer_data(&syn, 5001, &[], &[]);
    ack.wnd = 1000;
    input(&mut ep, &ack);
    assert!(
        ep.poll_transmit(Instant::from_nanos(2), &mut [0; 1500])
            .is_none()
    );
    let deadline = ep.poll_timeout().expect("short chunk needs SWS override");
    ep.handle_timeout(deadline);
    let bytes = transmit(&mut ep, deadline);
    assert_eq!(packet::parse(&bytes).unwrap().payload, &[1; 8]);
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
fn short_chunk_cannot_use_a_larger_sws_partial_budget() {
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
    ack.wnd = 800;
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
