use mptcp_rs::wire::{
    packet,
    tcp_options::{TcpOpt, walk},
};
use mptcp_rs::{ConnectConfig, Endpoint, Instant};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

/// These tests read the A=0 wire layout.
fn a0() -> ConnectConfig {
    let mut cfg = ConnectConfig::default();
    cfg.checksums = false;
    cfg
}

#[test]
fn public_mptcp_api_emits_capable_syn() {
    let mut ep = Endpoint::new(ChaCha20Rng::seed_from_u64(1));
    let now = Instant::from_nanos(0);
    ep.connect_mptcp(
        now,
        "10.0.0.1".parse().unwrap(),
        "10.0.0.2:80".parse().unwrap(),
        a0(),
    )
    .unwrap();
    let mut out = [0; 1500];
    let n = ep.poll_transmit(now, &mut out).unwrap();
    let syn = packet::parse(&out[..n]).unwrap();
    assert!(walk(syn.options).any(|o| matches!(o, Ok(TcpOpt::Mptcp([30, 4, 1, 1])))));
}

use mptcp_rs::wire::{
    mptcp::{self, DataAck, Dsn, Dss, Mapping, MptcpOption},
    packet::{Segment, TcpFlags},
};
use mptcp_rs::{CloseReason, Event, SeqNum};
use std::time::Duration;

fn option(value: MptcpOption) -> Vec<u8> {
    let mut buf = [1; 40];
    let len = mptcp::encode(&value, &mut buf).unwrap();
    buf[..len.next_multiple_of(4)].to_vec()
}
fn emit(ep: &mut Endpoint<ChaCha20Rng>, time: Instant) -> Vec<u8> {
    let mut buf = [0; 1500];
    let n = ep.poll_transmit(time, &mut buf).expect("packet due");
    buf[..n].to_vec()
}
fn input(ep: &mut Endpoint<ChaCha20Rng>, time: Instant, seg: &Segment) {
    let mut buf = [0; 1500];
    let n = packet::build(seg, 0, &mut buf).unwrap();
    ep.handle_packet(time, &buf[..n]);
}
fn protocol(bytes: &[u8]) -> MptcpOption {
    walk(packet::parse(bytes).unwrap().options)
        .find_map(|o| match o.unwrap() {
            TcpOpt::Mptcp(raw) => Some(mptcp::parse(raw).unwrap()),
            _ => None,
        })
        .unwrap()
}

#[test]
fn production_dss_recovery_and_close_wait_for_actual_tcp_close() {
    let mut ep = Endpoint::new(ChaCha20Rng::seed_from_u64(2));
    let mut time = Instant::from_nanos(1);
    let h = ep
        .connect_mptcp(
            time,
            "10.0.0.1".parse().unwrap(),
            "10.0.0.2:80".parse().unwrap(),
            a0(),
        )
        .unwrap();
    let bytes = emit(&mut ep, time);
    let syn = packet::parse(&bytes).unwrap();
    let capable = option(MptcpOption::Capable(mptcp::MpCapable {
        version: 1,
        flags: mptcp::CAP_H,
        sender_key: Some(42),
        receiver_key: None,
        data_len: None,
        checksum: None,
    }));
    let mut peer = Segment {
        src: syn.dst,
        dst: syn.src,
        seq: SeqNum(5000),
        ack: syn.seq.wrapping_add(1),
        flags: TcpFlags::SYN | TcpFlags::ACK,
        wnd: 65535,
        options: &capable,
        payload: &[],
    };
    input(&mut ep, time, &peer);
    let MptcpOption::Capable(keys) = protocol(&emit(&mut ep, time)) else {
        panic!()
    };
    assert_eq!(ep.poll_event(), Some((h, Event::Connected { mptcp: true })));
    let local_dsn = mptcp_rs::crypto::key_token_idsn(keys.sender_key.unwrap())
        .1
        .wrapping_add(1);
    let peer_dsn = mptcp_rs::crypto::key_token_idsn(42).1.wrapping_add(1);
    let confirmation = option(MptcpOption::Dss(Dss {
        data_ack: Some(DataAck::Ack64(local_dsn)),
        mapping: None,
        data_fin: false,
    }));
    peer.seq = SeqNum(5001);
    peer.flags = TcpFlags::ACK;
    peer.options = &confirmation;
    input(&mut ep, time, &peer);
    ep.connection(h).unwrap().write(b"abc").unwrap();
    let bytes = emit(&mut ep, time);
    let data = packet::parse(&bytes).unwrap();
    assert_eq!(data.payload, b"abc");
    assert!(matches!(protocol(&bytes), MptcpOption::Dss(_)));
    peer.ack = data.seq.wrapping_add(3);
    // TCP acknowledges the bytes, while DATA_ACK stays at the old head.
    input(&mut ep, time, &peer);
    time = ep.poll_timeout().unwrap();
    ep.handle_timeout(time);
    let bytes = emit(&mut ep, time);
    let retry = packet::parse(&bytes).unwrap();
    assert_eq!(
        retry.payload, b"abc",
        "connection-level recovery must reinject"
    );
    assert_ne!(retry.seq, data.seq);
    let acked = option(MptcpOption::Dss(Dss {
        data_ack: Some(DataAck::Ack64(local_dsn.wrapping_add(3))),
        mapping: None,
        data_fin: false,
    }));
    peer.ack = retry.seq.wrapping_add(3);
    peer.options = &acked;
    input(&mut ep, time, &peer);
    ep.connection(h).unwrap().close();
    let fin = emit(&mut ep, time);
    assert!(matches!(
        protocol(&fin),
        MptcpOption::Dss(Dss { data_fin: true, .. })
    ));
    let fin_ack = option(MptcpOption::Dss(Dss {
        data_ack: Some(DataAck::Ack64(local_dsn.wrapping_add(4))),
        mapping: None,
        data_fin: false,
    }));
    peer.options = &fin_ack;
    input(&mut ep, time, &peer);
    let bytes = emit(&mut ep, time);
    let tcp_fin = packet::parse(&bytes).unwrap();
    assert!(tcp_fin.flags.contains(TcpFlags::FIN));
    let peer_fin = option(MptcpOption::Dss(Dss {
        data_ack: Some(DataAck::Ack64(local_dsn.wrapping_add(4))),
        mapping: Some(Mapping {
            dsn: Dsn::Dsn64(peer_dsn),
            ssn: 0,
            data_len: 1,
            checksum: None,
        }),
        data_fin: true,
    }));
    peer.options = &peer_fin;
    peer.ack = tcp_fin.seq.wrapping_add(1);
    peer.flags = TcpFlags::ACK | TcpFlags::FIN;
    input(&mut ep, time, &peer);
    emit(&mut ep, time);
    assert_eq!(ep.connection(h).unwrap().read(&mut [0; 1]), Ok(0));
    assert_eq!(ep.poll_event(), None, "TIME_WAIT is not a closed TCB");
    ep.handle_timeout(time + Duration::from_secs(119));
    assert_eq!(ep.poll_event(), None);
    ep.handle_timeout(time + Duration::from_secs(120));
    assert_eq!(
        ep.poll_event(),
        Some((
            h,
            Event::Closed {
                reason: CloseReason::Normal
            }
        ))
    );
    assert!(ep.connection(h).is_none());
}
