mod support;

use mptcp_rs::wire::packet::TcpFlags;
use mptcp_rs::{CloseReason, ConnectConfig, ConnectError, Event, ReadError};
use support::*;

#[test]
fn connect_emits_syn_and_connected() {
    for v6 in [false, true] {
        let mut ep = endpoint(1);
        let h = ep
            .connect(t(1), local_ip(v6), peer_addr(v6), ConnectConfig::default())
            .unwrap();
        let syn = expect_syn(&drain(&mut ep, t(1)));
        assert!((49152..=65535).contains(&syn.src.port()));
        assert_eq!(syn.dst, peer_addr(v6));
        assert_eq!(ep.poll_event(), None);
        send_synack(&mut ep, t(1), &syn, 5000);
        assert_eq!(
            ep.poll_event(),
            Some((h, Event::Connected { mptcp: false }))
        );
        assert_eq!(ep.poll_event(), None);
    }
}

#[test]
fn passive_close_delivers_closed_event() {
    let mut ep = endpoint(2);
    let (h, syn, iss) = established(&mut ep, t(1), false);
    let isn = syn.seq.0;
    send_seg(
        &mut ep,
        t(2),
        &syn,
        iss + 1,
        isn + 1,
        TcpFlags::ACK | TcpFlags::FIN,
        &[],
    );
    expect_ack(&drain(&mut ep, t(2)), iss + 2);
    let c = ep.connection(h).unwrap();
    assert_eq!(c.read(&mut [0u8; 8]), Ok(0), "EOF");
    c.close();
    let fin = parse_owned(&drain(&mut ep, t(2))[0]);
    assert!(fin.flags.contains(TcpFlags::FIN));
    send_seg(&mut ep, t(3), &syn, iss + 2, isn + 2, TcpFlags::ACK, &[]);
    assert!(ep.poll_timeout().unwrap() <= t(3));
    ep.handle_timeout(t(3));
    assert!(ep.connection(h).is_none());
    assert_eq!(
        ep.poll_event(),
        Some((
            h,
            Event::Closed {
                reason: CloseReason::Normal
            }
        ))
    );
    assert_eq!(ep.poll_event(), None);
    assert_eq!(ep.poll_timeout(), None);
}

#[test]
fn reset_delivers_event_and_read_err() {
    let mut ep = endpoint(3);
    let (h, syn, iss) = established(&mut ep, t(1), true);
    send_seg(&mut ep, t(2), &syn, iss + 1, 0, TcpFlags::RST, &[]);
    assert_eq!(
        ep.poll_event(),
        Some((
            h,
            Event::Closed {
                reason: CloseReason::Reset
            }
        ))
    );
    assert_eq!(
        ep.connection(h).unwrap().write(b"x"),
        Err(mptcp_rs::WriteError::Closed)
    );
    assert_eq!(
        ep.connection(h).unwrap().read(&mut [0u8; 8]),
        Err(ReadError::Reset)
    );
    assert!(drain(&mut ep, t(2)).is_empty());
    ep.handle_timeout(t(2));
    assert!(ep.connection(h).is_none());
    assert_eq!(ep.poll_event(), None);
}

#[test]
fn read_without_data_would_block() {
    let mut ep = endpoint(4);
    let (h, syn, iss) = established(&mut ep, t(1), false);
    let c = ep.connection(h).unwrap();
    assert_eq!(c.read(&mut [0u8; 8]), Err(ReadError::WouldBlock));
    send_data(&mut ep, t(2), &syn, iss + 1, syn.seq.0 + 1, b"hello");
    let mut buf = [0u8; 16];
    assert_eq!(ep.connection(h).unwrap().read(&mut buf), Ok(5));
    assert_eq!(&buf[..5], b"hello");
    assert_eq!(
        ep.connection(h).unwrap().read(&mut buf),
        Err(ReadError::WouldBlock)
    );
}

#[test]
fn two_connections_get_distinct_ports_and_isns() {
    let mut ep = endpoint(5);
    let a = ep
        .connect(
            t(1),
            local_ip(false),
            peer_addr(false),
            ConnectConfig::default(),
        )
        .unwrap();
    let b = ep
        .connect(
            t(1),
            local_ip(false),
            peer_addr(false),
            ConnectConfig::default(),
        )
        .unwrap();
    assert_ne!(a, b);
    let pkts = drain(&mut ep, t(1));
    assert_eq!(pkts.len(), 2);
    let (x, y) = (parse_owned(&pkts[0]), parse_owned(&pkts[1]));
    assert_ne!(x.src.port(), y.src.port());
    assert_ne!(x.seq, y.seq);
}

#[test]
fn close_in_syn_sent_reports_and_frees() {
    let mut ep = endpoint(6);
    let h = ep
        .connect(
            t(1),
            local_ip(false),
            peer_addr(false),
            ConnectConfig::default(),
        )
        .unwrap();
    let syn = expect_syn(&drain(&mut ep, t(1)));
    ep.connection(h).unwrap().close();
    assert!(drain(&mut ep, t(1)).is_empty());
    assert!(ep.poll_timeout().unwrap() <= t(1));
    ep.handle_timeout(t(1));
    assert!(ep.connection(h).is_none());
    assert_eq!(
        ep.poll_event(),
        Some((
            h,
            Event::Closed {
                reason: CloseReason::Normal
            }
        ))
    );
    // A late SYN/ACK finds no TCB and is reset (RFC 9293 §3.10.7.1).
    send_synack(&mut ep, t(2), &syn, 5000);
    let rst = parse_owned(&drain(&mut ep, t(2))[0]);
    assert_eq!(rst.flags, TcpFlags::RST);
    assert_eq!(rst.seq, syn.seq.wrapping_add(1));
}

#[test]
fn connect_validates_arguments() {
    let mut ep = endpoint(7);
    let small = |mtu| ConnectConfig {
        mtu,
        ..ConnectConfig::default()
    };
    let c = |ep: &mut mptcp_rs::Endpoint<_>, v6, mtu| {
        ep.connect(t(1), local_ip(v6), peer_addr(v6), small(mtu))
    };
    assert_eq!(c(&mut ep, false, 67).err(), Some(ConnectError::InvalidMtu));
    assert!(c(&mut ep, false, 68).is_ok());
    assert_eq!(c(&mut ep, true, 1279).err(), Some(ConnectError::InvalidMtu));
    assert!(c(&mut ep, true, 1280).is_ok());
    for (send_buffer, recv_buffer) in [(0, 1), (1, 0), ((1 << 30) + 1, 1), (1, (1 << 30) + 1)] {
        let cfg = ConnectConfig {
            send_buffer,
            recv_buffer,
            ..ConnectConfig::default()
        };
        let r = ep.connect(t(1), local_ip(false), peer_addr(false), cfg);
        assert_eq!(r.err(), Some(ConnectError::InvalidBuffer));
    }
    let max = ConnectConfig {
        send_buffer: 1 << 30,
        recv_buffer: 1 << 30,
        ..ConnectConfig::default()
    };
    assert!(
        ep.connect(t(1), local_ip(false), peer_addr(false), max)
            .is_ok()
    );
    assert_eq!(
        ep.connect(
            t(1),
            local_ip(false),
            peer_addr(true),
            ConnectConfig::default()
        )
        .err(),
        Some(ConnectError::FamilyMismatch)
    );
}

#[test]
fn ports_exhausted_gives_no_port() {
    let mut ep = endpoint(8);
    let mut ports = std::collections::HashSet::new();
    for _ in 0..16384 {
        ep.connect(
            t(1),
            local_ip(false),
            peer_addr(false),
            ConnectConfig::default(),
        )
        .unwrap();
    }
    for p in drain(&mut ep, t(1)) {
        assert!(ports.insert(parse_owned(&p).src.port()));
    }
    assert_eq!(ports.len(), 16384);
    assert_eq!(
        ep.connect(
            t(1),
            local_ip(false),
            peer_addr(false),
            ConnectConfig::default()
        )
        .err(),
        Some(ConnectError::NoPort)
    );
    // Another remote is unaffected.
    let other = "10.0.0.9:80".parse().unwrap();
    assert!(
        ep.connect(t(1), local_ip(false), other, ConnectConfig::default())
            .is_ok()
    );
}

/// R23: a passive close must not lose received data the application has not read yet.
#[test]
fn passive_close_keeps_unread_data_readable() {
    let mut ep = endpoint(9);
    let (h, syn, iss) = established(&mut ep, t(1), false);
    let isn = syn.seq.0;
    send_seg(
        &mut ep,
        t(2),
        &syn,
        iss + 1,
        isn + 1,
        TcpFlags::ACK | TcpFlags::FIN,
        b"hello",
    );
    expect_ack(&drain(&mut ep, t(2)), iss + 7);
    ep.connection(h).unwrap().close(); // before reading
    let fin = parse_owned(&drain(&mut ep, t(2))[0]);
    assert!(fin.flags.contains(TcpFlags::FIN));
    send_seg(&mut ep, t(3), &syn, iss + 7, isn + 2, TcpFlags::ACK, &[]);
    ep.handle_timeout(t(3));
    assert_eq!(
        ep.poll_event(),
        Some((
            h,
            Event::Closed {
                reason: CloseReason::Normal
            }
        ))
    );
    // The port is released: a segment for the 4-tuple is now answered with RST.
    send_seg(&mut ep, t(3), &syn, iss + 7, isn + 2, TcpFlags::ACK, &[]);
    let rst = parse_owned(&drain(&mut ep, t(3))[0]);
    assert!(rst.flags.contains(TcpFlags::RST));
    // No timer spin while only the drained-pending connection exists.
    assert_eq!(ep.poll_timeout(), None);
    ep.handle_timeout(t(4));
    let mut buf = [0u8; 16];
    let c = ep.connection(h).expect("kept until drained");
    assert_eq!(c.read(&mut buf), Ok(5));
    assert_eq!(&buf[..5], b"hello");
    assert_eq!(c.read(&mut buf), Ok(0), "EOF");
    ep.handle_timeout(t(5));
    assert!(ep.connection(h).is_none());
    assert_eq!(ep.poll_timeout(), None);
}

#[test]
fn scoped_ipv6_remote_is_normalized_to_wire_form() {
    use std::net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV6};
    let mut ep = endpoint(9);
    let remote = SocketAddr::V6(SocketAddrV6::new(
        Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2),
        80,
        7,
        3,
    ));
    let h = ep
        .connect(
            t(1),
            IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1)),
            remote,
            ConnectConfig::default(),
        )
        .unwrap();
    let syn = expect_syn(&drain(&mut ep, t(1)));
    send_synack(&mut ep, t(1), &syn, 5000);
    assert_eq!(
        ep.poll_event(),
        Some((h, Event::Connected { mptcp: false }))
    );
    for p in drain(&mut ep, t(1)) {
        assert!(!parse_owned(&p).flags.contains(TcpFlags::RST));
    }
}
