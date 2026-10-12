mod support;

use mptcp_rs::ConnectConfig;
use mptcp_rs::SeqNum;
use mptcp_rs::wire::packet::TcpFlags;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
use support::*;

fn sa(last: u8, port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, last)), port)
}

/// An RST is never answered, so idle endpoints stay silent.
fn rst(src: SocketAddr, dst: SocketAddr, seq: u32, payload: &[u8]) -> Vec<u8> {
    pkt(
        src,
        dst,
        SeqNum(seq),
        SeqNum(0),
        TcpFlags::RST,
        &[],
        payload,
    )
}

fn idle_net() -> Net<rand_chacha::ChaCha20Rng> {
    Net::new(
        endpoint(1),
        endpoint(2),
        Link::new(1, 0, 0),
        Link::new(2, 0, 0),
    )
}

#[test]
fn net_delivers_in_order_with_delay() {
    let mut net = idle_net();
    for i in 0..3 {
        net.send(Dir::AtoB, rst(sa(1, 5), sa(2, 80), i, b""));
    }
    net.send(Dir::BtoA, rst(sa(2, 80), sa(1, 5), 9, b""));
    assert!(!net.run_until(ms(t(0), 1000), |_| false));
    let ab: Vec<_> = net.delivered.iter().filter(|d| d.0 == Dir::AtoB).collect();
    assert_eq!(ab.iter().map(|d| d.2.seq.0).collect::<Vec<_>>(), [0, 1, 2]);
    assert!(net.delivered.iter().all(|d| d.1 == ms(t(0), 10)));
    assert_eq!(net.delivered.len(), 4);
    assert_eq!(net.taps.len(), 4);
}

#[test]
fn net_delay_override_per_source() {
    let mut net = idle_net();
    let slow = sa(1, 5).ip();
    net.delay(Dir::AtoB, move |s| {
        (s.src.ip() == slow).then_some(Duration::from_millis(200))
    });
    net.send(Dir::AtoB, rst(sa(1, 5), sa(2, 80), 1, b""));
    net.send(Dir::AtoB, rst(sa(3, 5), sa(2, 80), 2, b""));
    net.run_until(ms(t(0), 1000), |_| false);
    let got: Vec<_> = net.delivered.iter().map(|d| (d.2.seq.0, d.1)).collect();
    assert_eq!(got, [(2, ms(t(0), 10)), (1, ms(t(0), 200))]);
}

#[test]
fn net_rewrite_drops_and_rewrites() {
    let mut net = idle_net();
    net.rewrite(Dir::AtoB, |s| {
        if s.payload == b"drop" {
            return false;
        }
        s.src = sa(9, 7);
        true
    });
    net.send(Dir::AtoB, rst(sa(1, 5), sa(2, 80), 1, b"keep"));
    net.send(Dir::AtoB, rst(sa(1, 5), sa(2, 80), 2, b"drop"));
    net.run_until(ms(t(0), 1000), |_| false);
    // `parse_owned` inside the harness already verified the checksums.
    assert_eq!(net.delivered.len(), 1);
    assert_eq!(net.delivered[0].2.src, sa(9, 7));
    assert_eq!(net.delivered[0].2.payload, b"keep");
    assert_eq!(net.taps.len(), 2);
    assert_eq!(net.taps[0].1.src, sa(1, 5));
}

#[test]
fn net_drop_next_drops_once() {
    let mut net = idle_net();
    net.drop_next(Dir::AtoB, |s| s.seq.0 == 1);
    for i in 0..3 {
        net.send(Dir::AtoB, rst(sa(1, 5), sa(2, 80), i.min(1), b""));
    }
    net.run_until(ms(t(0), 1000), |_| false);
    let seqs: Vec<_> = net.delivered.iter().map(|d| d.2.seq.0).collect();
    assert_eq!(seqs, [0, 1]);
}

#[test]
fn net_step_handles_one_delivery() {
    let mut net = idle_net();
    net.send(Dir::AtoB, rst(sa(1, 5), sa(2, 80), 1, b""));
    net.send(Dir::AtoB, rst(sa(1, 5), sa(2, 80), 2, b""));
    assert!(net.step());
    assert_eq!(net.delivered.len(), 1);
    assert!(net.step());
    assert_eq!(net.delivered.len(), 2);
    assert!(!net.step());
}

#[test]
fn net_run_until_pumps_before_checking_done() {
    let mut net = idle_net();
    let (local, remote) = (sa(1, 0).ip(), sa(2, 80));
    net.a
        .connect(net.now, local, remote, ConnectConfig::default())
        .unwrap();
    // The SYN is only queued in `a`; `done` observes taps, so the pump must come first.
    assert!(net.run_until(net.now, |n| !n.taps.is_empty()));
}
