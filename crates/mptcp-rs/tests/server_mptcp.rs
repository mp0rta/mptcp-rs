//! Server MP_CAPABLE between two `Endpoint`s (M4a Task 5): the passive side of the
//! negotiation, ending in the same `Confirmed` data path as the client.
mod support;

use mptcp_rs::wire::mptcp::{self, CAP_A, CAP_C, CAP_H, MpCapable, MpJoin, MptcpOption};
use mptcp_rs::wire::packet::TcpFlags;
use mptcp_rs::wire::tcp_options::{TcpOpt, walk};
use mptcp_rs::{
    AddSubflowError, CongestionControlKind, ConnectConfig, ConnectionHandle, Event, ListenConfig,
};
use rand_chacha::ChaCha20Rng;
use std::time::Duration;
use support::*;

/// A normal MPTCP close waits out TIME-WAIT (2·MSL = 120 s).
const SECS: u64 = 300;

/// The MPTCP options of `s`, with their lengths.
fn mptcp_opts(s: &Seg) -> Vec<(MptcpOption, usize)> {
    walk(&s.options)
        .filter_map(|o| match o {
            Ok(TcpOpt::Mptcp(raw)) => Some((mptcp::parse(raw).unwrap(), raw.len())),
            _ => None,
        })
        .collect()
}

fn capable(s: &Seg) -> Option<(MpCapable, usize)> {
    mptcp_opts(s).into_iter().find_map(|(o, len)| match o {
        MptcpOption::Capable(c) => Some((c, len)),
        _ => None,
    })
}

fn has_dss(s: &Seg) -> bool {
    (mptcp_opts(s).iter()).any(|(o, _)| matches!(o, MptcpOption::Dss(_)))
}

fn is_join_syn(s: &Seg) -> bool {
    let join = |(o, _): &(MptcpOption, usize)| matches!(o, MptcpOption::Join(MpJoin::Syn { .. }));
    s.flags == TcpFlags::SYN && mptcp_opts(s).iter().any(join)
}

/// Our MP_CAPABLE flags: H, and A with checksums.
fn flags(csum: bool) -> u8 {
    if csum { CAP_H | CAP_A } else { CAP_H }
}

/// The MP_CAPABLE length with data: the 22-octet form, 24 with the checksum.
fn dlen(csum: bool) -> usize {
    if csum { 24 } else { 22 }
}

/// `b` listens on 10.0.0.2:80 with MPTCP; `a` opens an MPTCP connection to it.
fn mptcp_net(cc: CongestionControlKind, csum: bool) -> (Net<ChaCha20Rng>, ConnectionHandle) {
    let mut n = idle_net();
    let mut l = ListenConfig::default();
    l.connection.congestion_control = cc;
    l.connection.checksums = csum;
    n.b.listen(sa(2, 80), l).unwrap();
    let mut cfg = ConnectConfig::default();
    cfg.congestion_control = cc;
    cfg.checksums = csum;
    let h = (n.a).connect_mptcp(n.now, sa(1, 0).ip(), sa(2, 80), cfg);
    (n, h.unwrap())
}

fn accepted_mptcp(n: &Net<ChaCha20Rng>) -> Option<ConnectionHandle> {
    let acc =
        |(h, e): &(ConnectionHandle, Event)| (*e == Event::Accepted { mptcp: true }).then_some(*h);
    n.events_b.iter().find_map(acc)
}

/// One `Accepted { mptcp: true }` and never `Connected` on the server, `Connected { mptcp: true }`
/// on the client, and no fallback anywhere.
fn assert_mptcp(n: &Net<ChaCha20Rng>) {
    let accepted = |e: &&(ConnectionHandle, Event)| matches!(e.1, Event::Accepted { .. });
    let acc: Vec<_> = n.events_b.iter().filter(accepted).collect();
    assert_eq!(acc.len(), 1);
    assert_eq!(acc[0].1, Event::Accepted { mptcp: true });
    let connected = |e: &(ConnectionHandle, Event)| matches!(e.1, Event::Connected { .. });
    assert!(!n.events_b.iter().any(connected));
    assert!(
        n.events_a
            .iter()
            .any(|e| e.1 == Event::Connected { mptcp: true })
    );
    let fell_back = |e: &(ConnectionHandle, Event)| e.1 == Event::FellBack;
    assert!(!n.events_a.iter().chain(&n.events_b).any(fell_back));
}

/// The first payload tap in `dir`.
fn first_payload(n: &Net<ChaCha20Rng>, dir: Dir) -> Seg {
    let tap = n
        .taps
        .iter()
        .find(|t| t.0 == dir && !t.1.payload.is_empty());
    tap.unwrap().1.clone()
}

/// When the first payload in `dir` was delivered.
fn first_delivery(n: &Net<ChaCha20Rng>, dir: Dir) -> mptcp_rs::Instant {
    let d = n
        .delivered
        .iter()
        .find(|d| d.0 == dir && !d.2.payload.is_empty());
    d.unwrap().1
}

fn apps(h: ConnectionHandle, client: usize, server: usize) -> [App; 2] {
    [
        App::new(false, Some(h), client, 0),
        App::new(true, None, server, 1),
    ]
}

fn mptcp_accept_and_transfer(csum: bool) {
    for cc in [CongestionControlKind::Cubic, CongestionControlKind::BbrV3] {
        let (mut n, h) = mptcp_net(cc, csum);
        run_apps(&mut n, &mut apps(h, 1 << 20, 1 << 20), SECS);
        assert_mptcp(&n);
        assert!(has_dss(&first_payload(&n, Dir::BtoA)));
    }
}

fn synack_carries_v1_h_only_and_c0(csum: bool) {
    let (mut n, _) = mptcp_net(CongestionControlKind::Cubic, csum);
    assert!(n.run_until(t(5), |n| n.taps.iter().any(|t| is_synack(&t.1))));
    let synack = &n.taps.iter().find(|t| is_synack(&t.1)).unwrap().1;
    let opts = mptcp_opts(synack);
    assert_eq!(opts.len(), 1);
    let (c, len) = capable(synack).unwrap();
    assert_eq!(len, 12);
    assert_eq!((c.version, c.flags), (1, flags(csum)));
    assert!(c.sender_key.is_some() && c.receiver_key.is_none());
}

/// The pure third ACK is lost; the client's first data carries MP_CAPABLE length 22 in place of
/// a DSS (RFC 8684 L836–855) and completes the handshake.
fn lost_third_ack_client_sends_first(csum: bool) {
    let (mut n, h) = mptcp_net(CongestionControlKind::Cubic, csum);
    n.drop_next(Dir::AtoB, is_pure_ack);
    run_apps(&mut n, &mut apps(h, 10_000, 10_000), SECS);
    let (c, len) = capable(&first_payload(&n, Dir::AtoB)).unwrap();
    assert_eq!(len, dlen(csum));
    assert!(c.data_len.is_some());
    assert_eq!(n.taps.iter().filter(|t| is_synack(&t.1)).count(), 1);
    assert_mptcp(&n);
}

/// The third ACK and the first data packet are both lost: the next segment of the same
/// MP_CAPABLE mapping completes the handshake out of order. The server's answers are slow, so
/// the client is still unconfirmed at its RTO and the retransmission carries MP_CAPABLE again.
fn lost_third_ack_retransmitted_and_split_mapping(csum: bool) {
    let (mut n, h) = mptcp_net(CongestionControlKind::Cubic, csum);
    n.drop_next(Dir::AtoB, is_pure_ack);
    n.drop_next(Dir::AtoB, |s| !s.payload.is_empty());
    let slow = Duration::from_millis(1500);
    n.delay(Dir::BtoA, move |s| {
        (!s.flags.contains(TcpFlags::SYN)).then_some(slow)
    });
    run_apps(&mut n, &mut apps(h, 20_000, 20_000), SECS);
    let c22: Vec<_> = (n.taps.iter())
        .filter(|t| t.0 == Dir::AtoB && capable(&t.1).is_some_and(|c| c.1 == dlen(csum)))
        .map(|t| t.1.seq)
        .collect();
    let first = c22[0];
    assert!(c22.iter().any(|&s| s != first), "split: {c22:?}");
    assert!(c22[1..].contains(&first), "retransmitted: {c22:?}");
    assert_mptcp(&n);
}

fn server_sends_first(csum: bool) {
    let (mut n, h) = mptcp_net(CongestionControlKind::Cubic, csum);
    let mut apps = apps(h, 10_000, 10_000);
    apps[0].hold = true;
    run_apps(&mut n, &mut apps, SECS);
    let first = n.taps.iter().find(|t| !t.1.payload.is_empty()).unwrap();
    assert_eq!(first.0, Dir::BtoA);
    assert!(has_dss(&first.1) && capable(&first.1).is_none());
    // The server's DSS confirmed the client before it wrote.
    assert!(has_dss(&first_payload(&n, Dir::AtoB)));
    assert_mptcp(&n);
}

/// The client's first data (MP_CAPABLE with data) is held back, so it reaches the server
/// after the server's own first data went out with a DSS (RFC 8684 L857–873); the client
/// writes before it knows.
fn both_send_first_data_at_once(csum: bool) {
    let (mut n, h) = mptcp_net(CongestionControlKind::Cubic, csum);
    let held = Duration::from_millis(50);
    n.delay(Dir::AtoB, move |s| {
        capable(s)
            .is_some_and(|c| c.1 == dlen(csum))
            .then_some(held)
    });
    run_apps(&mut n, &mut apps(h, 10_000, 10_000), SECS);
    assert_eq!(
        capable(&first_payload(&n, Dir::AtoB)).unwrap().1,
        dlen(csum)
    );
    assert!(has_dss(&first_payload(&n, Dir::BtoA)));
    assert!(first_delivery(&n, Dir::BtoA) < first_delivery(&n, Dir::AtoB));
    assert_mptcp(&n);
}

/// Review Focus 2: the client never writes; the server's DATA_ACK still confirms it, so an
/// MP_JOIN SYN goes out at once.
fn idle_client_still_confirmed(csum: bool) {
    let (mut n, h) = mptcp_net(CongestionControlKind::Cubic, csum);
    let dss_in =
        |n: &mut Net<ChaCha20Rng>| (n.delivered.iter()).any(|d| d.0 == Dir::BtoA && has_dss(&d.2));
    assert!(n.run_until(t(5), dss_in));
    assert!(accepted_mptcp(&n).is_some());
    assert!(n.taps.iter().all(|t| t.1.payload.is_empty()));
    let now = n.now;
    (n.a.add_subflow(now, h, sa(3, 0).ip(), sa(2, 80), 1500, false)).unwrap();
    let join =
        |n: &mut Net<ChaCha20Rng>| (n.taps.iter()).any(|t| t.0 == Dir::AtoB && is_join_syn(&t.1));
    assert!(n.run_until(now, join));
    assert_mptcp(&n);
}

/// Review Focus 3: the third ACK is lost and the server never writes: the client's first
/// data packet carries the keys and the connection does not stall.
fn lost_third_ack_idle_server(csum: bool) {
    let (mut n, h) = mptcp_net(CongestionControlKind::Cubic, csum);
    n.drop_next(Dir::AtoB, is_pure_ack);
    let mut apps = apps(h, 10_000, 0);
    apps[1].hold = true;
    run_apps(&mut n, &mut apps, SECS);
    assert_eq!(
        capable(&first_payload(&n, Dir::AtoB)).unwrap().1,
        dlen(csum)
    );
    assert!(
        n.taps
            .iter()
            .all(|t| t.0 == Dir::AtoB || t.1.payload.is_empty())
    );
    assert_mptcp(&n);
}

/// Sets C on every MP_CAPABLE of a segment that is not a SYN.
fn set_c(s: &mut Seg) -> bool {
    let mut i = 0;
    while !s.flags.contains(TcpFlags::SYN) && i + 1 < s.options.len() {
        match s.options[i] {
            0 => break,
            1 => i += 1,
            kind => {
                if kind == 30 && s.options[i + 2] >> 4 == 0 {
                    s.options[i + 3] |= CAP_C;
                }
                i += usize::from(s.options[i + 1]).max(2);
            }
        }
    }
    true
}

/// The SYN has C=0 and the confirming MP_CAPABLE C=1, in either form: the server may not join
/// to the client's initial address and port (RFC 8684 L924–932).
fn peer_c_from_final_ack(csum: bool) {
    for with_data in [false, true] {
        let (mut n, h) = mptcp_net(CongestionControlKind::Cubic, csum);
        n.rewrite(Dir::AtoB, set_c);
        if with_data {
            n.drop_next(Dir::AtoB, is_pure_ack);
            n.a.connection(h).unwrap().write(&[1; 1000]).unwrap();
        }
        assert!(n.run_until(t(5), |n| accepted_mptcp(n).is_some()));
        let syn = &n.taps[0].1;
        assert_eq!(capable(syn).unwrap().0.flags, flags(csum));
        let confirming = n.delivered.iter().find(|d| {
            d.0 == Dir::AtoB && !d.2.flags.contains(TcpFlags::SYN) && capable(&d.2).is_some()
        });
        let (c, len) = capable(&confirming.unwrap().2).unwrap();
        assert_eq!(
            (c.flags, len),
            (flags(csum) | CAP_C, if with_data { dlen(csum) } else { 20 })
        );
        let hb = accepted_mptcp(&n).unwrap();
        let initial = n.a.connection(h).unwrap().local();
        let now = n.now;
        let add =
            n.b.add_subflow(now, hb, sa(2, 0).ip(), initial, 1500, false);
        assert_eq!(add, Err(AddSubflowError::PeerForbidsJoin));
    }
}

/// Outgoing joins wait for a DSS from the peer (RFC 8684 L884–887): the client's first DSS,
/// its DATA_ACK for the server's 1 KiB, is held 500 ms.
fn server_add_subflow_waits_for_peer_dss(csum: bool) {
    let (mut n, h) = mptcp_net(CongestionControlKind::Cubic, csum);
    n.delay(Dir::AtoB, |s| {
        has_dss(s).then_some(Duration::from_millis(500))
    });
    assert!(n.run_until(t(5), |n| accepted_mptcp(n).is_some()));
    let hb = accepted_mptcp(&n).unwrap();
    let now = n.now;
    n.b.connection(hb).unwrap().write(&[7; 1024]).unwrap();
    let initial = n.a.connection(h).unwrap().local();
    (n.b.add_subflow(now, hb, sa(2, 0).ip(), initial, 1500, false)).unwrap();
    let join =
        |n: &Net<ChaCha20Rng>| (n.taps.iter()).any(|t| t.0 == Dir::BtoA && is_join_syn(&t.1));
    let dss_in =
        |n: &Net<ChaCha20Rng>| (n.delivered.iter()).any(|d| d.0 == Dir::AtoB && has_dss(&d.2));
    assert!(n.run_until(t(5), |n| {
        assert!(dss_in(n) || !join(n), "join before the peer's DSS");
        dss_in(n)
    }));
    assert!(n.now >= now + Duration::from_millis(500));
    assert!(join(&n));
}

/// Every scenario runs with checksums off (A=0) and on (A=1).
macro_rules! both {
    ($($f:ident),*) => {
        mod a0 { $(#[test] fn $f() { super::$f(false) })* }
        mod a1 { $(#[test] fn $f() { super::$f(true) })* }
    };
}
both!(
    mptcp_accept_and_transfer,
    synack_carries_v1_h_only_and_c0,
    lost_third_ack_client_sends_first,
    lost_third_ack_retransmitted_and_split_mapping,
    server_sends_first,
    both_send_first_data_at_once,
    idle_client_still_confirmed,
    lost_third_ack_idle_server,
    peer_c_from_final_ack,
    server_add_subflow_waits_for_peer_dss
);
