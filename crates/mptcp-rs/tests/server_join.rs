//! The MP_JOIN responder between two `Endpoint`s (M4a Task 6): joins answered on a listener,
//! matched to their connection by token and HMAC alone, sharing the subflow cap with
//! outgoing joins. `a` connects from 10.0.1.1; its second path is 10.0.2.1.
mod support;

use std::cell::Cell;
use std::net::{IpAddr, SocketAddr};
use std::rc::Rc;
use std::time::Duration;

use mptcp_rs::crypto::key_token_idsn;
use mptcp_rs::wire::mptcp::{self, MpJoin, MptcpOption};
use mptcp_rs::wire::packet::TcpFlags;
use mptcp_rs::wire::tcp_options::{TcpOpt, walk};
use mptcp_rs::{
    AddSubflowError, CloseReason, ConnectConfig, ConnectionHandle, Event, ListenConfig, SeqNum,
    SubflowId,
};
use rand_chacha::ChaCha20Rng;
use support::*;

/// A normal MPTCP close waits out TIME-WAIT (2·MSL = 120 s).
const SECS: u64 = 300;
const A1: &str = "10.0.1.1";
const A2: &str = "10.0.2.1";

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn server() -> SocketAddr {
    sa(2, 80)
}

/// `b` listens on 10.0.0.2:80; `a` opens an MPTCP connection to it from `A1`.
fn net() -> (Net<ChaCha20Rng>, ConnectionHandle) {
    let mut n = idle_net();
    n.b.listen(server(), ListenConfig::default()).unwrap();
    let cfg = ConnectConfig::default();
    let h = n.a.connect_mptcp(n.now, ip(A1), server(), cfg).unwrap();
    (n, h)
}

/// `a` joins from `from` to `to`.
fn add(
    n: &mut Net<ChaCha20Rng>,
    h: ConnectionHandle,
    from: &str,
    to: SocketAddr,
    backup: bool,
) -> SubflowId {
    let now = n.now;
    n.a.add_subflow(now, h, ip(from), to, 1500, backup).unwrap()
}

fn mptcp_opts(s: &Seg) -> Vec<MptcpOption> {
    walk(&s.options)
        .filter_map(|o| match o {
            Ok(TcpOpt::Mptcp(raw)) => mptcp::parse(raw).ok(),
            _ => None,
        })
        .collect()
}

fn is_join_syn(s: &Seg) -> bool {
    let syn = |o: &MptcpOption| matches!(o, MptcpOption::Join(MpJoin::Syn { .. }));
    s.flags == TcpFlags::SYN && mptcp_opts(s).iter().any(syn)
}

/// The initiator's third ACK, or a repeat of it (on any ACK it sends while joining, a FIN
/// included).
fn is_join_ack(s: &Seg) -> bool {
    let ack = |o: &MptcpOption| matches!(o, MptcpOption::Join(MpJoin::Ack { .. }));
    let f = s.flags;
    f.contains(TcpFlags::ACK) && !f.contains(TcpFlags::SYN) && mptcp_opts(s).iter().any(ack)
}

fn has_dss(s: &Seg) -> bool {
    (mptcp_opts(s).iter()).any(|o| matches!(o, MptcpOption::Dss(_)))
}

/// The MP_TCPRST reason of every RST sent in `dir` (`None`: the RST carried none).
fn rsts(n: &Net<ChaCha20Rng>, dir: Dir) -> Vec<Option<u8>> {
    let reason = |s: &Seg| {
        mptcp_opts(s).into_iter().find_map(|o| match o {
            MptcpOption::TcpRst { reason, .. } => Some(reason),
            _ => None,
        })
    };
    (n.taps.iter())
        .filter(|t| t.0 == dir && t.1.flags.contains(TcpFlags::RST))
        .map(|t| reason(&t.1))
        .collect()
}

fn ups(events: &[(ConnectionHandle, Event)]) -> Vec<(ConnectionHandle, SubflowId)> {
    let up = |(h, e): &(ConnectionHandle, Event)| match e {
        Event::SubflowUp { subflow } => Some((*h, *subflow)),
        _ => None,
    };
    events.iter().filter_map(up).collect()
}

/// `SubflowDown`s: subflow, reason and the MP_TCPRST reason of the RST that ended it.
fn downs(events: &[(ConnectionHandle, Event)]) -> Vec<(SubflowId, CloseReason, Option<u8>)> {
    let down = |(_, e): &(ConnectionHandle, Event)| match e {
        Event::SubflowDown {
            subflow,
            reason,
            rst,
        } => Some((*subflow, *reason, rst.map(|r| r.reason))),
        _ => None,
    };
    events.iter().filter_map(down).collect()
}

fn accepted(n: &Net<ChaCha20Rng>) -> ConnectionHandle {
    accepted_any(&n.events_b)[0]
}

fn apps(h: ConnectionHandle, len: usize) -> [App; 2] {
    [
        App::new(false, Some(h), len, 0),
        App::new(true, None, len, 1),
    ]
}

/// XORs octet `at` of the MP_JOIN option of length `len` in `s`.
fn flip_join(s: &mut Seg, len: u8, at: usize) {
    if let Some(i) = join_at(s, len) {
        s.options[i + at] ^= 0xff;
    }
}

/// Where the MP_JOIN option of length `len` starts in `s`.
fn join_at(s: &Seg, len: u8) -> Option<usize> {
    let mut i = 0;
    while i + 1 < s.options.len() {
        match s.options[i] {
            0 => return None,
            1 => i += 1,
            kind => {
                let l = s.options[i + 1];
                if kind == 30 && l == len && s.options[i + 2] >> 4 == 1 {
                    return Some(i);
                }
                i += usize::from(l).max(2);
            }
        }
    }
    None
}

/// Runs until join `j` of `a` is up on both sides or down on `a`.
fn settle(n: &mut Net<ChaCha20Rng>, j: SubflowId) {
    let done = |n: &mut Net<ChaCha20Rng>| {
        let up = ups(&n.events_a).iter().any(|u| u.1 == j) && !ups(&n.events_b).is_empty();
        up || downs(&n.events_a).iter().any(|d| d.0 == j)
    };
    assert!(n.run_until(t(10), done));
}

/// A join that never comes up: `a` sees it reset with `reason`, `b` reports nothing.
fn assert_refused(n: &Net<ChaCha20Rng>, j: SubflowId, from_b: Option<u8>) {
    assert_eq!(rsts(n, Dir::BtoA), [from_b]);
    assert_eq!(downs(&n.events_a), [(j, CloseReason::Reset, from_b)]);
    assert!(ups(&n.events_a).is_empty() && ups(&n.events_b).is_empty());
    assert!(downs(&n.events_b).is_empty());
}

#[test]
fn join_from_second_address() {
    let (mut n, h) = net();
    let j = add(&mut n, h, A2, server(), false);
    run_apps(&mut n, &mut apps(h, 1 << 20), SECS);
    assert_eq!(ups(&n.events_a), [(h, j)]);
    assert_eq!(ups(&n.events_b).len(), 1);
    for path in [A1, A2] {
        let data = |dir: Dir, t: &(Dir, Seg)| {
            let end = if dir == Dir::AtoB { t.1.src } else { t.1.dst };
            t.0 == dir && end.ip() == ip(path) && !t.1.payload.is_empty()
        };
        for dir in [Dir::AtoB, Dir::BtoA] {
            assert!(n.taps.iter().any(|t| data(dir, t)), "{path} {dir:?}");
        }
    }
}

/// Relay (spec G4): a NAT makes the join appear from 192.0.2.7:40000, an address the server
/// never saw. Token and HMAC alone match it to the connection.
#[test]
fn join_from_unseen_address() {
    let (mut n, h) = net();
    let relay: SocketAddr = "192.0.2.7:40000".parse().unwrap();
    let real = Rc::new(Cell::new(None));
    let seen = real.clone();
    n.rewrite(Dir::AtoB, move |s| {
        if s.src.ip() == ip(A2) {
            seen.set(Some(s.src));
            s.src = relay;
        }
        true
    });
    n.rewrite(Dir::BtoA, move |s| {
        if s.dst == relay {
            s.dst = real.get().unwrap();
        }
        true
    });
    let j = add(&mut n, h, A2, server(), false);
    run_apps(&mut n, &mut apps(h, 100_000), SECS);
    assert_eq!(ups(&n.events_a), [(h, j)]);
    assert_eq!(ups(&n.events_b).len(), 1);
    assert!((n.taps.iter()).any(|t| is_synack(&t.1) && t.1.dst == relay));
}

#[test]
fn join_bad_token_rst() {
    let (mut n, h) = net();
    n.rewrite(Dir::AtoB, |s| {
        if is_join_syn(s) {
            flip_join(s, 12, 4);
        }
        true
    });
    let j = add(&mut n, h, A2, server(), false);
    run_apps_with_rst(&mut n, &mut apps(h, 100_000), SECS);
    assert_refused(&n, j, Some(1));
}

#[test]
fn join_bad_hmac_rst_connection_survives() {
    let (mut n, h) = net();
    n.rewrite(Dir::AtoB, |s| {
        flip_join(s, 24, 4);
        true
    });
    let j = add(&mut n, h, A2, server(), false);
    run_apps_with_rst(&mut n, &mut apps(h, 100_000), SECS);
    assert_refused(&n, j, Some(1));
}

#[test]
fn third_ack_without_mp_join_rst() {
    let (mut n, h) = net();
    n.rewrite(Dir::AtoB, |s| {
        if let Some(i) = join_at(s, 24) {
            s.options[i..i + 24].fill(1);
        }
        true
    });
    let j = add(&mut n, h, A2, server(), false);
    run_apps_with_rst(&mut n, &mut apps(h, 100_000), SECS);
    assert_refused(&n, j, Some(1));
}

/// The initiator resends its third ACK until the responder acknowledges it (RFC 8684
/// L1155–1164).
#[test]
fn lost_third_join_ack() {
    let (mut n, h) = net();
    n.drop_next(Dir::AtoB, is_join_ack);
    let j = add(&mut n, h, A2, server(), false);
    run_apps(&mut n, &mut apps(h, 100_000), SECS);
    assert_eq!(ups(&n.events_a), [(h, j)]);
    assert_eq!(ups(&n.events_b).len(), 1);
    let sent = n.taps.iter().filter(|t| is_join_ack(&t.1)).count();
    assert!(sent >= 2, "{sent}");
}

/// The responder's answer to the third ACK is lost: the retransmitted third ACK draws a plain
/// ACK, and neither side attaches the subflow twice.
#[test]
fn lost_fourth_join_ack() {
    let (mut n, h) = net();
    // Everything the server sends on the join after its SYN/ACK is lost until the third ACK
    // has been sent twice.
    let sent = Rc::new(Cell::new(0));
    let seen = sent.clone();
    n.rewrite(Dir::AtoB, move |s| {
        seen.set(seen.get() + usize::from(is_join_ack(s)));
        true
    });
    n.rewrite(Dir::BtoA, move |s| {
        s.dst.ip() != ip(A2) || s.flags.contains(TcpFlags::SYN) || sent.get() >= 2
    });
    let j = add(&mut n, h, A2, server(), false);
    run_apps(&mut n, &mut apps(h, 100_000), SECS);
    assert_eq!(ups(&n.events_a), [(h, j)]);
    assert_eq!(ups(&n.events_b).len(), 1);
    let sent = n.taps.iter().filter(|t| is_join_ack(&t.1)).count();
    assert!(sent >= 2, "{sent}");
}

/// Spec G2a: a join naming a connection still waiting for the client's key is refused.
#[test]
fn join_before_client_key_refused() {
    let (mut n, _) = net();
    n.drop_next(Dir::AtoB, is_pure_ack);
    let third = |n: &mut Net<ChaCha20Rng>| n.taps.iter().any(|t| is_pure_ack(&t.1));
    assert!(n.run_until(t(5), third));
    assert!(accepted_any(&n.events_b).is_empty());
    let synack = &n.taps.iter().find(|t| is_synack(&t.1)).unwrap().1;
    let key = mptcp_opts(synack).into_iter().find_map(|o| match o {
        MptcpOption::Capable(c) => c.sender_key,
        _ => None,
    });
    let join = MptcpOption::Join(MpJoin::Syn {
        backup: false,
        addr_id: 1,
        token: key_token_idsn(key.unwrap()).0,
        nonce: 7,
    });
    let mut opts = [0; 12];
    mptcp::encode(&join, &mut opts).unwrap();
    let src: SocketAddr = "10.0.2.1:40000".parse().unwrap();
    let syn = pkt(
        src,
        server(),
        SeqNum(1),
        SeqNum(0),
        TcpFlags::SYN,
        &opts,
        &[],
    );
    n.send(Dir::AtoB, syn);
    let refused = |n: &mut Net<ChaCha20Rng>| !rsts(n, Dir::BtoA).is_empty();
    assert!(n.run_until(n.now + Duration::from_millis(500), refused));
    assert_eq!(rsts(&n, Dir::BtoA), [Some(1)]);
}

/// Review Focus 1 (spec G2a amendment): the join SYN on the fast path arrives before the
/// client's first DSS on the slow one, and is accepted.
#[test]
fn join_beats_clients_first_dss() {
    let (mut n, h) = net();
    n.delay(Dir::AtoB, |s| {
        let ms = if s.src.ip() == ip(A1) { 200 } else { 10 };
        Some(Duration::from_millis(ms))
    });
    n.a.connection(h).unwrap().write(&[1; 100_000]).unwrap();
    let j = add(&mut n, h, A2, server(), false);
    settle(&mut n, j);
    assert_eq!(ups(&n.events_a), [(h, j)]);
    assert_eq!(ups(&n.events_b).len(), 1);
    let dss_in =
        |n: &mut Net<ChaCha20Rng>| (n.delivered.iter()).any(|d| d.0 == Dir::AtoB && has_dss(&d.2));
    assert!(n.run_until(t(10), dss_in));
    let at = |f: fn(&Seg) -> bool| {
        let d = n.delivered.iter().find(|d| d.0 == Dir::AtoB && f(&d.2));
        d.unwrap().1
    };
    // The server had the client's key, and no DSS from it yet, when the join SYN arrived.
    assert!(at(is_join_syn) < at(has_dss));
}

#[test]
fn join_to_unlistened_port_rst() {
    let (mut n, h) = net();
    let j = add(&mut n, h, A2, sa(2, 81), false);
    run_apps_with_rst(&mut n, &mut apps(h, 100_000), SECS);
    assert_refused(&n, j, None);
}

#[test]
fn join_after_unlisten_rst() {
    let (mut n, h) = net();
    let mut apps = apps(h, 100_000);
    assert!(n.run_until(t(5), |n| !accepted_any(&n.events_b).is_empty()));
    assert!(n.b.unlisten(server()));
    let j = add(&mut n, h, A2, server(), false);
    run_apps_with_rst(&mut n, &mut apps, SECS);
    assert_refused(&n, j, None);
}

/// `a` has written, so both sides have seen the other's DSS, and joins from 10.0.2.1 to
/// 10.0.2.`k` are up: `k + 1` subflows on each side.
fn subflows_up(k: u8) -> (Net<ChaCha20Rng>, ConnectionHandle) {
    let (mut n, h) = net();
    n.a.connection(h).unwrap().write(&[1; 100]).unwrap();
    for i in 1..=k {
        add(&mut n, h, &format!("10.0.2.{i}"), server(), false);
    }
    let all = |n: &mut Net<ChaCha20Rng>| ups(&n.events_a).len() == usize::from(k);
    assert!(n.run_until(t(10), |n| all(n)
        && ups(&n.events_b).len() == usize::from(k)));
    (n, h)
}

/// Spec G3b, deterministic order: with 7 subflows up, an incoming join completes first and
/// takes the last slot; then the server's own join is refused.
#[test]
fn cap_shared_incoming_then_outgoing() {
    let (mut n, h) = subflows_up(6);
    let j = add(&mut n, h, "10.0.3.1", server(), false);
    settle(&mut n, j);
    assert_eq!(ups(&n.events_a).last(), Some(&(h, j)));
    assert_eq!(ups(&n.events_b).len(), 7);
    let (hb, now) = (accepted(&n), n.now);
    let to = n.a.connection(h).unwrap().local();
    let add_b = n.b.add_subflow(now, hb, sa(2, 0).ip(), to, 1500, false);
    assert_eq!(add_b, Err(AddSubflowError::TooManySubflows));
    let add_a =
        n.a.add_subflow(now, h, ip("10.0.3.2"), server(), 1500, false);
    assert_eq!(add_a, Err(AddSubflowError::TooManySubflows));
}

/// Spec G3b: each side reserves its 8th slot with an outgoing join before the other's SYN
/// arrives, so each SYN finds the cap reached and draws MP_TCPRST "Lack of resources".
#[test]
fn cap_simultaneous_reservations_both_refused() {
    let (mut n, h) = subflows_up(6);
    let a_listen: SocketAddr = "10.0.1.1:7000".parse().unwrap();
    n.a.listen(a_listen, ListenConfig::default()).unwrap();
    let (hb, now) = (accepted(&n), n.now);
    let ja = add(&mut n, h, "10.0.3.1", server(), false);
    let jb =
        n.b.add_subflow(now, hb, sa(2, 0).ip(), a_listen, 1500, false);
    let both =
        |n: &mut Net<ChaCha20Rng>| !downs(&n.events_a).is_empty() && !downs(&n.events_b).is_empty();
    assert!(n.run_until(t(20), both));
    let reset = CloseReason::Reset;
    assert_eq!(downs(&n.events_a), [(ja, reset, Some(2))]);
    assert_eq!(downs(&n.events_b), [(jb.unwrap(), reset, Some(2))]);
    assert_eq!(
        (rsts(&n, Dir::AtoB), rsts(&n, Dir::BtoA)),
        (vec![Some(2)], vec![Some(2)])
    );
    // 7 subflows up and one reserved at most, on each side.
    assert_eq!((ups(&n.events_a).len(), ups(&n.events_b).len()), (6, 6));
}

/// Spec G3b: a subflow that was reset frees its slot for a new join.
#[test]
fn cap_slot_reused_after_failure() {
    let (mut n, h) = subflows_up(7);
    let now = n.now;
    let full =
        n.a.add_subflow(now, h, ip("10.0.3.1"), server(), 1500, false);
    assert_eq!(full, Err(AddSubflowError::TooManySubflows));
    n.a.remove_address(now, h, ip("10.0.2.7")).unwrap();
    assert!(n.run_until(t(20), |n| downs(&n.events_b).len() == 1));
    let j = add(&mut n, h, "10.0.3.1", server(), false);
    settle(&mut n, j);
    assert_eq!(ups(&n.events_a).last(), Some(&(h, j)));
    assert_eq!(ups(&n.events_b).len(), 8);
}

/// Spec G4a: the connection was accepted on :80; its join arrives on :81, where `b` also
/// listens.
#[test]
fn pending_join_via_other_listener() {
    let (mut n, h) = net();
    n.b.listen(sa(2, 81), ListenConfig::default()).unwrap();
    let j = add(&mut n, h, A2, sa(2, 81), false);
    run_apps(&mut n, &mut apps(h, 100_000), SECS);
    assert_eq!(ups(&n.events_a), [(h, j)]);
    assert_eq!(ups(&n.events_b).len(), 1);

    // The third join ACK is lost and :81 stops listening while the join is pending: the join
    // is reset and gives its half-open slot back, so a new :81 with one slot takes a join.
    let (mut n, h) = net();
    let mut l = ListenConfig::default();
    l.max_half_open = 1;
    n.b.listen(sa(2, 81), l.clone()).unwrap();
    n.drop_next(Dir::AtoB, is_join_ack);
    let j = add(&mut n, h, A2, sa(2, 81), false);
    let lost = |n: &mut Net<ChaCha20Rng>| n.taps.iter().any(|t| is_join_ack(&t.1));
    assert!(n.run_until(t(5), lost));
    assert!(n.b.unlisten(sa(2, 81)));
    assert!(n.run_until(t(10), |n| !downs(&n.events_a).is_empty()));
    assert_eq!(downs(&n.events_a), [(j, CloseReason::Reset, Some(1))]);
    n.b.listen(sa(2, 81), l).unwrap();
    let j = add(&mut n, h, "10.0.3.1", sa(2, 81), false);
    assert!(n.run_until(t(20), |n| ups(&n.events_a) == [(h, j)]));
    assert_eq!(ups(&n.events_b).len(), 1);
}

/// `b` writes `len` octets on `hb` while `a` reads them on `h`; true once all are read.
fn b_to_a(n: &mut Net<ChaCha20Rng>, h: ConnectionHandle, hb: ConnectionHandle, len: usize) -> bool {
    let (mut written, mut got, mut buf) = (0, 0, vec![0; 65536]);
    let deadline = n.now + Duration::from_secs(120);
    n.run_until(deadline, |n| {
        let c = n.b.connection(hb).unwrap();
        while written < len {
            let w = c.write(&buf[..(len - written).min(65536)]).unwrap();
            if w == 0 {
                break;
            }
            written += w;
        }
        let c = n.a.connection(h).unwrap();
        while let Ok(k @ 1..) = c.read(&mut buf) {
            got += k;
        }
        flush(n);
        got == len
    })
}

/// Spec G3c: `a` joins with B=1, so the server sends on that subflow only once path A has
/// failed (all its packets dropped).
#[test]
fn backup_join_unused_until_primary_fails() {
    let (mut n, h) = net();
    add(&mut n, h, A2, server(), true);
    assert!(n.run_until(t(5), |n| ups(&n.events_b).len() == 1));
    let hb = accepted(&n);
    let on_backup = |n: &Net<ChaCha20Rng>| {
        let data = |t: &&(Dir, Seg)| t.0 == Dir::BtoA && !t.1.payload.is_empty();
        n.taps.iter().filter(data).any(|t| t.1.dst.ip() == ip(A2))
    };
    assert!(b_to_a(&mut n, h, hb, 100_000));
    assert!(!on_backup(&n));
    n.rewrite(Dir::AtoB, |s| s.src.ip() != ip(A1));
    n.rewrite(Dir::BtoA, |s| s.dst.ip() != ip(A1));
    assert!(b_to_a(&mut n, h, hb, 100_000));
    assert!(on_backup(&n));
}

/// `a` writes, also listens on 10.0.1.1:7000, and is past the handshake; returns that
/// address and `b`'s handle.
fn client_listens(n: &mut Net<ChaCha20Rng>, h: ConnectionHandle) -> (SocketAddr, ConnectionHandle) {
    let a_listen: SocketAddr = "10.0.1.1:7000".parse().unwrap();
    n.a.listen(a_listen, ListenConfig::default()).unwrap();
    n.a.connection(h).unwrap().write(&[1; 100]).unwrap();
    let dss_in = |n: &mut Net<ChaCha20Rng>| {
        (n.delivered.iter()).any(|d| d.0 == Dir::AtoB && !d.2.payload.is_empty())
    };
    assert!(n.run_until(t(5), |n| dss_in(n) && !accepted_any(&n.events_b).is_empty()));
    (a_listen, accepted(n))
}

/// Spec G3a: a connection `a` opened takes a join through `a`'s listener while its own
/// outgoing join to `b` runs.
#[test]
fn client_role_connection_accepts_join() {
    let (mut n, h) = net();
    let (a_listen, hb) = client_listens(&mut n, h);
    let ja = add(&mut n, h, A2, server(), false);
    let now = n.now;
    let jb =
        n.b.add_subflow(now, hb, sa(2, 0).ip(), a_listen, 1500, false);
    let both =
        |n: &mut Net<ChaCha20Rng>| ups(&n.events_a).len() == 2 && ups(&n.events_b).len() == 2;
    assert!(n.run_until(t(10), both));
    assert!(ups(&n.events_a).iter().all(|u| u.0 == h));
    assert!(ups(&n.events_b).iter().all(|u| u.0 == hb));
    assert!(ups(&n.events_a).contains(&(h, ja)));
    assert!(ups(&n.events_b).contains(&(hb, jb.unwrap())));
}

/// §7a: the server joins to an address of the client where the client listens.
#[test]
fn server_add_subflow_to_client_listener() {
    let (mut n, h) = net();
    let (a_listen, hb) = client_listens(&mut n, h);
    let now = n.now;
    let jb =
        n.b.add_subflow(now, hb, sa(2, 0).ip(), a_listen, 1500, false);
    let up = |n: &mut Net<ChaCha20Rng>| ups(&n.events_a).len() == 1;
    assert!(n.run_until(t(10), |n| up(n) && ups(&n.events_b) == [(hb, jb.unwrap())]));
    assert_eq!(ups(&n.events_a)[0].0, h);
    let joined = |t: &(Dir, Seg)| t.0 == Dir::BtoA && t.1.dst == a_listen;
    assert!(b_to_a(&mut n, h, hb, 1 << 20));
    assert!(n.taps.iter().any(|t| joined(t) && !t.1.payload.is_empty()));
}

/// The server's application writes its whole response and closes before the join arrives:
/// the connection is still live, so the join comes up and carries the client's upload.
#[test]
fn join_after_server_app_closed() {
    let (mut n, h) = net();
    // The join starts once `a` is Confirmed; its path is slower, so the server has closed by
    // the time the SYN arrives.
    n.delay(Dir::AtoB, |s| {
        (s.src.ip() == ip(A2)).then_some(Duration::from_millis(50))
    });
    let j = add(&mut n, h, A2, server(), false);
    let mut apps = [
        App::new(false, Some(h), 1 << 20, 0),
        App::new(true, None, 10_000, 1),
    ];
    let closed = n.run_until(t(5), |n| {
        for i in 0..apps.len() {
            let side = apps[i].on_b;
            let mine = |a: &App| a.h.filter(|_| a.on_b == side);
            let claimed: Vec<_> = apps.iter().filter_map(mine).collect();
            apps[i].drive(n, &claimed);
        }
        flush(n);
        apps[1].closing
    });
    assert!(closed);
    assert!(!n.delivered.iter().any(|d| is_join_syn(&d.2)));
    run_apps(&mut n, &mut apps, SECS);
    assert_eq!(ups(&n.events_a), [(h, j)]);
    assert_eq!(ups(&n.events_b).len(), 1);
    let up = |t: &(Dir, Seg)| t.0 == Dir::AtoB && t.1.src.ip() == ip(A2);
    assert!(n.taps.iter().any(|t| up(t) && !t.1.payload.is_empty()));
}

/// RFC 8684 L2191–2196: a RST with MP_FASTCLOSE and the server's key, on a join the server is
/// answering (its third ACK lost), tears the whole connection down.
#[test]
fn fastclose_rst_on_pending_join() {
    let (mut n, h) = net();
    n.drop_next(Dir::AtoB, is_join_ack);
    add(&mut n, h, A2, server(), false);
    let lost = |n: &mut Net<ChaCha20Rng>| n.taps.iter().any(|t| is_join_ack(&t.1));
    assert!(n.run_until(t(5), lost));
    let syn = n.taps.iter().find(|t| is_join_syn(&t.1)).unwrap().1.clone();
    let synack = &n.taps.iter().find(|t| is_synack(&t.1)).unwrap().1;
    let key = mptcp_opts(synack).into_iter().find_map(|o| match o {
        MptcpOption::Capable(c) => c.sender_key,
        _ => None,
    });
    let mut opts = [0; 12];
    let fc = MptcpOption::FastClose {
        receiver_key: key.unwrap(),
    };
    mptcp::encode(&fc, &mut opts).unwrap();
    let seq = syn.seq.wrapping_add(1);
    let rst = pkt(syn.src, syn.dst, seq, SeqNum(0), TcpFlags::RST, &opts, &[]);
    n.send(Dir::AtoB, rst);
    let ended =
        |n: &mut Net<ChaCha20Rng>| (n.events_b.iter()).any(|e| matches!(e.1, Event::Closed { .. }));
    assert!(n.run_until(n.now + Duration::from_millis(100), ended));
    let closed: Vec<_> = (n.events_b.iter())
        .filter(|e| matches!(e.1, Event::Closed { .. }))
        .collect();
    let hb = accepted(&n);
    let reset = Event::Closed {
        reason: CloseReason::Reset,
    };
    assert_eq!(closed, [&(hb, reset)]);
    assert!(ups(&n.events_b).is_empty() && downs(&n.events_b).is_empty());
    // The initial subflow is reset too.
    let to_a1 = |t: &(Dir, Seg)| t.0 == Dir::BtoA && t.1.dst.ip() == ip(A1);
    assert!(
        n.taps
            .iter()
            .any(|t| to_a1(t) && t.1.flags.contains(TcpFlags::RST))
    );
}
