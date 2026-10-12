//! Every per-connection feature on an accepted connection (M4a Task 7, spec G8): the data path
//! after the handshake is the client's, so each case mirrors a client-side outcome with the
//! roles swapped. `a` connects from 10.0.1.1 and joins from 10.0.2.1; links lose 1% and
//! reorder 2% unless a test says otherwise.
mod support;

use std::cell::Cell;
use std::net::{IpAddr, SocketAddr};
use std::rc::Rc;
use std::time::Duration;

use mptcp_rs::crypto::add_addr_hmac;
use mptcp_rs::wire::mptcp::{self, Dss, MpJoin, MptcpOption};
use mptcp_rs::wire::packet::TcpFlags;
use mptcp_rs::wire::tcp_options::{TcpOpt, walk};
use mptcp_rs::{
    CloseReason, CongestionControlKind, ConnectConfig, ConnectionHandle, Event, ListenConfig,
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

/// `b` listens on 10.0.0.2:80 with `cc`; `a` opens an MPTCP connection to it from `A1`, over
/// lossy links seeded with `seed` (`lossy` false: no loss, no reordering).
fn net_with(
    seed: u64,
    lossy: bool,
    cc: CongestionControlKind,
) -> (Net<ChaCha20Rng>, ConnectionHandle) {
    let (loss, reorder) = if lossy { (10, 20) } else { (0, 0) };
    let mut n = Net::new(
        endpoint(1 + 2 * seed),
        endpoint(2 + 2 * seed),
        Link::new(100 + seed, loss, reorder),
        Link::new(200 + seed, loss, reorder),
    );
    let mut l = ListenConfig::default();
    l.connection.congestion_control = cc;
    n.b.listen(server(), l).unwrap();
    let mut cfg = ConnectConfig::default();
    cfg.congestion_control = cc;
    let h = n.a.connect_mptcp(n.now, ip(A1), server(), cfg).unwrap();
    (n, h)
}

fn net(lossy: bool) -> (Net<ChaCha20Rng>, ConnectionHandle) {
    net_with(1, lossy, CongestionControlKind::Cubic)
}

/// `a` joins from `A2`.
fn join(n: &mut Net<ChaCha20Rng>, h: ConnectionHandle) -> SubflowId {
    let now = n.now;
    n.a.add_subflow(now, h, ip(A2), server(), 1500, false)
        .unwrap()
}

fn mptcp_opts(s: &Seg) -> Vec<MptcpOption> {
    walk(&s.options)
        .filter_map(|o| match o {
            Ok(TcpOpt::Mptcp(raw)) => mptcp::parse(raw).ok(),
            _ => None,
        })
        .collect()
}

fn dss(s: &Seg) -> Option<Dss> {
    mptcp_opts(s).into_iter().find_map(|o| match o {
        MptcpOption::Dss(d) => Some(d),
        _ => None,
    })
}

fn is_data_fin(s: &Seg) -> bool {
    dss(s).is_some_and(|d| d.data_fin)
}

fn is_join(s: &Seg) -> bool {
    (mptcp_opts(s).iter()).any(|o| matches!(o, MptcpOption::Join(_)))
}

fn ups(events: &[(ConnectionHandle, Event)]) -> Vec<SubflowId> {
    let up = |(_, e): &(ConnectionHandle, Event)| match e {
        Event::SubflowUp { subflow } => Some(*subflow),
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

fn has(events: &[(ConnectionHandle, Event)], e: &Event) -> bool {
    events.iter().any(|x| x.1 == *e)
}

fn closed(events: &[(ConnectionHandle, Event)]) -> Vec<CloseReason> {
    let c = |(_, e): &(ConnectionHandle, Event)| match e {
        Event::Closed { reason } => Some(*reason),
        _ => None,
    };
    events.iter().filter_map(c).collect()
}

/// RSTs sent in `dir`.
fn rsts(n: &Net<ChaCha20Rng>, dir: Dir) -> Vec<Seg> {
    let rst = |t: &&(Dir, Seg)| t.0 == dir && t.1.flags.contains(TcpFlags::RST);
    n.taps.iter().filter(rst).map(|t| t.1.clone()).collect()
}

/// The MP_CAPABLE keys (client, server), from the client's third ACK.
fn keys(n: &Net<ChaCha20Rng>) -> (u64, u64) {
    let both = |t: &(Dir, Seg)| {
        mptcp_opts(&t.1).into_iter().find_map(|o| match o {
            MptcpOption::Capable(c) if t.0 == Dir::AtoB => c.sender_key.zip(c.receiver_key),
            _ => None,
        })
    };
    n.taps.iter().find_map(both).unwrap()
}

fn apps(h: ConnectionHandle, client: usize, server: usize) -> [App; 2] {
    [
        App::new(false, Some(h), client, 0),
        App::new(true, None, server, 1),
    ]
}

/// The client writes the first 1000 octets of its app's data (no app has closed yet) and runs
/// until the join is up on both sides; returns the server's handle and its id for the join.
fn joined(
    n: &mut Net<ChaCha20Rng>,
    h: ConnectionHandle,
    apps: &mut [App],
) -> (ConnectionHandle, SubflowId) {
    let w = n.a.connection(h).unwrap().write(&apps[0].out[..1000]);
    assert_eq!(w, Ok(1000));
    apps[0].written = 1000;
    let up = |n: &mut Net<ChaCha20Rng>| ups(&n.events_a).len() == 1 && ups(&n.events_b).len() == 1;
    assert!(n.run_until(t(10), up));
    (accepted_any(&n.events_b)[0], ups(&n.events_b)[0])
}

/// Runs the apps to the end; the first DATA_FIN goes in direction `first`.
fn close_first(first: Dir) {
    let (mut n, h) = net(true);
    join(&mut n, h);
    let mut apps = apps(h, 100_000, 100_000);
    // The other side writes 1 MiB, only after it has read: its DATA_FIN comes last.
    let late = if first == Dir::AtoB { 1 } else { 0 };
    apps[late].out = pattern(1 << 20, late);
    apps[late].hold = true;
    run_apps(&mut n, &mut apps, SECS);
    let fin = |t: &&(Dir, Seg)| is_data_fin(&t.1);
    let fins: Vec<_> = n.taps.iter().filter(fin).map(|t| t.0).collect();
    assert_eq!(fins[0], first);
    assert!(fins.contains(&Dir::AtoB) && fins.contains(&Dir::BtoA));
    assert_eq!((ups(&n.events_a).len(), ups(&n.events_b).len()), (1, 1));
}

#[test]
fn close_from_server_side() {
    close_first(Dir::BtoA);
}

#[test]
fn close_from_client_side() {
    close_first(Dir::AtoB);
}

/// One side aborts mid-transfer with both subflows up: it reports `Closed { Aborted }`, every
/// RST it sends carries MP_FASTCLOSE with the other side's key (one on each path), and the
/// other side reports one `Closed { Reset }` and no `SubflowDown`.
fn abort_by(server_aborts: bool) {
    let (mut n, h) = net(true);
    join(&mut n, h);
    let mut apps = apps(h, 1 << 20, 1 << 20);
    let (hb, _) = joined(&mut n, h, &mut apps);
    let (kc, ks) = keys(&n);
    let (dir, key) = if server_aborts {
        n.b.connection(hb).unwrap().abort();
        (Dir::BtoA, kc)
    } else {
        n.a.connection(h).unwrap().abort();
        (Dir::AtoB, ks)
    };
    flush(&mut n);
    let ended = |n: &mut Net<ChaCha20Rng>| {
        !closed(&n.events_a).is_empty() && !closed(&n.events_b).is_empty()
    };
    assert!(n.run_until(n.now + Duration::from_secs(5), ended));
    let (aborter, peer) = if server_aborts {
        (&n.events_b, &n.events_a)
    } else {
        (&n.events_a, &n.events_b)
    };
    assert_eq!(closed(aborter), [CloseReason::Aborted]);
    assert_eq!(closed(peer), [CloseReason::Reset]);
    assert!(downs(peer).is_empty(), "{peer:?}");
    let sent = rsts(&n, dir);
    let fc = MptcpOption::FastClose { receiver_key: key };
    assert!(sent.iter().all(|s| mptcp_opts(s) == [fc]), "{sent:?}");
    for path in [A1, A2] {
        let on = |s: &&Seg| (if server_aborts { s.dst } else { s.src }).ip() == ip(path);
        assert_eq!(sent.iter().filter(on).count(), 1, "{path}");
    }
}

#[test]
fn abort_from_server_sends_fastclose() {
    abort_by(true);
}

#[test]
fn abort_from_client_seen_by_server() {
    abort_by(false);
}

/// `options` without its MPTCP options (a middlebox that strips them); with `subtype`, only
/// those of that subtype.
fn without_mptcp(options: &[u8], subtype: Option<u8>) -> Vec<u8> {
    let mut i = 0;
    let mut kept = Vec::new();
    while i < options.len() {
        match options[i] {
            0 => break,
            1 => i += 1,
            kind => {
                let l = usize::from(options[i + 1]).max(2);
                let sub = options.get(i + 2).map(|b| b >> 4);
                if kind != 30 || subtype.is_some_and(|t| Some(t) != sub) {
                    kept.extend_from_slice(&options[i..i + l]);
                }
                i += l;
            }
        }
    }
    kept
}

/// RFC 8684 L2306–2328 on the server's only subflow: a middlebox strips the client's DSS
/// options, so no DATA_ACK ever confirms the server's DSS. The server writes first; its data is
/// ACKed without a DATA_ACK, so it falls back and sends the infinite mapping, on which the
/// client falls back too. The data is byte-exact both ways. No loss or reordering: our infinite
/// mapping goes out once, on whatever segment is next, so a link that loses or overtakes that
/// segment loses the switch (see the Task 7 report).
#[test]
fn server_dss_stripped_before_confirm_single_subflow_falls_back() {
    let (mut n, h) = net(false);
    n.rewrite(Dir::AtoB, |s| {
        s.options = without_mptcp(&s.options, Some(2));
        true
    });
    let mut apps = apps(h, 200_000, 200_000);
    apps[0].hold = true;
    run_apps(&mut n, &mut apps, SECS);
    assert!(has(&n.events_a, &Event::FellBack));
    assert!(has(&n.events_b, &Event::FellBack));
    let inf = |t: &(Dir, Seg)| {
        let m = dss(&t.1).and_then(|d| d.mapping);
        t.0 == Dir::BtoA && m.is_some_and(|m| m.data_len == 0)
    };
    assert!(n.taps.iter().any(inf));
}

/// The counterpart of the client's `joined_subflow_stripping_resets_only_it`: once the join is
/// up, the path of the joined subflow strips MPTCP options from what the client sends. The
/// server resets that subflow alone, never falls back, and the transfer completes on the
/// initial subflow.
#[test]
fn server_joined_subflow_stripping_resets_only_it() {
    let (mut n, h) = net(true);
    let j = join(&mut n, h);
    let mut apps = apps(h, 20_000, 1 << 20);
    apps[0].hold = true;
    let (_, sb) = joined(&mut n, h, &mut apps);
    n.rewrite(Dir::AtoB, |s| {
        if s.src.ip() == ip(A2) {
            s.options = without_mptcp(&s.options, None);
        }
        true
    });
    run_apps_with_rst(&mut n, &mut apps, SECS);
    assert_eq!(downs(&n.events_b), [(sb, CloseReason::Reset, None)]);
    assert!(!has(&n.events_a, &Event::FellBack) && !has(&n.events_b, &Event::FellBack));
    assert_eq!(downs(&n.events_a).len(), 1);
    assert_eq!(downs(&n.events_a)[0].0, j);
    // The server resets nothing else. (The client may answer late segments on the joined path,
    // and at the end reset a subflow holding only DATA_ACKed data, ruling R18.)
    let b = rsts(&n, Dir::BtoA);
    assert!(!b.is_empty() && b.iter().all(|s| s.dst.ip() == ip(A2)));
    let inf = |t: &(Dir, Seg)| {
        dss(&t.1)
            .and_then(|d| d.mapping)
            .is_some_and(|m| m.data_len == 0)
    };
    assert!(!n.taps.iter().any(inf), "no infinite mapping");
}

/// The counterpart of the client's `infinite_mapping_with_join_keeps_one_subflow`: with the
/// join up and everything so far DATA_ACKed, a middlebox turns the client's mappings on the
/// joined subflow into infinite mappings. The server falls back onto that subflow and resets
/// the initial one; the client follows on the server's own infinite mapping, and the rest of
/// the transfer is byte-exact on the joined subflow. No loss or reordering, as for
/// `server_dss_stripped_before_confirm_single_subflow_falls_back`.
#[test]
fn server_receives_infinite_mapping_with_join_keeps_one_subflow() {
    let (mut n, h) = net(false);
    join(&mut n, h);
    let first = pattern(100_000, 3);
    n.a.connection(h).unwrap().write(&first).unwrap();
    let (mut got, mut buf) = (Vec::new(), vec![0; 65536]);
    let mut read_all = |n: &mut Net<ChaCha20Rng>, got: &mut Vec<u8>| {
        let Some(&hb) = accepted_any(&n.events_b).first() else {
            return false;
        };
        let c = n.b.connection(hb).unwrap();
        while let Ok(k @ 1..) = c.read(&mut buf) {
            got.extend_from_slice(&buf[..k]);
        }
        got.len() == first.len() && ups(&n.events_a).len() == 1 && ups(&n.events_b).len() == 1
    };
    assert!(n.run_until(t(10), |n| read_all(n, &mut got)));
    assert_eq!(got, first);
    // Quiet: every DATA_ACK is in.
    let quiet = n.now + Duration::from_secs(2);
    n.run_until(quiet, |_| false);
    let hb = accepted_any(&n.events_b)[0];
    // The client sends new data on the joined subflow only.
    n.a.set_local_backup(h, SubflowId::INITIAL, true).unwrap();
    n.rewrite(Dir::AtoB, |s| {
        if s.src.ip() != ip(A2) {
            return true;
        }
        let mut opts = s.options.clone();
        let mut i = 0;
        while i + 1 < opts.len() {
            match opts[i] {
                0 => break,
                1 => i += 1,
                kind => {
                    let l = usize::from(opts[i + 1]).max(2);
                    if kind == 30 {
                        if let Ok(MptcpOption::Dss(mut d)) = mptcp::parse(&opts[i..i + l]) {
                            if let Some(m) = d.mapping.as_mut() {
                                m.data_len = 0;
                                let w = mptcp::encode(&MptcpOption::Dss(d), &mut opts[i..i + l]);
                                assert_eq!(w, Ok(l));
                            }
                        }
                    }
                    i += l;
                }
            }
        }
        s.options = opts;
        true
    });
    let mut apps = [
        App::new(false, Some(h), 200_000, 4),
        App::new(true, Some(hb), 200_000, 5),
    ];
    apps[1].hold = true;
    run_apps_with_rst(&mut n, &mut apps, SECS);
    assert!(has(&n.events_b, &Event::FellBack));
    assert!(has(&n.events_a, &Event::FellBack));
    assert!(!closed(&n.events_b).contains(&CloseReason::FallbackDataLoss));
    // The initial subflow is reset, by the server and maybe by the client on its own fallback;
    // the joined one never.
    let b = rsts(&n, Dir::BtoA);
    assert!(!b.is_empty() && b.iter().all(|s| s.dst.ip() == ip(A1)));
    assert!(rsts(&n, Dir::AtoB).iter().all(|s| s.src.ip() == ip(A1)));
    assert!(downs(&n.events_b).is_empty(), "FellBack, no SubflowDown");
    // The server's FIN goes on the survivor.
    let fin = |t: &&(Dir, Seg)| t.0 == Dir::BtoA && t.1.flags.contains(TcpFlags::FIN);
    assert!(n.taps.iter().filter(fin).all(|t| t.1.dst.ip() == ip(A2)));
}

/// The server asks the client to treat the join as backup (MP_PRIO), then retires it by FIN
/// exchange; the transfer completes on the initial subflow without a RST.
#[test]
fn set_backup_and_close_subflow_on_server() {
    let (mut n, h) = net(true);
    let j = join(&mut n, h);
    let mut apps = apps(h, 1 << 20, 1 << 20);
    let (hb, sb) = joined(&mut n, h, &mut apps);
    let prio = Event::PeerPriority {
        subflow: j,
        backup: true,
    };
    // MP_PRIO is not acknowledged: repeated until it arrives.
    let seen = |n: &mut Net<ChaCha20Rng>| {
        if has(&n.events_a, &prio) {
            return true;
        }
        let now = n.now;
        n.b.set_backup(now, hb, sb, true).unwrap();
        flush(n);
        false
    };
    assert!(n.run_until(t(20), seen));
    let now = n.now;
    n.b.close_subflow(now, hb, sb).unwrap();
    run_apps(&mut n, &mut apps, SECS);
    assert_eq!(downs(&n.events_b), [(sb, CloseReason::Normal, None)]);
    assert_eq!(downs(&n.events_a), [(j, CloseReason::Normal, None)]);
    let prios = |t: &&(Dir, Seg)| {
        (mptcp_opts(&t.1).iter()).any(|o| matches!(o, MptcpOption::Prio { backup: true }))
    };
    assert!(
        n.taps
            .iter()
            .filter(prios)
            .all(|t| t.0 == Dir::BtoA && t.1.dst.ip() == ip(A2))
    );
}

/// The client withdraws its second address: the server reports `AddressRemoved` for the join's
/// address id and `SubflowDown` for the join, and the transfer completes on the initial subflow.
#[test]
fn remove_address_from_client_seen_by_server() {
    let (mut n, h) = net(true);
    join(&mut n, h);
    let mut apps = apps(h, 1 << 20, 1 << 20);
    let (_, sb) = joined(&mut n, h, &mut apps);
    let syn = n
        .taps
        .iter()
        .find(|t| is_join(&t.1) && t.1.flags == TcpFlags::SYN);
    let id = mptcp_opts(&syn.unwrap().1)
        .into_iter()
        .find_map(|o| match o {
            MptcpOption::Join(MpJoin::Syn { addr_id, .. }) => Some(addr_id),
            _ => None,
        });
    let now = n.now;
    n.a.remove_address(now, h, ip(A2)).unwrap();
    run_apps_with_rst(&mut n, &mut apps, SECS);
    assert!(has(&n.events_b, &Event::AddressRemoved { id: id.unwrap() }));
    let down = downs(&n.events_b);
    assert_eq!(down.len(), 1);
    assert_eq!((down[0].0, down[0].1), (sb, CloseReason::Reset));
}

/// The client announces 10.0.3.1:8080 (mptcp-rs does not send ADD_ADDR, so a middlebox adds
/// it to the client's pure ACKs, with the HMAC keyed client ‖ server, RFC 8684 L1985–1993):
/// the server reports `AddressAnnounced` and echoes it.
#[test]
fn server_receives_add_addr() {
    let (mut n, h) = net(true);
    join(&mut n, h);
    let mut apps = apps(h, 1 << 20, 1 << 20);
    joined(&mut n, h, &mut apps);
    let (kc, ks) = keys(&n);
    let addr = ip("10.0.3.1");
    let opt = MptcpOption::AddAddr {
        echo: false,
        id: 5,
        addr,
        port: Some(8080),
        hmac: Some(add_addr_hmac(kc, ks, 5, addr, Some(8080))),
    };
    let mut raw = [0; 18];
    assert_eq!(mptcp::encode(&opt, &mut raw), Ok(18));
    // On the client's next three pure ACKs on the initial subflow (one may be lost).
    let left = Rc::new(Cell::new(3));
    n.rewrite(Dir::AtoB, move |s| {
        if left.get() > 0 && is_pure_ack(s) && s.src.ip() == ip(A1) && s.options.len() <= 22 {
            s.options.extend_from_slice(&raw);
            left.set(left.get() - 1);
        }
        true
    });
    run_apps_with_rst(&mut n, &mut apps, SECS);
    let announced = Event::AddressAnnounced {
        id: 5,
        addr: "10.0.3.1:8080".parse().unwrap(),
    };
    assert!(has(&n.events_b, &announced));
    let echo = |t: &&(Dir, Seg)| {
        t.0 == Dir::BtoA
            && (mptcp_opts(&t.1).iter()).any(|o| {
                matches!(
                    o,
                    MptcpOption::AddAddr {
                        echo: true,
                        id: 5,
                        ..
                    }
                )
            })
    };
    assert!(n.taps.iter().any(|t| echo(&t)));
}

/// Both congestion controls, 4 MiB each way over two lossy subflows, five seeds.
#[test]
fn transfer_bbr_and_cubic_lossy() {
    for cc in [CongestionControlKind::Cubic, CongestionControlKind::BbrV3] {
        for seed in 0..5 {
            let (mut n, h) = net_with(seed, true, cc);
            join(&mut n, h);
            run_apps(&mut n, &mut apps(h, 4 << 20, 4 << 20), SECS);
            assert_eq!((ups(&n.events_a).len(), ups(&n.events_b).len()), (1, 1));
        }
    }
}
