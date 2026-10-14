//! DSS checksums between two `Endpoint`s (M4b spec G11–G17): a middlebox that changes one
//! payload octet, on a joined subflow or on the only one. `a` connects from 10.0.1.1; its
//! second path is 10.0.2.1.
mod support;

use std::cell::Cell;
use std::net::IpAddr;
use std::rc::Rc;

use mptcp_rs::wire::mptcp::{self, MptcpOption};
use mptcp_rs::wire::packet::TcpFlags;
use mptcp_rs::wire::tcp_options::{TcpOpt, walk};
use mptcp_rs::{ConnectConfig, Event, ListenConfig, MpTcpRst};
use support::*;

/// A normal MPTCP close waits out TIME-WAIT (2·MSL = 120 s).
const SECS: u64 = 300;

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn mptcp_opts(s: &Seg) -> Vec<MptcpOption> {
    walk(&s.options)
        .filter_map(|o| match o {
            Ok(TcpOpt::Mptcp(raw)) => mptcp::parse(raw).ok(),
            _ => None,
        })
        .collect()
}

/// The DSN of the DSS mapping `s` carries.
fn mapping_dsn(s: &Seg) -> Option<u64> {
    mptcp_opts(s).into_iter().find_map(|o| match o {
        MptcpOption::Dss(d) => d.mapping.map(|m| match m.dsn {
            mptcp::Dsn::Dsn64(x) => x,
            mptcp::Dsn::Dsn32(x) => u64::from(x),
        }),
        _ => None,
    })
}

/// Both ends with checksums, two subflows, 1 MiB each way. In direction `dir`, one payload
/// octet of the first data segment of the joined subflow's second mapping is inverted: its
/// receiver resets that subflow with MP_FAIL + MP_TCPRST 0x06, the sender reports
/// `SubflowDown` with reason 6, and the transfer completes over the initial subflow without
/// fallback.
#[test]
fn two_subflows_corrupt_joined_subflow_each_direction() {
    for dir in [Dir::AtoB, Dir::BtoA] {
        let mut n = idle_net();
        let mut cfg = ConnectConfig::default();
        cfg.checksums = true;
        let mut listen = ListenConfig::default();
        listen.connection = cfg.clone();
        n.b.listen(sa(2, 80), listen).unwrap();
        let h =
            n.a.connect_mptcp(n.now, ip("10.0.1.1"), sa(2, 80), cfg)
                .unwrap();
        let now = n.now;
        (n.a.add_subflow(now, h, ip("10.0.2.1"), sa(2, 80), 1500, false)).unwrap();
        let joined = move |s: &Seg| {
            let end = if dir == Dir::AtoB { s.src } else { s.dst };
            end.ip() == ip("10.0.2.1")
        };
        let (first, done) = (Rc::new(Cell::new(None)), Rc::new(Cell::new(false)));
        let corrupted = done.clone();
        n.rewrite(dir, move |s| {
            if !joined(s) || s.payload.is_empty() || done.get() {
                return true;
            }
            let dsn = mapping_dsn(s);
            if first.get().is_none() {
                first.set(dsn);
            } else if dsn != first.get() {
                s.payload[0] ^= 0xff;
                done.set(true);
            }
            true
        });
        let mut apps = [
            App::new(false, Some(h), 1 << 20, 0),
            App::new(true, None, 1 << 20, 1),
        ];
        run_apps_with_rst(&mut n, &mut apps, SECS);
        assert!(corrupted.get(), "{dir:?}: a segment was corrupted");
        let back = if dir == Dir::AtoB {
            Dir::BtoA
        } else {
            Dir::AtoB
        };
        // Segments still in flight to the closed subflow are answered with bare RSTs.
        let resets: Vec<_> = (n.taps.iter())
            .filter(|t| t.0 == back && t.1.flags.contains(TcpFlags::RST))
            .map(|t| &t.1)
            .filter(|s| !s.options.is_empty())
            .collect();
        assert_eq!(resets.len(), 1, "{dir:?}");
        let rst = resets[0];
        let on_joined = [rst.src, rst.dst].iter().any(|a| a.ip() == ip("10.0.2.1"));
        assert!(on_joined, "{dir:?}: on the joined subflow");
        let opts = mptcp_opts(rst);
        assert!(
            matches!(opts[0], MptcpOption::Fail { .. }),
            "{dir:?}: {opts:?}"
        );
        let tcprst = MptcpOption::TcpRst {
            transient: false,
            reason: 6,
        };
        assert_eq!(opts[1..], [tcprst], "{dir:?}");
        assert_eq!(rst.options.len(), 16, "{dir:?}");
        let sender = if dir == Dir::AtoB {
            &n.events_a
        } else {
            &n.events_b
        };
        let down = |(_, e): &&(_, Event)| {
            matches!(
                e,
                Event::SubflowDown {
                    rst: Some(MpTcpRst { reason: 6, .. }),
                    ..
                }
            )
        };
        assert_eq!(sender.iter().filter(down).count(), 1, "{dir:?}");
        let fell_back = |(_, e): &(_, Event)| *e == Event::FellBack;
        assert!(!n.events_a.iter().any(fell_back), "{dir:?}");
        assert!(!n.events_b.iter().any(fell_back), "{dir:?}");
    }
}

/// A middlebox in `dir` that inverts the first payload octet of the first segment of the
/// second mapping it sees on the only subflow; returns whether it has.
fn corrupt_second_mapping(n: &mut Net<rand_chacha::ChaCha20Rng>, dir: Dir) -> Rc<Cell<bool>> {
    let (first, done) = (Rc::new(Cell::new(None)), Rc::new(Cell::new(false)));
    let corrupted = done.clone();
    n.rewrite(dir, move |s| {
        if s.payload.is_empty() || done.get() {
            return true;
        }
        let dsn = mapping_dsn(s);
        if first.get().is_none() {
            first.set(dsn);
        } else if dsn != first.get() {
            s.payload[0] ^= 0xff;
            done.set(true);
        }
        true
    });
    corrupted
}

/// Both ends with checksums, one subflow, `a` sending 256 KiB and `b` 128 KiB, the middlebox
/// in `dir`. Runs to the end and checks: one octet inverted at the receiver, the rest exact;
/// one `FellBack` on each side; MP_FAIL both ways (ours and the echo); no RST; both close
/// normally. `setup` adds drops. Returns the finished `Net`.
fn single_subflow_case(
    dir: Dir,
    setup: impl FnOnce(&mut Net<rand_chacha::ChaCha20Rng>),
) -> Net<rand_chacha::ChaCha20Rng> {
    let mut n = idle_net();
    let mut cfg = ConnectConfig::default();
    cfg.checksums = true;
    let mut listen = ListenConfig::default();
    listen.connection = cfg.clone();
    n.b.listen(sa(2, 80), listen).unwrap();
    let h =
        n.a.connect_mptcp(n.now, ip("10.0.1.1"), sa(2, 80), cfg)
            .unwrap();
    let corrupted = corrupt_second_mapping(&mut n, dir);
    setup(&mut n);
    let mut apps = [
        App::new(false, Some(h), 256 << 10, 0),
        App::new(true, None, 128 << 10, 1),
    ];
    let deadline = n.now + std::time::Duration::from_secs(SECS);
    let done = |n: &mut Net<_>, apps: &[App]| apps.iter().all(|a| a.eof && !a.closed(n).is_empty());
    assert!(run_apps_until(&mut n, &mut apps, deadline, done), "{dir:?}");
    assert!(corrupted.get(), "{dir:?}: a segment was corrupted");
    let (sender, receiver) = match dir {
        Dir::AtoB => (&apps[0], &apps[1]),
        Dir::BtoA => (&apps[1], &apps[0]),
    };
    assert_eq!(receiver.got.len(), sender.out.len(), "{dir:?}");
    let diff: Vec<_> = (0..sender.out.len())
        .filter(|&i| receiver.got[i] != sender.out[i])
        .collect();
    assert_eq!(diff.len(), 1, "{dir:?}");
    assert_eq!(receiver.got[diff[0]], sender.out[diff[0]] ^ 0xff);
    assert!(
        sender.got == receiver.out,
        "{dir:?}: the other direction is exact"
    );
    let fell_back = |(_, e): &&(_, Event)| *e == Event::FellBack;
    assert_eq!(n.events_a.iter().filter(fell_back).count(), 1, "{dir:?}");
    assert_eq!(n.events_b.iter().filter(fell_back).count(), 1, "{dir:?}");
    assert!(
        !n.taps.iter().any(|t| t.1.flags.contains(TcpFlags::RST)),
        "{dir:?}"
    );
    for a in &apps {
        assert_eq!(a.closed(&n), [mptcp_rs::CloseReason::Normal], "{dir:?}");
    }
    for d in [Dir::AtoB, Dir::BtoA] {
        let fail = |t: &&(Dir, Seg)| t.0 == d && fail_dsn(&t.1).is_some();
        assert!(n.taps.iter().any(|t| fail(&t)), "{dir:?}: MP_FAIL {d:?}");
    }
    n
}

/// The DSN of the MP_FAIL `s` carries.
fn fail_dsn(s: &Seg) -> Option<u64> {
    mptcp_opts(s).into_iter().find_map(|o| match o {
        MptcpOption::Fail { dsn } => Some(dsn),
        _ => None,
    })
}

/// A payload octet inverted after the first verified mapping, in each direction: the receiver
/// waits with MP_FAIL, the sender echoes, both fall back to TCP; the receiver gets the full
/// length with exactly that octet inverted, and no RST is sent (spec G11, G13, G15).
#[test]
fn single_subflow_corrupt_each_direction() {
    for dir in [Dir::AtoB, Dir::BtoA] {
        let _ = single_subflow_case(dir, |_| {});
    }
}

/// The echo is lost: the originator keeps retrying, the echoer's schedule repairs it, and the
/// transfer still ends with one fallback each and no RST (spec G13, G18).
#[test]
fn single_subflow_lost_echo_repaired() {
    // `b` receives the corrupt octet and sends MP_FAIL; `a` echoes.
    let n = single_subflow_case(Dir::AtoB, |n| {
        n.drop_next(Dir::AtoB, |s| fail_dsn(s).is_some());
    });
    let sent = (n.taps.iter()).filter(|t| t.0 == Dir::AtoB && fail_dsn(&t.1).is_some());
    let got = (n.delivered.iter()).filter(|t| t.0 == Dir::AtoB && fail_dsn(&t.2).is_some());
    let (sent, got) = (sent.count(), got.count());
    assert!(
        got >= 1 && sent == got + 1,
        "one echo dropped, a later one delivered"
    );
}
