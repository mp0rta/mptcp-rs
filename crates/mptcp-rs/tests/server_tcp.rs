mod support;

use mptcp_rs::wire::packet::TcpFlags;
use mptcp_rs::{
    CloseReason, ConnectConfig, ConnectionHandle, Event, ListenConfig, ListenError, ReadError,
    SeqNum,
};
use rand_chacha::ChaCha20Rng;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};
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

fn idle_net() -> Net<ChaCha20Rng> {
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

// ---------------------------------------------------------------------------------------------
// Listeners and plain TCP accept (M4a Task 3).

fn listen_cfg(max_half_open: usize) -> ListenConfig {
    let mut cfg = ListenConfig::default();
    cfg.mptcp = false;
    cfg.max_half_open = max_half_open;
    cfg
}

fn v6(last: u16, port: u16) -> SocketAddr {
    SocketAddr::new(
        IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, last)),
        port,
    )
}

fn connect(net: &mut Net<ChaCha20Rng>, local: IpAddr, remote: SocketAddr) -> ConnectionHandle {
    let now = net.now;
    net.a
        .connect(now, local, remote, ConnectConfig::default())
        .unwrap()
}

fn accepted(events: &[(ConnectionHandle, Event)]) -> Vec<ConnectionHandle> {
    let acc =
        |(h, e): &(ConnectionHandle, Event)| (*e == Event::Accepted { mptcp: false }).then_some(*h);
    events.iter().filter_map(acc).collect()
}

fn is_synack(s: &Seg) -> bool {
    s.flags == TcpFlags::SYN | TcpFlags::ACK
}

/// The pure ACK that completes a handshake (and any later pure ACK).
fn is_pure_ack(s: &Seg) -> bool {
    s.flags == TcpFlags::ACK && s.payload.is_empty()
}

/// One application: writes `out`, then closes; reads until EOF. A client (`h` set) starts
/// once `Connected`, a server once it takes an unclaimed `Accepted` on its side.
struct App {
    on_b: bool,
    h: Option<ConnectionHandle>,
    out: Vec<u8>,
    written: usize,
    got: Vec<u8>,
    eof: bool,
    closing: bool,
}

impl App {
    fn new(on_b: bool, h: Option<ConnectionHandle>, len: usize, salt: usize) -> Self {
        let out = pattern(len, salt);
        let (written, got, eof, closing) = (0, Vec::new(), false, false);
        App {
            on_b,
            h,
            out,
            written,
            got,
            eof,
            closing,
        }
    }

    fn events<'a>(&self, n: &'a Net<ChaCha20Rng>) -> &'a [(ConnectionHandle, Event)] {
        if self.on_b { &n.events_b } else { &n.events_a }
    }

    fn up(&self, n: &Net<ChaCha20Rng>) -> bool {
        let up = |(h, e): &(ConnectionHandle, Event)| {
            Some(*h) == self.h && matches!(e, Event::Connected { .. } | Event::Accepted { .. })
        };
        self.events(n).iter().any(up)
    }

    fn closed(&self, n: &Net<ChaCha20Rng>) -> Vec<CloseReason> {
        let closed = |(h, e): &(ConnectionHandle, Event)| match e {
            Event::Closed { reason } if Some(*h) == self.h => Some(*reason),
            _ => None,
        };
        self.events(n).iter().filter_map(closed).collect()
    }

    fn drive(&mut self, n: &mut Net<ChaCha20Rng>, claimed: &[ConnectionHandle]) {
        if self.h.is_none() {
            let free = accepted(self.events(n))
                .into_iter()
                .find(|h| !claimed.contains(h));
            self.h = free;
        }
        let Some(h) = self.h.filter(|_| self.up(n)) else {
            return;
        };
        let ep = if self.on_b { &mut n.b } else { &mut n.a };
        let c = ep.connection(h).expect("live connection");
        while self.written < self.out.len() {
            let w = c.write(&self.out[self.written..]).unwrap();
            if w == 0 {
                break;
            }
            self.written += w;
        }
        if self.written == self.out.len() && !self.closing {
            c.close();
            self.closing = true;
        }
        let mut buf = vec![0u8; 65536];
        loop {
            match c.read(&mut buf) {
                Ok(0) => {
                    self.eof = true;
                    break;
                }
                Ok(k) => self.got.extend_from_slice(&buf[..k]),
                Err(ReadError::WouldBlock) => break,
                Err(e) => panic!("{e:?}"),
            }
        }
    }
}

/// Sends what the applications' calls made due (driver contract of `poll_transmit`).
fn flush(n: &mut Net<ChaCha20Rng>) {
    let mut buf = [0u8; MTU];
    while let Some(k) = n.a.poll_transmit(n.now, &mut buf) {
        n.send(Dir::AtoB, buf[..k].to_vec());
    }
    while let Some(k) = n.b.poll_transmit(n.now, &mut buf) {
        n.send(Dir::BtoA, buf[..k].to_vec());
    }
}

/// Runs `apps` until each has read EOF and seen `Closed`; each pair (client, server) must
/// have exchanged its bytes exactly, closed `Normal`, and no RST may have been sent.
fn run_apps(n: &mut Net<ChaCha20Rng>, apps: &mut [App], secs: u64) {
    let deadline = n.now + Duration::from_secs(secs);
    let ok = n.run_until(deadline, |n| {
        for i in 0..apps.len() {
            let side = apps[i].on_b;
            let mine = |a: &App| a.h.filter(|_| a.on_b == side);
            let claimed: Vec<_> = apps.iter().filter_map(mine).collect();
            apps[i].drive(n, &claimed);
        }
        flush(n);
        apps.iter().all(|a| a.eof && !a.closed(n).is_empty())
    });
    assert!(ok, "transfer did not finish by {deadline:?}");
    for pair in apps.chunks(2) {
        assert!(pair[0].got == pair[1].out, "server to client bytes differ");
        assert!(pair[1].got == pair[0].out, "client to server bytes differ");
    }
    for a in apps.iter() {
        assert_eq!(a.closed(n), [CloseReason::Normal]);
    }
    assert!(n.taps.iter().all(|t| !t.1.flags.contains(TcpFlags::RST)));
}

/// `b` listens on `listen`; `a` connects from `local` to `remote` and both send `len` bytes.
fn session(listen: SocketAddr, local: IpAddr, remote: SocketAddr, len: usize) -> Net<ChaCha20Rng> {
    let mut n = idle_net();
    n.b.listen(listen, listen_cfg(256)).unwrap();
    let h = connect(&mut n, local, remote);
    let mut apps = [
        App::new(false, Some(h), len, 0),
        App::new(true, None, len, 1),
    ];
    run_apps(&mut n, &mut apps, 120);
    assert_eq!(accepted(&n.events_b).len(), 1);
    n
}

#[test]
fn listen_rejects_bad_config() {
    let mut ep = endpoint(1);
    let ok = ListenConfig::default();
    ep.listen(sa(2, 80), ok.clone()).unwrap();
    assert_eq!(ep.listen(sa(2, 80), ok.clone()), Err(ListenError::InUse));
    assert_eq!(ep.listen(sa(2, 0), ok.clone()), Err(ListenError::PortZero));
    let mut cfg = ok.clone();
    cfg.connection.mtu = 1279;
    assert_eq!(
        ep.listen(v6(2, 81), cfg.clone()),
        Err(ListenError::InvalidMtu)
    );
    cfg.connection.mtu = 67;
    assert_eq!(ep.listen(sa(2, 81), cfg), Err(ListenError::InvalidMtu));
    let mut cfg = ok.clone();
    cfg.connection.send_buffer = 0;
    assert_eq!(ep.listen(sa(2, 81), cfg), Err(ListenError::InvalidBuffer));
    let mut cfg = ok;
    cfg.max_half_open = 0;
    assert_eq!(ep.listen(sa(2, 81), cfg), Err(ListenError::InvalidHalfOpen));
}

#[test]
fn plain_tcp_accept_and_transfer() {
    let n = session(sa(2, 80), sa(1, 0).ip(), sa(2, 80), 1 << 20);
    let h = accepted(&n.events_b)[0];
    assert_eq!(
        n.events_b.iter().filter(|e| e.0 == h).count(),
        2,
        "Accepted, Closed"
    );
}

#[test]
fn wildcard_listener_matches_any_local_ip() {
    let any4 = SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 80);
    session(any4, sa(1, 0).ip(), sa(2, 80), 10_000);
    let any6 = SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 80);
    session(any6, v6(1, 0).ip(), v6(2, 80), 10_000);
}

#[test]
fn ipv6_listener_ignores_scope_and_flowinfo() {
    let ip = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2);
    let scoped = SocketAddr::V6(SocketAddrV6::new(ip, 80, 7, 3));
    let mut n = session(scoped, v6(1, 0).ip(), v6(2, 80), 10_000);
    assert_eq!(
        n.b.listen(v6(2, 80), listen_cfg(1)),
        Err(ListenError::InUse)
    );
    let other = SocketAddr::V6(SocketAddrV6::new(ip, 80, 1, 9));
    assert!(n.b.unlisten(other));
    assert!(!n.b.unlisten(v6(2, 80)));
}

#[test]
fn no_listener_gets_rst() {
    let mut n = idle_net();
    n.b.listen(sa(2, 81), listen_cfg(256)).unwrap();
    let h = connect(&mut n, sa(1, 0).ip(), sa(2, 80));
    n.run_until(t(5), |n| !n.events_a.is_empty());
    assert_eq!(
        n.events_a,
        [(
            h,
            Event::Closed {
                reason: CloseReason::Reset
            }
        )]
    );
    let rst = TcpFlags::RST | TcpFlags::ACK;
    assert!(
        n.taps
            .iter()
            .any(|(d, s)| *d == Dir::BtoA && s.flags == rst)
    );
    assert!(n.events_b.is_empty());
}

#[test]
fn lost_synack_recovers() {
    let mut n = idle_net();
    n.b.listen(sa(2, 80), listen_cfg(256)).unwrap();
    n.drop_next(Dir::BtoA, is_synack);
    let h = connect(&mut n, sa(1, 0).ip(), sa(2, 80));
    let mut apps = [
        App::new(false, Some(h), 10_000, 0),
        App::new(true, None, 10_000, 1),
    ];
    run_apps(&mut n, &mut apps, 60);
    assert_eq!(n.taps.iter().filter(|t| is_synack(&t.1)).count(), 2);
    assert_eq!(accepted(&n.events_b).len(), 1);
}

#[test]
fn lost_final_ack_with_client_data_first() {
    let mut n = idle_net();
    n.b.listen(sa(2, 80), listen_cfg(256)).unwrap();
    n.drop_next(Dir::AtoB, is_pure_ack);
    let h = connect(&mut n, sa(1, 0).ip(), sa(2, 80));
    let mut apps = [
        App::new(false, Some(h), 10_000, 0),
        App::new(true, None, 10_000, 1),
    ];
    run_apps(&mut n, &mut apps, 60);
    // The client's first data segment completed the handshake, before any SYN/ACK retry.
    assert_eq!(n.taps.iter().filter(|t| is_synack(&t.1)).count(), 1);
    assert_eq!(accepted(&n.events_b).len(), 1);
}

#[test]
fn half_open_hidden_until_established() {
    let mut n = idle_net();
    n.b.listen(sa(2, 80), listen_cfg(256)).unwrap();
    connect(&mut n, sa(1, 0).ip(), sa(2, 80));
    // The SYN/ACK has reached `a`; its final ACK is still on the wire.
    let synack_in = |n: &mut Net<ChaCha20Rng>| n.delivered.iter().any(|d| is_synack(&d.2));
    assert!(n.run_until(t(5), synack_in));
    assert!(n.events_b.is_empty());
    assert!(n.run_until(t(5), |n| !n.events_b.is_empty()));
    assert_eq!(accepted(&n.events_b).len(), 1);
}

#[test]
fn half_open_cap_drops_then_recovers() {
    let mut n = idle_net();
    n.b.listen(sa(2, 80), listen_cfg(2)).unwrap();
    // Every handshake stays half-open: no final ACK ever reaches `b`.
    n.rewrite(Dir::AtoB, |s| !is_pure_ack(s));
    let hs: Vec<_> = (0..3)
        .map(|_| connect(&mut n, sa(1, 0).ip(), sa(2, 80)))
        .collect();
    let third = n.a.connection(hs[2]).unwrap().local();
    // Before `b`'s R2 (180 s after the first SYN/ACK) the third SYN gets nothing.
    n.run_until(t(170), |_| false);
    assert!(
        n.taps
            .iter()
            .all(|(d, s)| !(*d == Dir::BtoA && s.dst == third))
    );
    assert!(
        n.taps.iter().filter(|t| is_synack(&t.1)).count() > 2,
        "SYN/ACK retries"
    );
    n.run_until(t(200), |_| false);
    assert!(
        n.events_b.is_empty(),
        "half-opens end silently: {:?}",
        n.events_b
    );
    n.rewrite(Dir::AtoB, |_| true);
    let h = connect(&mut n, sa(1, 0).ip(), sa(2, 80));
    let mut apps = [
        App::new(false, Some(h), 1000, 0),
        App::new(true, None, 1000, 1),
    ];
    let deadline = n.now + Duration::from_secs(60);
    assert!(n.run_until(deadline, |n| {
        apps[0].drive(n, &[]);
        apps[1].drive(n, &[]);
        flush(n);
        apps[1].got.len() == 1000
    }));
    assert_eq!(accepted(&n.events_b).len(), 1);
}

#[test]
fn half_open_rst_frees_slot() {
    let mut n = idle_net();
    n.b.listen(sa(2, 80), listen_cfg(1)).unwrap();
    n.drop_next(Dir::AtoB, is_pure_ack);
    let h1 = connect(&mut n, sa(1, 0).ip(), sa(2, 80));
    let up = |n: &mut Net<ChaCha20Rng>| n.events_a.iter().any(|e| e.0 == h1);
    assert!(n.run_until(t(5), up));
    // The dropped final ACK carries RCV.NXT: a RST there is acceptable (RFC 9293 L3551).
    let ack = n.taps.iter().find(|t| is_pure_ack(&t.1)).unwrap().1.clone();
    n.send(
        Dir::AtoB,
        pkt(
            ack.src,
            ack.dst,
            ack.seq,
            SeqNum(0),
            TcpFlags::RST,
            &[],
            &[],
        ),
    );
    let h2 = connect(&mut n, sa(1, 0).ip(), sa(2, 80));
    let mut apps = [
        App::new(false, Some(h2), 1000, 0),
        App::new(true, None, 1000, 1),
    ];
    let deadline = n.now + Duration::from_secs(5);
    assert!(n.run_until(deadline, |n| {
        apps[0].drive(n, &[]);
        apps[1].drive(n, &[]);
        flush(n);
        apps[1].got.len() == 1000
    }));
    // The slot freed at once: no SYN/ACK retry was needed for the second client.
    assert_eq!(n.taps.iter().filter(|t| is_synack(&t.1)).count(), 2);
    assert_eq!(accepted(&n.events_b).len(), 1);
    assert_eq!(n.events_b.len(), 1);
}

#[test]
fn unlisten_keeps_established_drops_half_open() {
    let mut n = idle_net();
    n.b.listen(sa(2, 80), listen_cfg(256)).unwrap();
    let h1 = connect(&mut n, sa(1, 0).ip(), sa(2, 80));
    assert!(n.run_until(t(5), |n| !n.events_b.is_empty()));
    n.drop_next(Dir::AtoB, is_pure_ack);
    let h2 = connect(&mut n, sa(1, 0).ip(), sa(2, 80));
    let up = |n: &mut Net<ChaCha20Rng>| n.events_a.iter().any(|e| e.0 == h2);
    assert!(n.run_until(t(5), up));
    assert!(n.b.unlisten(sa(2, 80)));
    assert!(!n.b.unlisten(sa(2, 80)));
    // The half-open is gone: the client's data meets no TCB and no listener.
    n.a.connection(h2).unwrap().write(b"x").unwrap();
    let reset = Event::Closed {
        reason: CloseReason::Reset,
    };
    let gone = |n: &mut Net<ChaCha20Rng>| n.events_a.contains(&(h2, reset));
    assert!(n.run_until(t(10), gone));
    // The established connection carries on, without RSTs of its own.
    n.taps.clear();
    let mut apps = [
        App::new(false, Some(h1), 50_000, 0),
        App::new(true, None, 50_000, 1),
    ];
    run_apps(&mut n, &mut apps, 60);
    assert_eq!(accepted(&n.events_b).len(), 1);
}

#[test]
fn relisten_starts_with_free_slots() {
    let mut n = idle_net();
    n.b.listen(sa(2, 80), listen_cfg(1)).unwrap();
    n.drop_next(Dir::AtoB, is_pure_ack);
    let h1 = connect(&mut n, sa(1, 0).ip(), sa(2, 80));
    let up = |n: &mut Net<ChaCha20Rng>| n.events_a.iter().any(|e| e.0 == h1);
    assert!(n.run_until(t(5), up));
    assert!(n.b.unlisten(sa(2, 80)));
    n.b.listen(sa(2, 80), listen_cfg(1)).unwrap();
    let h2 = connect(&mut n, sa(1, 0).ip(), sa(2, 80));
    let mut apps = [
        App::new(false, Some(h2), 1000, 0),
        App::new(true, None, 1000, 1),
    ];
    let deadline = n.now + Duration::from_secs(5);
    assert!(n.run_until(deadline, |n| {
        apps[0].drive(n, &[]);
        apps[1].drive(n, &[]);
        flush(n);
        apps[1].got.len() == 1000
    }));
    assert_eq!(accepted(&n.events_b).len(), 1);
}

#[test]
fn both_roles_tcp() {
    let mut n = idle_net();
    n.a.listen(sa(1, 80), listen_cfg(256)).unwrap();
    n.b.listen(sa(2, 80), listen_cfg(256)).unwrap();
    let ha = connect(&mut n, sa(1, 0).ip(), sa(2, 80));
    let now = n.now;
    let hb = (n.b)
        .connect(now, sa(2, 0).ip(), sa(1, 80), ConnectConfig::default())
        .unwrap();
    let mut apps = [
        App::new(false, Some(ha), 200_000, 0),
        App::new(true, None, 200_000, 1),
        App::new(true, Some(hb), 200_000, 2),
        App::new(false, None, 200_000, 3),
    ];
    run_apps(&mut n, &mut apps, 120);
    assert_eq!(accepted(&n.events_a).len(), 1);
    assert_eq!(accepted(&n.events_b).len(), 1);
}

/// Only a bare SYN opens a connection; a SYN with MP_JOIN, or with ACK, gets a RST as today.
#[test]
fn listener_rsts_join_syn_and_synack() {
    let mut n = idle_net();
    n.b.listen(sa(2, 80), ListenConfig::default()).unwrap();
    let join = [30, 12, 0x10, 0, 1, 2, 3, 4, 5, 6, 7, 8];
    let (src, dst) = (sa(1, 5000), sa(2, 80));
    n.send(
        Dir::AtoB,
        pkt(src, dst, SeqNum(7), SeqNum(0), TcpFlags::SYN, &join, &[]),
    );
    let synack = TcpFlags::SYN | TcpFlags::ACK;
    n.send(
        Dir::AtoB,
        pkt(src, dst, SeqNum(7), SeqNum(99), synack, &[], &[]),
    );
    n.run_until(t(5), |_| false);
    let rsts: Vec<_> = n.taps.iter().filter(|(d, _)| *d == Dir::BtoA).collect();
    assert_eq!(rsts.len(), 2);
    assert_eq!(rsts[0].1.flags, TcpFlags::RST | TcpFlags::ACK);
    assert_eq!(
        (rsts[1].1.flags, rsts[1].1.seq),
        (TcpFlags::RST, SeqNum(99))
    );
    assert!(n.events_b.is_empty());
}

/// In LISTEN a segment without SYN, ACK or RST is dropped (RFC 9293 L3340–3346).
#[test]
fn listener_drops_fin_only_and_flagless() {
    let mut n = idle_net();
    n.b.listen(sa(2, 80), ListenConfig::default()).unwrap();
    let (src, dst) = (sa(1, 5000), sa(2, 80));
    n.send(
        Dir::AtoB,
        pkt(src, dst, SeqNum(7), SeqNum(0), TcpFlags::FIN, &[], &[]),
    );
    n.send(
        Dir::AtoB,
        pkt(src, dst, SeqNum(7), SeqNum(0), TcpFlags(0), &[], b"data"),
    );
    n.run_until(t(5), |_| false);
    assert_eq!(n.delivered.len(), 2);
    assert!(n.taps.iter().all(|(d, _)| *d == Dir::AtoB), "no response");
    assert!(n.events_b.is_empty());
}
