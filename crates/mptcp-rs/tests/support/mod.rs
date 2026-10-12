//! Test-only helpers: owned segment views, handshake helpers and `ScriptedPeer`, a small
//! passive TCP peer built on `wire::packet::{build, parse}`.
#![allow(dead_code)]

use std::collections::{BTreeMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use mptcp_rs::wire::packet::{Segment, TcpFlags, build, parse};
use mptcp_rs::{ConnectConfig, ConnectionHandle, Endpoint, Event, Instant, SeqNum};
use rand_chacha::ChaCha20Rng;
use rand_core::{CryptoRng, Rng, SeedableRng};

pub const MTU: usize = 1500;
pub const PEER_MSS: u16 = 1200;

pub fn t(secs: u64) -> Instant {
    Instant::from_nanos(secs * 1_000_000_000)
}

pub fn ms(now: Instant, n: u64) -> Instant {
    now + Duration::from_millis(n)
}

pub fn local_ip(v6: bool) -> IpAddr {
    if v6 {
        IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1))
    } else {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))
    }
}

pub fn peer_addr(v6: bool) -> SocketAddr {
    let ip = if v6 {
        IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2))
    } else {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))
    };
    SocketAddr::new(ip, 80)
}

pub fn endpoint(seed: u64) -> Endpoint<ChaCha20Rng> {
    Endpoint::new(ChaCha20Rng::seed_from_u64(seed))
}

/// A parsed packet with owned options and payload.
#[derive(Debug, Clone)]
pub struct Seg {
    pub src: SocketAddr,
    pub dst: SocketAddr,
    pub seq: SeqNum,
    pub ack: SeqNum,
    pub flags: TcpFlags,
    pub wnd: u16,
    pub options: Vec<u8>,
    pub payload: Vec<u8>,
}

pub fn parse_owned(pkt: &[u8]) -> Seg {
    let s = parse(pkt).expect("our output parses");
    Seg {
        src: s.src,
        dst: s.dst,
        seq: s.seq,
        ack: s.ack,
        flags: s.flags,
        wnd: s.wnd,
        options: s.options.to_vec(),
        payload: s.payload.to_vec(),
    }
}

pub fn pkt(
    src: SocketAddr,
    dst: SocketAddr,
    seq: SeqNum,
    ack: SeqNum,
    flags: TcpFlags,
    options: &[u8],
    payload: &[u8],
) -> Vec<u8> {
    let seg = Segment {
        src,
        dst,
        seq,
        ack,
        flags,
        wnd: 65535,
        options,
        payload,
    };
    let mut buf = vec![0u8; MTU];
    let n = build(&seg, 0, &mut buf).unwrap();
    buf.truncate(n);
    buf
}

/// Every packet the endpoint wants to send right now.
pub fn drain(ep: &mut Endpoint<ChaCha20Rng>, now: Instant) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut buf = [0u8; MTU];
    while let Some(n) = ep.poll_transmit(now, &mut buf) {
        out.push(buf[..n].to_vec());
    }
    out
}

pub fn expect_syn(pkts: &[Vec<u8>]) -> Seg {
    assert_eq!(pkts.len(), 1, "exactly one packet expected");
    let s = parse_owned(&pkts[0]);
    assert_eq!(s.flags, TcpFlags::SYN);
    s
}

pub fn mss_option() -> [u8; 4] {
    let m = PEER_MSS.to_be_bytes();
    [2, 4, m[0], m[1]]
}

pub fn send_synack(ep: &mut Endpoint<ChaCha20Rng>, now: Instant, syn: &Seg, iss: u32) {
    let p = pkt(
        syn.dst,
        syn.src,
        SeqNum(iss),
        syn.seq.wrapping_add(1),
        TcpFlags::SYN | TcpFlags::ACK,
        &mss_option(),
        &[],
    );
    ep.handle_packet(now, &p);
}

/// Peer-to-endpoint data/ACK/FIN with explicit numbers (`ack` is the endpoint's `seq + 1 + ..`).
pub fn send_seg(
    ep: &mut Endpoint<ChaCha20Rng>,
    now: Instant,
    syn: &Seg,
    seq: u32,
    ack: u32,
    flags: TcpFlags,
    payload: &[u8],
) {
    let p = pkt(
        syn.dst,
        syn.src,
        SeqNum(seq),
        SeqNum(ack),
        flags,
        &[],
        payload,
    );
    ep.handle_packet(now, &p);
}

pub fn send_data(
    ep: &mut Endpoint<ChaCha20Rng>,
    now: Instant,
    syn: &Seg,
    seq: u32,
    ack: u32,
    d: &[u8],
) {
    send_seg(ep, now, syn, seq, ack, TcpFlags::ACK, d);
}

/// Asserts that the packets are exactly one pure ACK acknowledging `ack`.
pub fn expect_ack(pkts: &[Vec<u8>], ack: u32) -> Seg {
    assert_eq!(
        pkts.len(),
        1,
        "exactly one ACK expected, got {}",
        pkts.len()
    );
    let s = parse_owned(&pkts[0]);
    assert_eq!(s.flags, TcpFlags::ACK);
    assert_eq!(s.ack, SeqNum(ack));
    assert!(s.payload.is_empty());
    s
}

/// Connects and completes the handshake; returns (handle, syn, peer_iss).
pub fn established(
    ep: &mut Endpoint<ChaCha20Rng>,
    now: Instant,
    v6: bool,
) -> (mptcp_rs::ConnectionHandle, Seg, u32) {
    let h = ep
        .connect(now, local_ip(v6), peer_addr(v6), ConnectConfig::default())
        .unwrap();
    let syn = expect_syn(&drain(ep, now));
    let iss = 5000;
    send_synack(ep, now, &syn, iss);
    assert_eq!(
        ep.poll_event(),
        Some((h, mptcp_rs::Event::Connected { mptcp: false }))
    );
    // The handshake ACK.
    expect_ack(&drain(ep, now), iss + 1);
    (h, syn, iss)
}

/// Drives timers up to `deadline`, collecting output (timers only, no peer).
pub fn drive_until(
    ep: &mut Endpoint<ChaCha20Rng>,
    mut now: Instant,
    deadline: Instant,
) -> Vec<(Instant, Vec<u8>)> {
    let mut out = Vec::new();
    loop {
        for p in drain(ep, now) {
            out.push((now, p));
        }
        match ep.poll_timeout() {
            Some(next) if next <= deadline => {
                now = next.max(now);
                ep.handle_timeout(now);
            }
            _ => return out,
        }
    }
}

pub fn pattern(len: usize, salt: usize) -> Vec<u8> {
    (0..len)
        .map(|i| (((i + salt) * 31 + 7) % 251) as u8)
        .collect()
}

// ---------------------------------------------------------------------------------------------

#[derive(PartialEq, Eq, Clone, Copy, Debug)]
enum PState {
    Listen,
    SynRcvd,
    Open,
}

/// A passive TCP peer: handshake, in-order reassembly with an ACK per segment, its own data
/// with go-back-N (timer or 3 duplicate ACKs), FIN handling. No window scaling, no SACK.
pub struct ScriptedPeer {
    pub addr: SocketAddr,
    client: SocketAddr,
    state: PState,
    iss: u32,
    /// Sequence number of the byte at offset 0 of `data`.
    data: Vec<u8>,
    una: u32,
    nxt: u32,
    peer_wnd: u32,
    rto_at: Option<Instant>,
    dupacks: u32,
    send_fin: bool,
    fin_sent: bool,
    pub fin_acked: bool,
    rcv_base: u32,
    rcv_nxt: u32,
    pub received: Vec<u8>,
    ooo: BTreeMap<u32, Vec<u8>>,
    pub fin_received: bool,
    ack_pending: bool,
    out: VecDeque<Vec<u8>>,
    pub rst_seen: bool,
}

const PEER_RTO: Duration = Duration::from_millis(200);
const PEER_WINDOW_SEGS: u32 = 20;

impl ScriptedPeer {
    /// `data` is sent after the handshake; the FIN follows it once `send_fin` is set (also
    /// possible later via `close`).
    pub fn new(addr: SocketAddr, data: Vec<u8>) -> Self {
        Self {
            addr,
            client: addr,
            state: PState::Listen,
            iss: 7000,
            data,
            una: 0,
            nxt: 0,
            peer_wnd: 65535,
            rto_at: None,
            dupacks: 0,
            send_fin: false,
            fin_sent: false,
            fin_acked: false,
            rcv_base: 0,
            rcv_nxt: 0,
            received: Vec::new(),
            ooo: BTreeMap::new(),
            fin_received: false,
            ack_pending: false,
            out: VecDeque::new(),
            rst_seen: false,
        }
    }

    pub fn close(&mut self) {
        self.send_fin = true;
    }

    fn data_len(&self) -> u32 {
        self.data.len() as u32
    }

    fn seq_of(&self, off: u32) -> SeqNum {
        SeqNum(self.iss.wrapping_add(1).wrapping_add(off))
    }

    fn emit(&mut self, seq: SeqNum, flags: TcpFlags, options: &[u8], payload: &[u8]) {
        let p = pkt(
            self.addr,
            self.client,
            seq,
            SeqNum(self.rcv_nxt),
            flags,
            options,
            payload,
        );
        self.out.push_back(p);
    }

    pub fn rx(&mut self, now: Instant, raw: &[u8]) {
        let s = parse_owned(raw);
        if s.flags.contains(TcpFlags::RST) {
            self.rst_seen = true;
            return;
        }
        if s.flags.contains(TcpFlags::SYN) {
            // A (re)transmitted SYN.
            self.client = s.src;
            self.rcv_base = s.seq.0.wrapping_add(1);
            self.rcv_nxt = self.rcv_base;
            self.state = PState::SynRcvd;
            self.emit(
                SeqNum(self.iss),
                TcpFlags::SYN | TcpFlags::ACK,
                &mss_option(),
                &[],
            );
            return;
        }
        if self.state == PState::Listen {
            return;
        }
        if s.flags.contains(TcpFlags::ACK) {
            self.state = PState::Open;
            self.on_ack(now, &s);
        }
        let len = s.payload.len() as u32;
        let fin = s.flags.contains(TcpFlags::FIN);
        if len > 0 || fin {
            self.ack_pending = true;
            self.on_data(&s, fin);
        }
    }

    fn on_ack(&mut self, now: Instant, s: &Seg) {
        self.peer_wnd = s.wnd as u32;
        let base = self.iss.wrapping_add(1);
        let acked = s.ack.0.wrapping_sub(base);
        let end = self.data_len() + self.fin_sent as u32;
        if acked == 0 && self.una == 0 && self.nxt == 0 {
            return;
        }
        if acked > self.una && acked <= end.max(self.nxt) {
            self.una = acked;
            self.nxt = self.nxt.max(self.una);
            self.dupacks = 0;
            self.fin_acked = self.fin_sent && acked == self.data_len() + 1;
            self.rto_at = (self.una < self.nxt).then(|| now + PEER_RTO);
        } else if acked == self.una && s.payload.is_empty() && self.nxt > self.una {
            self.dupacks += 1;
            if self.dupacks == 3 {
                self.go_back();
            }
        }
    }

    fn go_back(&mut self) {
        self.nxt = self.una;
        if self.fin_sent && !self.fin_acked {
            self.fin_sent = false;
        }
    }

    fn on_data(&mut self, s: &Seg, fin: bool) {
        let off = s.seq.0.wrapping_sub(self.rcv_nxt) as i32;
        let have = self.rcv_nxt.wrapping_sub(self.rcv_base);
        if off <= 0 {
            let skip = (-off) as usize;
            if skip < s.payload.len() {
                self.received.extend_from_slice(&s.payload[skip..]);
                self.rcv_nxt = self.rcv_nxt.wrapping_add((s.payload.len() - skip) as u32);
            }
        } else if !s.payload.is_empty() {
            self.ooo
                .insert(have.wrapping_add(off as u32), s.payload.clone());
        }
        // Pull in held pieces that now touch or overlap.
        loop {
            let have = self.rcv_nxt.wrapping_sub(self.rcv_base);
            let Some((&k, _)) = self.ooo.range(..=have).next() else {
                break;
            };
            let piece = self.ooo.remove(&k).unwrap();
            let skip = (have - k) as usize;
            if skip < piece.len() {
                self.received.extend_from_slice(&piece[skip..]);
                self.rcv_nxt = self.rcv_nxt.wrapping_add((piece.len() - skip) as u32);
            }
        }
        if fin && s.seq.0.wrapping_add(s.payload.len() as u32) == self.rcv_nxt && !self.fin_received
        {
            self.fin_received = true;
            self.rcv_nxt = self.rcv_nxt.wrapping_add(1);
        }
    }

    fn fire_timer(&mut self, now: Instant) {
        if self.rto_at.is_some_and(|t| t <= now) {
            self.rto_at = Some(now + PEER_RTO);
            self.go_back();
        }
    }

    pub fn next_timer(&self) -> Option<Instant> {
        self.rto_at
    }

    /// One packet to the client, if any.
    pub fn poll_tx(&mut self, now: Instant) -> Option<Vec<u8>> {
        self.fire_timer(now);
        if let Some(p) = self.out.pop_front() {
            return Some(p);
        }
        if self.state != PState::Open {
            return None;
        }
        let limit = self.peer_wnd.min(PEER_WINDOW_SEGS * PEER_MSS as u32);
        if self.nxt < self.data_len() && self.nxt - self.una < limit {
            let n = (self.data_len() - self.nxt)
                .min(PEER_MSS as u32)
                .min(limit - (self.nxt - self.una)) as usize;
            let start = self.nxt as usize;
            let payload = self.data[start..start + n].to_vec();
            let seq = self.seq_of(self.nxt);
            self.emit(seq, TcpFlags::ACK | TcpFlags::PSH, &[], &payload);
            self.nxt += n as u32;
            self.ack_pending = false;
            self.rto_at.get_or_insert(now + PEER_RTO);
            return self.out.pop_front();
        }
        if self.send_fin && !self.fin_sent && self.nxt == self.data_len() {
            let seq = self.seq_of(self.nxt);
            self.emit(seq, TcpFlags::ACK | TcpFlags::FIN, &[], &[]);
            self.fin_sent = true;
            self.nxt += 1;
            self.ack_pending = false;
            self.rto_at.get_or_insert(now + PEER_RTO);
            return self.out.pop_front();
        }
        if self.ack_pending {
            self.ack_pending = false;
            let seq = self.seq_of(self.nxt.min(self.data_len() + self.fin_sent as u32));
            self.emit(seq, TcpFlags::ACK, &[], &[]);
            return self.out.pop_front();
        }
        None
    }
}

/// A one-way link with a fixed delay, random loss and random extra delay (= reordering).
pub struct Link {
    rng: ChaCha20Rng,
    loss_permille: u32,
    reorder_permille: u32,
    q: BTreeMap<(Instant, u64), Vec<u8>>,
    n: u64,
}

impl Link {
    pub fn new(seed: u64, loss_permille: u32, reorder_permille: u32) -> Self {
        Self {
            rng: ChaCha20Rng::seed_from_u64(seed),
            loss_permille,
            reorder_permille,
            q: BTreeMap::new(),
            n: 0,
        }
    }

    pub fn send(&mut self, now: Instant, p: Vec<u8>) {
        self.send_after(now, p, Duration::from_millis(10));
    }

    /// Like `send` with a caller-chosen base delay; loss and reorder still apply.
    pub fn send_after(&mut self, now: Instant, p: Vec<u8>, delay: Duration) {
        if self.rng.next_u32() % 1000 < self.loss_permille {
            return;
        }
        let mut delay = delay;
        if self.rng.next_u32() % 1000 < self.reorder_permille {
            delay += Duration::from_millis(5 + u64::from(self.rng.next_u32() % 20));
        }
        self.n += 1;
        self.q.insert((now + delay, self.n), p);
    }

    pub fn recv(&mut self, now: Instant) -> Option<Vec<u8>> {
        let (&k, _) = self.q.first_key_value()?;
        (k.0 <= now).then(|| self.q.remove(&k).unwrap())
    }

    pub fn next_due(&self) -> Option<Instant> {
        self.q.first_key_value().map(|(k, _)| k.0)
    }
}

/// Direction through a `Net`: `AtoB` is sent by `a`, delivered to `b`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dir {
    AtoB,
    BtoA,
}

type DropFn = Box<dyn Fn(&Seg) -> bool>;
type DelayFn = Box<dyn FnMut(&Seg) -> Option<Duration>>;
type RewriteFn = Box<dyn FnMut(&mut Seg) -> bool>;

/// Two endpoints joined by one `Link` per direction, on a single virtual clock.
pub struct Net<R: CryptoRng> {
    pub a: Endpoint<R>,
    pub b: Endpoint<R>,
    pub now: Instant,
    pub events_a: Vec<(ConnectionHandle, Event)>,
    pub events_b: Vec<(ConnectionHandle, Event)>,
    /// Every packet sent, before rewrite, drop and loss.
    pub taps: Vec<(Dir, Seg)>,
    /// Every packet handed to an endpoint, with its delivery time.
    pub delivered: Vec<(Dir, Instant, Seg)>,
    ab: Link,
    ba: Link,
    drops: Vec<(Dir, DropFn)>,
    delays: [Option<DelayFn>; 2],
    rewrites: [Option<RewriteFn>; 2],
}

impl<R: CryptoRng> Net<R> {
    pub fn new(a: Endpoint<R>, b: Endpoint<R>, link_ab: Link, link_ba: Link) -> Self {
        Self {
            a,
            b,
            now: Instant::from_nanos(0),
            events_a: Vec::new(),
            events_b: Vec::new(),
            taps: Vec::new(),
            delivered: Vec::new(),
            ab: link_ab,
            ba: link_ba,
            drops: Vec::new(),
            delays: [None, None],
            rewrites: [None, None],
        }
    }

    /// Drops the first packet in `dir` matching `pred`, once.
    pub fn drop_next(&mut self, dir: Dir, pred: impl Fn(&Seg) -> bool + 'static) {
        self.drops.push((dir, Box::new(pred)));
    }

    /// Per-packet delay override (`None` keeps the link default).
    pub fn delay(&mut self, dir: Dir, f: impl FnMut(&Seg) -> Option<Duration> + 'static) {
        self.delays[dir as usize] = Some(Box::new(f));
    }

    /// Rewrites packets in `dir`; the packet is re-serialised with fresh checksums.
    /// Returning `false` drops it.
    pub fn rewrite(&mut self, dir: Dir, f: impl FnMut(&mut Seg) -> bool + 'static) {
        self.rewrites[dir as usize] = Some(Box::new(f));
    }

    /// Puts a raw packet on the wire in `dir` at the current time.
    pub fn send(&mut self, dir: Dir, raw: Vec<u8>) {
        let mut seg = parse_owned(&raw);
        self.taps.push((dir, seg.clone()));
        if let Some(i) = self.drops.iter().position(|(d, p)| *d == dir && p(&seg)) {
            let _ = self.drops.remove(i);
            return;
        }
        let mut raw = raw;
        if let Some(f) = &mut self.rewrites[dir as usize] {
            if !f(&mut seg) {
                return;
            }
            let wire = Segment {
                src: seg.src,
                dst: seg.dst,
                seq: seg.seq,
                ack: seg.ack,
                flags: seg.flags,
                wnd: seg.wnd,
                options: &seg.options,
                payload: &seg.payload,
            };
            let mut buf = vec![0u8; MTU];
            let n = build(&wire, 0, &mut buf).unwrap();
            buf.truncate(n);
            raw = buf;
        }
        let over = self.delays[dir as usize].as_mut().and_then(|f| f(&seg));
        let link = match dir {
            Dir::AtoB => &mut self.ab,
            Dir::BtoA => &mut self.ba,
        };
        match over {
            Some(d) => link.send_after(self.now, raw, d),
            None => link.send(self.now, raw),
        }
    }

    /// Moves everything the endpoints want to send onto the links and collects events.
    fn pump(&mut self) {
        let mut buf = [0u8; MTU];
        while let Some(n) = self.a.poll_transmit(self.now, &mut buf) {
            self.send(Dir::AtoB, buf[..n].to_vec());
        }
        while let Some(n) = self.b.poll_transmit(self.now, &mut buf) {
            self.send(Dir::BtoA, buf[..n].to_vec());
        }
        while let Some(e) = self.a.poll_event() {
            self.events_a.push(e);
        }
        while let Some(e) = self.b.poll_event() {
            self.events_b.push(e);
        }
    }

    fn next_event(&self) -> Option<Instant> {
        [
            self.ab.next_due(),
            self.ba.next_due(),
            self.a.poll_timeout(),
            self.b.poll_timeout(),
        ]
        .into_iter()
        .flatten()
        .min()
    }

    /// Advances to the earliest link delivery or timeout and handles it.
    /// Returns `false` when nothing is pending.
    pub fn step(&mut self) -> bool {
        self.pump();
        let Some(next) = self.next_event() else {
            return false;
        };
        self.now = self.now.max(next);
        let now = self.now;
        while let Some(p) = self.ab.recv(now) {
            self.delivered.push((Dir::AtoB, now, parse_owned(&p)));
            self.b.handle_packet(now, &p);
        }
        while let Some(p) = self.ba.recv(now) {
            self.delivered.push((Dir::BtoA, now, parse_owned(&p)));
            self.a.handle_packet(now, &p);
        }
        if self.a.poll_timeout().is_some_and(|t| t <= now) {
            self.a.handle_timeout(now);
        }
        if self.b.poll_timeout().is_some_and(|t| t <= now) {
            self.b.handle_timeout(now);
        }
        self.pump();
        true
    }

    /// Steps until `done` holds (returns `true`), the next event is past `deadline`, or
    /// nothing is pending (both return `false`).
    pub fn run_until(
        &mut self,
        deadline: Instant,
        mut done: impl FnMut(&mut Self) -> bool,
    ) -> bool {
        loop {
            if done(self) {
                return true;
            }
            self.pump();
            if self.next_event().is_none_or(|t| t > deadline) {
                return false;
            }
            self.step();
        }
    }
}
