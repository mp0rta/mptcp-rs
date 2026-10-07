//! The sans-I/O entry point: owns every connection, demultiplexes packets and builds output
//! (spec §1, §3.1).

use std::collections::{BTreeMap, VecDeque};
use std::net::{IpAddr, SocketAddr};

use rand_core::CryptoRng;

use crate::Instant;
use crate::SeqNum;
use crate::connection::{Connection, ConnectionHooks};
use crate::crypto::IsnGenerator;
use crate::tcp::{CloseReason, ConnectConfig, Reaction, SegmentWriter, Tcb, TcpState};
use crate::wire::packet::{self, Segment, TcpFlags};

/// Queued RSTs for segments without a TCB; beyond this they are dropped.
const MAX_PENDING_RST: usize = 64;
const EPHEMERAL_FIRST: u16 = 49152;
const EPHEMERAL_COUNT: u32 = 65536 - EPHEMERAL_FIRST as u32;

/// Opaque, never reused within one `Endpoint`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ConnectionHandle(u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    Connected { mptcp: bool },
    FellBack,
    Closed { reason: CloseReason },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectError {
    /// All ephemeral ports to this remote are in use.
    NoPort,
    /// IPv4 needs an MTU of at least 68, IPv6 at least 1280.
    InvalidMtu,
    /// `send_buffer` and `recv_buffer` must be within 1 and 2^30.
    InvalidBuffer,
    /// `local` and `remote` are of different IP families.
    FamilyMismatch,
}

struct PendingRst {
    src: SocketAddr,
    dst: SocketAddr,
    seq: SeqNum,
    ack: SeqNum,
    flags: TcpFlags,
}

pub struct Endpoint<R: CryptoRng> {
    rng: R,
    isn: IsnGenerator,
    conns: BTreeMap<ConnectionHandle, Connection>,
    /// (local, remote) → handle (a BTreeMap: no OS-seeded hasher in the core). Closed and TIME-WAIT TCBs stay until `handle_timeout`.
    demux: BTreeMap<(SocketAddr, SocketAddr), ConnectionHandle>,
    next_handle: u64,
    /// Round-robin cursor for `poll_transmit`.
    cursor: u64,
    ip_id: u16,
    events: VecDeque<(ConnectionHandle, Event)>,
    pending_rst: VecDeque<PendingRst>,
    scratch: SegmentWriter,
}

impl<R: CryptoRng> Endpoint<R> {
    pub fn new(mut rng: R) -> Self {
        let mut secret = [0u8; 16];
        rng.fill_bytes(&mut secret);
        Self {
            rng,
            isn: IsnGenerator::new(secret),
            conns: BTreeMap::new(),
            demux: BTreeMap::new(),
            next_handle: 0,
            cursor: 0,
            ip_id: 0,
            events: VecDeque::new(),
            pending_rst: VecDeque::new(),
            scratch: SegmentWriter::default(),
        }
    }

    pub fn connect(
        &mut self,
        now: Instant,
        local: IpAddr,
        remote: SocketAddr,
        cfg: ConnectConfig,
    ) -> Result<ConnectionHandle, ConnectError> {
        // The wire carries only IP and port: drop IPv6 flow info and scope so demux keys match
        // what `packet::parse` builds.
        let remote = SocketAddr::new(remote.ip(), remote.port());
        let min_mtu = match (local, remote.ip()) {
            (IpAddr::V4(_), IpAddr::V4(_)) => 68,
            (IpAddr::V6(_), IpAddr::V6(_)) => 1280,
            _ => return Err(ConnectError::FamilyMismatch),
        };
        if cfg.mtu < min_mtu {
            return Err(ConnectError::InvalidMtu);
        }
        if [cfg.send_buffer, cfg.recv_buffer]
            .iter()
            .any(|b| !(1..=1 << 30).contains(b))
        {
            return Err(ConnectError::InvalidBuffer);
        }
        let start = self.rng.next_u32() % EPHEMERAL_COUNT;
        let local = (0..EPHEMERAL_COUNT)
            .map(|i| EPHEMERAL_FIRST + ((start + i) % EPHEMERAL_COUNT) as u16)
            .map(|port| SocketAddr::new(local, port))
            .find(|l| !self.demux.contains_key(&(*l, remote)))
            .ok_or(ConnectError::NoPort)?;
        let isn = self.isn.isn(now, local, remote);
        let h = ConnectionHandle(self.next_handle);
        self.next_handle += 1;
        self.demux.insert((local, remote), h);
        self.conns.insert(
            h,
            Connection {
                tcb: Tcb::new_active(&cfg, local, remote, isn, now),
                hooks: ConnectionHooks::new(&cfg),
                local,
                remote,
                closed_by_app: false,
                reset: false,
                detached: false,
            },
        );
        Ok(h)
    }

    /// Opens an MPTCP v1 connection, falling back to TCP if the peer does not support it.
    pub fn connect_mptcp(
        &mut self,
        now: Instant,
        local: IpAddr,
        remote: SocketAddr,
        cfg: ConnectConfig,
    ) -> Result<ConnectionHandle, ConnectError> {
        let h = self.connect(now, local, remote, cfg)?;
        // ponytail: scan live connections; use a token set if connect volume warrants it.
        // Keeping the token on its connection also retains it through TIME_WAIT.
        let negotiation = loop {
            let candidate = crate::mptcp::Negotiation::new(self.rng.next_u64());
            if !self.conns.values().any(|c| {
                c.hooks
                    .negotiation
                    .as_ref()
                    .is_some_and(|m| m.token == candidate.token)
            }) {
                break candidate;
            }
        };
        self.conns.get_mut(&h).unwrap().hooks.negotiation = Some(negotiation);
        Ok(h)
    }

    /// `None` once the connection is freed. A closed (not reset) connection with unread data
    /// stays reachable, without its port, until the data is read and `handle_timeout` runs.
    pub fn connection(&mut self, h: ConnectionHandle) -> Option<&mut Connection> {
        self.conns.get_mut(&h)
    }

    pub fn poll_event(&mut self) -> Option<(ConnectionHandle, Event)> {
        self.events.pop_front()
    }

    /// Feeds one received IP packet. Unparseable packets are dropped silently. Never frees a
    /// TCB (`handle_timeout` does), so buffered data and `Err(Reset)` stay readable.
    pub fn handle_packet(&mut self, now: Instant, ip_packet: &[u8]) {
        let Ok(seg) = packet::parse(ip_packet) else {
            return;
        };
        let Some(&h) = self.demux.get(&(seg.dst, seg.src)) else {
            self.queue_rst(&seg);
            return;
        };
        let Some(c) = self.conns.get_mut(&h) else {
            return;
        };
        match c.tcb.on_segment(&seg, now, &mut c.hooks) {
            Reaction::None => {}
            r => Self::push_event(&mut self.events, c, h, r),
        }
        c.hooks.update_recovery(&c.tcb, now);
        Self::update_close(&mut self.events, c, h, now);
        if std::mem::take(&mut c.hooks.fallback_event) {
            self.events.push_back((h, Event::FellBack));
        }
    }

    fn update_close(
        events: &mut VecDeque<(ConnectionHandle, Event)>,
        c: &mut Connection,
        h: ConnectionHandle,
        now: Instant,
    ) {
        if let Some(reason) = c.hooks.update_close(&c.tcb, now) {
            c.reset |= reason != CloseReason::Normal;
            events.push_back((h, Event::Closed { reason }));
        }
    }

    fn push_event(
        events: &mut VecDeque<(ConnectionHandle, Event)>,
        c: &mut Connection,
        h: ConnectionHandle,
        r: Reaction,
    ) {
        match r {
            Reaction::None => {}
            Reaction::Established => {
                if c.hooks.negotiation.is_some() {
                    return;
                }
                events.push_back((h, Event::Connected { mptcp: false }));
            }
            Reaction::Closed(reason) => {
                if c.hooks.active() {
                    return;
                }
                c.reset |= reason == CloseReason::Reset;
                events.push_back((h, Event::Closed { reason }));
            }
        }
    }

    /// RFC 9293 §3.10.7.1: segment arrives in CLOSED. Never in reply to a RST.
    fn queue_rst(&mut self, seg: &Segment) {
        if seg.flags.contains(TcpFlags::RST) || self.pending_rst.len() >= MAX_PENDING_RST {
            return;
        }
        let (seq, ack, flags) = if seg.flags.contains(TcpFlags::ACK) {
            (seg.ack, SeqNum(0), TcpFlags::RST)
        } else {
            let len = seg.payload.len() as u32
                + seg.flags.contains(TcpFlags::SYN) as u32
                + seg.flags.contains(TcpFlags::FIN) as u32;
            (
                SeqNum(0),
                seg.seq.wrapping_add(len),
                TcpFlags::RST | TcpFlags::ACK,
            )
        };
        self.pending_rst.push_back(PendingRst {
            src: seg.dst,
            dst: seg.src,
            seq,
            ack,
            flags,
        });
    }

    /// Writes one complete IP packet into `buf` and returns its length, or `None` if nothing is
    /// to be sent. `buf` must hold at least the connection MTU: a packet that does not fit is
    /// dropped (TCP retransmission recovers it). Driver contract: call this after every `read`,
    /// `write`, `close` and `handle_packet` until it returns `None`: those calls can make a
    /// packet (window update, data, FIN) due without any timer being armed.
    pub fn poll_transmit(&mut self, now: Instant, buf: &mut [u8]) -> Option<usize> {
        while let Some(r) = self.pending_rst.pop_front() {
            let seg = Segment {
                src: r.src,
                dst: r.dst,
                seq: r.seq,
                ack: r.ack,
                flags: r.flags,
                wnd: 0,
                options: &[],
                payload: &[],
            };
            if let Some(n) = Self::build(&mut self.ip_id, &seg, buf) {
                return Some(n);
            }
        }
        use std::ops::Bound::{Excluded, Included, Unbounded};
        let cursor = ConnectionHandle(self.cursor);
        // Round robin from the cursor, then wrap around; no allocation.
        for bounds in [(Included(cursor), Unbounded), (Unbounded, Excluded(cursor))] {
            for (h, c) in self.conns.range_mut(bounds) {
                // An MPTCP third ACK must remain due until it can be emitted.
                if c.hooks.negotiation.is_some() && buf.len() < c.tcb.mtu() {
                    continue;
                }
                c.hooks.prepare_send(&mut c.tcb, now);
                if c.closed_by_app && !c.hooks.close() {
                    c.tcb.close();
                }
                let sent = c.tcb.poll_send(now, &mut c.hooks, &mut self.scratch);
                let sent = sent.or_else(|| {
                    if c.hooks.assign(&c.tcb, now) {
                        c.tcb.poll_send(now, &mut c.hooks, &mut self.scratch)
                    } else {
                        None
                    }
                });
                if sent.is_none() {
                    continue;
                }
                self.cursor = h.0 + 1;
                let w = &self.scratch;
                let seg = Segment {
                    src: c.local,
                    dst: c.remote,
                    seq: w.seq,
                    ack: w.ack,
                    flags: w.flags,
                    wnd: w.wnd,
                    options: w.options(),
                    payload: &w.payload,
                };
                if let Some(n) = Self::build(&mut self.ip_id, &seg, buf) {
                    c.hooks
                        .on_transmitted(&seg, now, c.tcb.retransmission_timeout());
                    if let Some(mptcp) = c
                        .hooks
                        .negotiation
                        .as_mut()
                        .and_then(|m| m.on_transmitted(w.flags))
                    {
                        self.events.push_back((*h, Event::Connected { mptcp }));
                    }
                    return Some(n);
                }
            }
        }
        None
    }

    fn build(ip_id: &mut u16, seg: &Segment, buf: &mut [u8]) -> Option<usize> {
        let id = *ip_id;
        *ip_id = id.wrapping_add(1);
        packet::build(seg, id, buf).ok()
    }

    /// Earliest `poll_send_at` over all connections. Driver contract: after any `read`,
    /// `write` or `close` call `poll_transmit` (they can make a packet due), then re-read this.
    pub fn poll_timeout(&self) -> Option<Instant> {
        self.conns
            .values()
            .filter(|c| !c.detached)
            .filter_map(|c| {
                let at = c.tcb.poll_send_at();
                at.filter(|_| !c.hooks.active() || c.tcb.state() != TcpState::Closed)
                    .into_iter()
                    .chain(c.hooks.recovery_deadline())
                    .min()
            })
            .min()
    }

    /// Runs `Tcb::on_timeout` on every due TCB (Closed ones included: a SYN-SENT close reports
    /// its `Closed(Normal)` there), then frees the TCBs that are `Closed`.
    pub fn handle_timeout(&mut self, now: Instant) {
        for (&h, c) in self.conns.iter_mut().filter(|(_, c)| !c.detached) {
            c.hooks.update_recovery(&c.tcb, now);
            if c.tcb.poll_send_at().is_some_and(|t| t <= now) {
                let r = c.tcb.on_timeout(now, &mut c.hooks);
                Self::push_event(&mut self.events, c, h, r);
            }
            Self::update_close(&mut self.events, c, h, now);
        }
        let demux = &mut self.demux;
        self.conns.retain(|&h, c| {
            if c.hooks.retained() || c.tcb.reset_pending() {
                return true;
            }
            if c.tcb.state() != TcpState::Closed {
                return true;
            }
            let key = (c.local, c.remote);
            if demux.get(&key) == Some(&h) {
                demux.remove(&key);
            }
            // A reset connection's data is not readable; otherwise keep it until drained.
            c.detached = !c.reset && c.hooks.has_unread();
            c.detached
        });
    }
}

#[cfg(test)]
mod mptcp_tests;
