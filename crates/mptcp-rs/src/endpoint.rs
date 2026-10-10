//! The sans-I/O entry point: owns every connection, demultiplexes packets and builds output
//! (spec §1, §3.1).

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::net::{IpAddr, SocketAddr};

use rand_core::CryptoRng;

use crate::Instant;
use crate::SeqNum;
use crate::connection::{Connection, ConnectionHooks, QueuedJoin};
use crate::crypto::IsnGenerator;
use crate::mptcp::addr::{LocalAddrs, PeerAddrs};
use crate::mptcp::{
    Join, SUBFLOW_CAP, State, Subflow, SubflowHooks, SubflowId, SubflowMp, SubflowState, fastclose,
    tcprst,
};
use crate::tcp::{CloseReason, ConnectConfig, Reaction, SegmentWriter, Tcb, TcpState};
use crate::wire::packet::{self, Segment, TcpFlags};

mod aborted;

/// Queued RSTs for segments without a TCB; beyond this they are dropped.
const MAX_PENDING_RST: usize = 64;
const EPHEMERAL_FIRST: u16 = 49152;
const EPHEMERAL_COUNT: u32 = 65536 - EPHEMERAL_FIRST as u32;

/// Opaque, never reused within one `Endpoint`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ConnectionHandle(u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Event {
    Connected {
        mptcp: bool,
    },
    /// The connection continues as plain TCP on one subflow; every other one was reset (no
    /// `SubflowDown` for them). It ends the per-subflow events: a Stale survivor becomes
    /// Active again without `SubflowRecovered`, and a survivor whose join completed on the
    /// same segment without `SubflowUp`.
    FellBack,
    Closed {
        reason: CloseReason,
    },
    /// A joined subflow completed its MP_JOIN handshake and can carry data.
    SubflowUp {
        subflow: SubflowId,
    },
    /// A subflow ended (`Reset`: refused or reset, also a queued join that can no longer
    /// start, or reset by us at close because it held only DATA_ACKed data; `Timeout`: R2;
    /// `Normal`: FIN exchange). The connection carries on; data the subflow had in flight is
    /// resent on the others; if it was the last open subflow, the no-subflow wait starts and
    /// ends in `Closed` unless `add_subflow` starts a join first. Not emitted for the subflows
    /// a fallback or MP_FASTCLOSE resets, nor for the initial subflow ending after both
    /// DATA_FINs. `rst`: the MP_TCPRST of the peer's RST that ended it, if it carried one.
    SubflowDown {
        subflow: SubflowId,
        reason: CloseReason,
        rst: Option<MpTcpRst>,
    },
    /// A subflow's retransmission timer expired R1 = 3 times in a row: it gets no new data,
    /// and data it had in flight is resent on the other subflows.
    SubflowStale {
        subflow: SubflowId,
    },
    /// A Stale subflow's data was acknowledged again: it carries data again.
    SubflowRecovered {
        subflow: SubflowId,
    },
    /// The peer announced an address (ADD_ADDR) as `id`; `addr` carries the port to join.
    /// Emitted again when the peer repeats the announcement, which also lifts `AddressFailed`.
    /// Never for an unspecified, multicast or loopback address.
    AddressAnnounced {
        id: u8,
        addr: SocketAddr,
    },
    /// The peer withdrew its address `id` (REMOVE_ADDR): one it announced, or one a subflow's
    /// handshake carried (0 for the initial subflow). Each subflow to it is probed and kept if
    /// it answers, else reset (`SubflowDown { Reset }`).
    AddressRemoved {
        id: u8,
    },
    /// The peer asked us to treat `subflow` as backup or not (MP_PRIO).
    PeerPriority {
        subflow: SubflowId,
        backup: bool,
    },
}

/// The MP_TCPRST option of a peer's RST (RFC 8684 §3.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct MpTcpRst {
    pub reason: u8,
    /// The T flag: the condition is temporary, a new join may succeed.
    pub transient: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AddSubflowError {
    NoConnection,
    /// Plain TCP, or the connection fell back to it.
    NotMptcp,
    /// The peer's MP_CAPABLE set C=1, and `remote` is the connection's initial remote address
    /// and port.
    PeerForbidsJoin,
    /// `remote` is an address the peer announced, and a join to it failed; joins to it are
    /// refused until the peer announces it again.
    AddressFailed,
    /// `local` and `remote` are of different IP families.
    FamilyMismatch,
    /// IPv4 needs an MTU of at least 68, IPv6 at least 1280.
    InvalidMtu,
    /// The application closed the connection, or it is closed.
    Closed,
    /// All ephemeral ports from `local` to the remote are in use.
    NoPort,
    /// The connection has 8 subflows, queued joins included.
    TooManySubflows,
    /// The connection has bound 256 local IPs, each to its own address ID, and `local` is
    /// another one.
    TooManyAddresses,
    /// The connection has used up its subflow IDs.
    SubflowIdsExhausted,
}

/// Why a call on one subflow failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SubflowError {
    NoConnection,
    /// The connection never issued this ID, or its subflow has ended.
    NoSubflow,
    /// Plain TCP, or the connection fell back to it.
    NotMptcp,
    /// The application closed the connection, or it is closed.
    Closed,
    /// `close_subflow`: no other Active subflow can take over its data.
    LastSubflow,
}

/// Why `remove_address` failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AddressError {
    NoConnection,
    /// Plain TCP, or the connection fell back to it.
    NotMptcp,
    /// The connection never bound this local IP to an address ID.
    UnknownAddress,
    /// The application closed the connection, or it is closed.
    Closed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
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
    /// MP_FASTCLOSE, on the RSTs of an aborted subflow (M3 spec §3.5).
    option: Option<[u8; 12]>,
}

pub struct Endpoint<R: CryptoRng> {
    rng: R,
    isn: IsnGenerator,
    conns: BTreeMap<ConnectionHandle, Connection>,
    /// (local, remote) → (handle, subflow) (a BTreeMap: no OS-seeded hasher in the core). Closed and TIME-WAIT TCBs stay until `handle_timeout`.
    demux: BTreeMap<(SocketAddr, SocketAddr), (ConnectionHandle, SubflowId)>,
    next_handle: u64,
    /// Round-robin cursor for `poll_transmit`.
    cursor: u64,
    ip_id: u16,
    events: VecDeque<(ConnectionHandle, Event)>,
    pending_rst: VecDeque<PendingRst>,
    /// The 4-tuples `Connection::abort` reset with MP_FASTCLOSE.
    aborted: aborted::Aborted,
    scratch: SegmentWriter,
    /// Connections with queued joins (`Connection::queued_joins`).
    pending_joins: BTreeSet<ConnectionHandle>,
    /// Congestion controller for new connections; `None` is the default (CUBIC).
    #[cfg(test)]
    pub(crate) cc: Option<fn() -> Box<dyn crate::tcp::cc::CongestionControl>>,
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
            aborted: Default::default(),
            scratch: SegmentWriter::default(),
            pending_joins: BTreeSet::new(),
            #[cfg(test)]
            cc: None,
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
        let min_mtu = min_mtu(local, remote.ip()).ok_or(ConnectError::FamilyMismatch)?;
        if cfg.mtu < min_mtu {
            return Err(ConnectError::InvalidMtu);
        }
        if [cfg.send_buffer, cfg.recv_buffer]
            .iter()
            .any(|b| !(1..=1 << 30).contains(b))
        {
            return Err(ConnectError::InvalidBuffer);
        }
        let initial_ip = local;
        let local = (self.free_port(now, local, remote)).ok_or(ConnectError::NoPort)?;
        let isn = self.isn.isn(now, local, remote);
        let tcb = self.new_tcb(&cfg, local, remote, isn, now);
        let h = ConnectionHandle(self.next_handle);
        self.next_handle += 1;
        self.demux.insert((local, remote), (h, SubflowId(0)));
        self.conns.insert(
            h,
            Connection {
                subflows: vec![Subflow {
                    id: SubflowId(0),
                    tcb,
                    local,
                    remote,
                    state: SubflowState::Active,
                    mp: SubflowMp::new(),
                }],
                hooks: ConnectionHooks::new(&cfg),
                closed_by_app: false,
                aborting: false,
                reset: false,
                detached: false,
                cfg,
                nodelay: false,
                queued_joins: Vec::new(),
                next_subflow: 1,
                local_addrs: LocalAddrs::new(initial_ip),
                peer_addrs: PeerAddrs::default(),
                opp: None,
                repair: Default::default(),
            },
        );
        Ok(h)
    }

    /// A free ephemeral port from `local` to `remote`, searched from a random start. A retained
    /// aborted 4-tuple is in use.
    fn free_port(&mut self, now: Instant, local: IpAddr, remote: SocketAddr) -> Option<SocketAddr> {
        let start = self.rng.next_u32() % EPHEMERAL_COUNT;
        (0..EPHEMERAL_COUNT)
            .map(|i| EPHEMERAL_FIRST + ((start + i) % EPHEMERAL_COUNT) as u16)
            .map(|port| SocketAddr::new(local, port))
            .find(|&l| {
                !self.demux.contains_key(&(l, remote))
                    && self.aborted.key((l, remote), now).is_none()
            })
    }

    fn new_tcb(
        &self,
        cfg: &ConnectConfig,
        local: SocketAddr,
        remote: SocketAddr,
        isn: SeqNum,
        now: Instant,
    ) -> Tcb {
        #[cfg(test)]
        if let Some(cc) = self.cc {
            return Tcb::with_cc(cfg, local, remote, isn, now, cc());
        }
        Tcb::new_active(cfg, local, remote, isn, now)
    }

    /// Opens an MP_JOIN subflow from `local`, whose path MTU is `mtu`, to `remote`: the
    /// connection's remote address, or another endpoint of the peer such as one it announced
    /// (`Event::AddressAnnounced`). Its `Tcb` uses the connection's `ConnectConfig` with this
    /// MTU. `backup` is the preference the join advertises, the MP_JOIN SYN's B bit: whether
    /// the peer should send on it only as a backup (`set_backup` changes it later; our own use
    /// of the subflow is `set_local_backup`).
    /// Before the connection is Confirmed (the peer's first DSS) the join is queued and starts
    /// at the first `poll_transmit` after that (RFC 8684 L884–887); a queued join that can no
    /// longer start (fallback, C=1) ends with `SubflowDown { Reset }`. `SubflowUp` follows the
    /// peer's acknowledgement of the third ACK; data goes only to subflows that are up.
    pub fn add_subflow(
        &mut self,
        now: Instant,
        h: ConnectionHandle,
        local: IpAddr,
        remote: SocketAddr,
        mtu: u16,
        backup: bool,
    ) -> Result<SubflowId, AddSubflowError> {
        use AddSubflowError as E;
        // Only IP and port reach the wire (`connect`).
        let remote = SocketAddr::new(remote.ip(), remote.port());
        let c = self.open_mptcp(h, [E::NoConnection, E::NotMptcp, E::Closed])?;
        let m = c.hooks.negotiation.as_ref().unwrap();
        if m.peer_c && remote == c.subflows[0].remote {
            return Err(E::PeerForbidsJoin);
        }
        if c.peer_addrs.failed(remote) {
            return Err(E::AddressFailed);
        }
        let min = min_mtu(local, remote.ip()).ok_or(E::FamilyMismatch)?;
        if mtu < min {
            return Err(E::InvalidMtu);
        }
        if c.subflows.len() + c.queued_joins.len() >= SUBFLOW_CAP {
            return Err(E::TooManySubflows);
        }
        let id = SubflowId(c.next_subflow);
        let next = c
            .next_subflow
            .checked_add(1)
            .ok_or(E::SubflowIdsExhausted)?;
        let addr_id = c.local_addrs.bind(local).ok_or(E::TooManyAddresses)?;
        let join = QueuedJoin {
            id,
            local,
            remote,
            mtu,
            addr_id,
            backup,
            local_backup: false,
        };
        if m.state == State::Confirmed {
            self.start_join(now, h, join)?;
        } else {
            c.queued_joins.push(join);
            self.pending_joins.insert(h);
        }
        let c = self.conns.get_mut(&h).unwrap();
        c.next_subflow = next;
        c.hooks.signals.cancel_remove(addr_id);
        Ok(id)
    }

    /// `h` as an open MPTCP connection, else the caller's error for: no such connection, not
    /// MPTCP (plain TCP or fallen back), closed.
    fn open_mptcp<E>(
        &mut self,
        h: ConnectionHandle,
        [none, not_mptcp, closed_err]: [E; 3],
    ) -> Result<&mut Connection, E> {
        let c = self.conns.get_mut(&h).ok_or(none)?;
        if !(c.hooks.negotiation.as_ref()).is_some_and(|m| m.state != State::FellBack) {
            return Err(not_mptcp);
        }
        if c.closed_by_app || c.reset || c.detached || closed(c) {
            return Err(closed_err);
        }
        Ok(c)
    }

    /// The connection of a call on subflow `s`, which must be issued and not ended (a queued
    /// join counts). TIME-WAIT is ended: entering it reported `SubflowDown`.
    fn subflow_conn(
        &mut self,
        h: ConnectionHandle,
        s: SubflowId,
    ) -> Result<&mut Connection, SubflowError> {
        use SubflowError as E;
        let c = self.open_mptcp(h, [E::NoConnection, E::NotMptcp, E::Closed])?;
        let ended = |sf: &Subflow| matches!(sf.tcb.state(), TcpState::Closed | TcpState::TimeWait);
        let open = |sf: &Subflow| sf.id == s && !ended(sf);
        if !(c.subflows.iter().any(open) || c.queued_joins.iter().any(|q| q.id == s)) {
            return Err(E::NoSubflow);
        }
        Ok(c)
    }

    /// Advertises whether the peer should send on subflow `s` only as a backup: an MP_PRIO on
    /// `s` (RFC 8684 §3.3.8), sent once on an ACK when `s` is up and the connection Confirmed.
    /// MP_PRIO is not acknowledged, so it may be lost; call again to repeat it. Each call
    /// leaves one MP_PRIO due with the latest value. Our own use of `s` is unchanged
    /// (`set_local_backup`); the peer's requests arrive as `Event::PeerPriority`.
    pub fn set_backup(
        &mut self,
        _now: Instant,
        h: ConnectionHandle,
        s: SubflowId,
        backup: bool,
    ) -> Result<(), SubflowError> {
        let c = self.subflow_conn(h, s)?;
        c.hooks.signals.prio(s, backup);
        Ok(())
    }

    /// Sends on subflow `s` only as a backup, or not; no wire effect. A subflow is a backup if
    /// this says so or the peer asked for it (MP_JOIN B bit, MP_PRIO): new data, reinjections
    /// and copies go to a backup subflow only while no other subflow is usable, Active with a
    /// nonzero peer window. A busy (cwnd- or pacing-limited) subflow is still usable. May be
    /// called as soon as `add_subflow` returns.
    pub fn set_local_backup(
        &mut self,
        h: ConnectionHandle,
        s: SubflowId,
        backup: bool,
    ) -> Result<(), SubflowError> {
        let c = self.subflow_conn(h, s)?;
        match c.subflows.iter_mut().find(|sf| sf.id == s) {
            Some(sf) => sf.mp.local_backup = backup,
            None => {
                let q = c.queued_joins.iter_mut().find(|q| q.id == s).unwrap();
                q.local_backup = backup;
            }
        }
        Ok(())
    }

    /// Retires subflow `s`, which still works, by FIN exchange (RFC 8684 L2114–2116): it gets
    /// no new data, its TCP retransmissions go on, and once it ends (`SubflowDown`) the data it
    /// held that is not DATA_ACKed is resent on the others. A queued join, or one still in
    /// SYN-SENT, is dropped (`SubflowDown { Reset }`). Only while another subflow can take over: one that is Active
    /// (not Joining, Stale or retiring), not under the peer's REMOVE_ADDR keepalive, and has an
    /// established TCB; a closed window or busy cwnd does not matter. Otherwise `LastSubflow`
    /// and nothing changes: closing every subflow is `Connection::close`.
    pub fn close_subflow(
        &mut self,
        now: Instant,
        h: ConnectionHandle,
        s: SubflowId,
    ) -> Result<(), SubflowError> {
        let c = self.subflow_conn(h, s)?;
        if !(c.subflows.iter()).any(|o| o.id != s && o.can_replace()) {
            return Err(SubflowError::LastSubflow);
        }
        let dropped = match c.subflows.iter_mut().find(|sf| sf.id == s) {
            // RFC 9293 §3.10.4: CLOSE in SYN-SENT deletes the TCB, sending nothing.
            Some(sf) if sf.tcb.state() == TcpState::SynSent => {
                sf.tcb.delete(now);
                true
            }
            Some(sf) => {
                sf.state = SubflowState::Closing;
                sf.tcb.close();
                false
            }
            None => {
                c.queued_joins.retain(|q| q.id != s);
                true
            }
        };
        if dropped {
            (self.events).push_back((h, down(s, CloseReason::Reset, None)));
        }
        Ok(())
    }

    /// Withdraws the local IP `local`, which is no longer valid (its interface is gone; RFC
    /// 8684 §3.4.2). Every subflow using it is reset with MP_TCPRST 0x00 T=0, and joins queued
    /// from it are dropped, each with `SubflowDown { Reset }`; with no subflow left the
    /// no-subflow wait starts. If the peer has learned `local`'s address ID (the initial IP's
    /// is 0), a REMOVE_ADDR for it goes once on another Active subflow, when one exists. A later
    /// `add_subflow` from `local` keeps the ID and drops that REMOVE_ADDR if it has not gone
    /// out yet. To retire a working path, `close_subflow` it first (make-before-break).
    pub fn remove_address(
        &mut self,
        now: Instant,
        h: ConnectionHandle,
        local: IpAddr,
    ) -> Result<(), AddressError> {
        use AddressError as E;
        let c = self.open_mptcp(h, [E::NoConnection, E::NotMptcp, E::Closed])?;
        let id = c.local_addrs.id(local).ok_or(E::UnknownAddress)?;
        if c.local_addrs.on_wire(id) {
            c.hooks.signals.remove(id);
        }
        let c = self.conns.get_mut(&h).unwrap();
        for i in 0..c.subflows.len() {
            let sf = &c.subflows[i];
            let ended = matches!(sf.tcb.state(), TcpState::Closed | TcpState::TimeWait);
            if sf.local.ip() != local || ended {
                continue;
            }
            let last = !others_open(&c.subflows, i);
            let rst = Some(tcprst(0x00, false));
            let r = c.subflows[i].tcb.abort_with(CloseReason::Reset, rst, now);
            Self::report(&mut self.events, h, c, i, r, last, now);
        }
        for q in std::mem::take(&mut c.queued_joins) {
            if q.local == local {
                (self.events).push_back((h, down(q.id, CloseReason::Reset, None)));
            } else {
                c.queued_joins.push(q);
            }
        }
        Ok(())
    }

    /// Materializes a join: port, ISN, nonce, demux entry and a Joining subflow whose `Tcb`
    /// sends the MP_JOIN SYN at the next `poll_transmit`.
    fn start_join(
        &mut self,
        now: Instant,
        h: ConnectionHandle,
        q: QueuedJoin,
    ) -> Result<(), AddSubflowError> {
        let c = &self.conns[&h];
        let remote = q.remote;
        let cfg = ConnectConfig {
            mtu: q.mtu,
            ..c.cfg.clone()
        };
        let local = (self.free_port(now, q.local, remote)).ok_or(AddSubflowError::NoPort)?;
        let isn = self.isn.isn(now, local, remote);
        let mut tcb = self.new_tcb(&cfg, local, remote, isn, now);
        let nonce = self.rng.next_u32();
        let c = self.conns.get_mut(&h).unwrap();
        tcb.set_nodelay(c.nodelay);
        // SubflowMp fields the MP_CAPABLE path would set: this subflow's own ISN, and nothing
        // TCP-acknowledged on it yet. `peer_scale` comes with its SYN/ACK (`join_segment`).
        let mut mp = SubflowMp::new();
        mp.local_isn = isn;
        mp.tcp_acked_dsn = c.hooks.data.as_ref().map_or(0, |d| d.send.una);
        mp.join = Some(Join::new(nonce, q.addr_id, q.backup));
        mp.local_backup = q.local_backup;
        c.hooks.cancel_no_subflow_wait();
        self.demux.insert((local, remote), (h, q.id));
        c.subflows.push(Subflow {
            id: q.id,
            tcb,
            local,
            remote,
            state: SubflowState::Joining,
            mp,
        });
        Ok(())
    }

    /// Starts the queued joins of connections that became Confirmed; drops those that can no
    /// longer start (fallback, C=1 for the initial remote, connection closed).
    fn start_queued_joins(&mut self, now: Instant) {
        for h in std::mem::take(&mut self.pending_joins) {
            let Some(c) = self.conns.get_mut(&h) else {
                continue;
            };
            let m = c.hooks.negotiation.as_ref().unwrap();
            let open = !c.reset && !c.detached && !closed(c);
            let (state, peer_c, initial) = (m.state, m.peer_c, c.subflows[0].remote);
            let waiting = open && matches!(state, State::SynSent | State::PreConfirmed);
            let mut kept = Vec::new();
            for q in std::mem::take(&mut c.queued_joins) {
                let subflow = q.id;
                let allowed = open && !(peer_c && q.remote == initial);
                if allowed && waiting {
                    kept.push(q);
                } else if !(allowed
                    && state == State::Confirmed
                    && self.start_join(now, h, q).is_ok())
                {
                    (self.events).push_back((h, down(subflow, CloseReason::Reset, None)));
                }
            }
            if !kept.is_empty() {
                self.conns.get_mut(&h).unwrap().queued_joins = kept;
                self.pending_joins.insert(h);
            }
        }
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
        self.apply_aborts(now);
        let Some(&(h, id)) = self.demux.get(&(seg.dst, seg.src)) else {
            self.queue_rst(&seg, now);
            return;
        };
        let Some(c) = self.conns.get_mut(&h) else {
            return;
        };
        let Some(mut i) = c.subflows.iter().position(|sf| sf.id == id) else {
            return;
        };
        // A Closed TCB kept for its connection (`subflows[0]`, or until `handle_timeout`)
        // answers as CLOSED (§3.10.7.1); a RST still due for it is the answer already.
        let tcb = &c.subflows[i].tcb;
        if tcb.state() == TcpState::Closed {
            if !tcb.reset_pending() {
                self.queue_rst(&seg, now);
            }
            return;
        }
        let last = !others_open(&c.subflows, i);
        let sf = &mut c.subflows[i];
        let mut hk = SubflowHooks {
            conn: &mut c.hooks,
            sf: &mut sf.mp,
        };
        let r = sf.tcb.on_segment(&seg, now, &mut hk);
        let port = sf.remote.port();
        if let Some(backup) = sf.mp.peer_prio.take() {
            let subflow = sf.id;
            (self.events).push_back((h, Event::PeerPriority { subflow, backup }));
        }
        c.note_join_failure(i);
        // MP_FASTCLOSE tears down every subflow (RFC 8684 L2168–2172).
        if c.hooks.fast_closed {
            c.abort_all(now, Some(i), None);
        }
        let mut fell_back = std::mem::take(&mut c.hooks.fallback_event);
        if fell_back {
            if c.on_fallback(i, now) {
                fell_back = false;
                c.reset = true;
                let reason = CloseReason::FallbackDataLoss;
                self.events.push_back((h, Event::Closed { reason }));
            }
            i = 0;
        }
        for id in std::mem::take(&mut c.hooks.peer_removed) {
            if c.hooks.active() && c.peer_removed(id) {
                self.events.push_back((h, Event::AddressRemoved { id }));
            }
        }
        for e in std::mem::take(&mut c.hooks.peer_announced) {
            if let Some(addr) = (c.hooks.active())
                .then(|| c.peer_announced(e, port))
                .flatten()
            {
                (self.events).push_back((h, Event::AddressAnnounced { id: e.id, addr }));
            }
        }
        // Events first: a join this segment completed is Active before `update_health`, so a
        // bare FIN on the same segment retires it (`SubflowUp`, then the Closing path).
        let sf = &mut c.subflows[i];
        if i != 0 {
            let joining = sf.mp.joining();
            let view = (sf.id, &mut sf.state, &sf.tcb, sf.mp.rst);
            Self::subflow_event(&mut self.events, &c.hooks, h, view, joining, r);
        } else if r != Reaction::None {
            let rst = sf.mp.rst;
            Self::push_event(&mut self.events, &c.hooks, &mut c.reset, h, r, !last, rst);
        }
        if let Some(e) = c.update_health(i) {
            self.events.push_back((h, e));
        }
        let sf = &mut c.subflows[i];
        let mut hk = SubflowHooks {
            conn: &mut c.hooks,
            sf: &mut sf.mp,
        };
        Self::update_close(
            &mut self.events,
            &mut hk,
            &sf.tcb,
            &mut c.reset,
            h,
            now,
            last,
        );
        c.update_recovery(now);
        if fell_back {
            self.events.push_back((h, Event::FellBack));
        }
        Self::free_ended(&mut self.demux, h, c);
    }

    /// Frees the ended subflows (TCB Closed, no RST left to send) other than `subflows[0]`,
    /// with their demux entries and ports, as soon as they end. A subflow in TIME-WAIT is not
    /// Closed, so it keeps its 4-tuple until 2·MSL.
    fn free_ended(
        demux: &mut BTreeMap<(SocketAddr, SocketAddr), (ConnectionHandle, SubflowId)>,
        h: ConnectionHandle,
        c: &mut Connection,
    ) {
        let mut first = true;
        let freed = &mut c.hooks.freed_dsn_end;
        let signals = &mut c.hooks.signals;
        c.subflows.retain(|sf| {
            let keep = std::mem::take(&mut first)
                || sf.tcb.state() != TcpState::Closed
                || sf.tcb.reset_pending();
            if !keep {
                signals.forget(sf.id);
                if let Some(end) = sf.mp.dsn_end {
                    *freed = crate::mptcp::later(*freed, end);
                }
                if demux.get(&(sf.local, sf.remote)) == Some(&(h, sf.id)) {
                    demux.remove(&(sf.local, sf.remote));
                }
            }
            keep
        });
    }

    /// After reaction `r` of subflow `i` to a timeout or a local call (`last`: no other subflow
    /// was open before it): its health, its event and the connection's close.
    fn report(
        events: &mut VecDeque<(ConnectionHandle, Event)>,
        h: ConnectionHandle,
        c: &mut Connection,
        i: usize,
        r: Reaction,
        last: bool,
        now: Instant,
    ) {
        c.note_join_failure(i);
        if let Some(e) = c.update_health(i) {
            events.push_back((h, e));
        }
        let sf = &mut c.subflows[i];
        let mut hk = SubflowHooks {
            conn: &mut c.hooks,
            sf: &mut sf.mp,
        };
        if i != 0 {
            let joining = hk.sf.joining();
            let view = (sf.id, &mut sf.state, &sf.tcb, hk.sf.rst);
            Self::subflow_event(events, hk.conn, h, view, joining, r);
        } else {
            let rst = hk.sf.rst;
            Self::push_event(events, hk.conn, &mut c.reset, h, r, !last, rst);
        }
        Self::update_close(events, &mut hk, &sf.tcb, &mut c.reset, h, now, last);
    }

    #[allow(clippy::too_many_arguments)]
    fn update_close(
        events: &mut VecDeque<(ConnectionHandle, Event)>,
        hk: &mut SubflowHooks<'_>,
        tcb: &Tcb,
        reset: &mut bool,
        h: ConnectionHandle,
        now: Instant,
        last: bool,
    ) {
        if let Some(reason) = hk.update_close(tcb, now, last) {
            *reset |= reason != CloseReason::Normal;
            events.push_back((h, Event::Closed { reason }));
        }
    }

    /// The events of a subflow other than `subflows[0]`: `SubflowDown` when its TCB ends
    /// (not for an MP_FASTCLOSE reset), else `SubflowUp` once its join completes (`joining`
    /// false), which also makes it Active.
    fn subflow_event(
        events: &mut VecDeque<(ConnectionHandle, Event)>,
        hooks: &ConnectionHooks,
        h: ConnectionHandle,
        (subflow, state, tcb, rst): (SubflowId, &mut SubflowState, &Tcb, Option<MpTcpRst>),
        joining: bool,
        r: Reaction,
    ) {
        let reason = match r {
            Reaction::Closed(reason) => Some(reason),
            // A SYN/ACK the join rejects resets the TCB inside its `Established` processing.
            Reaction::Established if tcb.state() == TcpState::Closed => Some(CloseReason::Reset),
            _ => None,
        };
        if let Some(reason) = reason {
            if !hooks.fast_closed {
                events.push_back((h, down(subflow, reason, rst)));
            }
        } else if *state == SubflowState::Joining && !joining {
            *state = SubflowState::Active;
            events.push_back((h, Event::SubflowUp { subflow }));
        }
    }

    /// The events of `subflows[0]`. With MPTCP active its end is `SubflowDown` while the
    /// connection carries on (not on MP_FASTCLOSE): another subflow is open (`others_open`),
    /// or, as the last one, its end starts the no-subflow wait, whose end is `Closed`.
    fn push_event(
        events: &mut VecDeque<(ConnectionHandle, Event)>,
        hooks: &ConnectionHooks,
        reset: &mut bool,
        h: ConnectionHandle,
        r: Reaction,
        others_open: bool,
        rst: Option<MpTcpRst>,
    ) {
        match r {
            Reaction::None => {}
            Reaction::Established => {
                if hooks.negotiation.is_some() {
                    return;
                }
                events.push_back((h, Event::Connected { mptcp: false }));
            }
            Reaction::Closed(reason) => {
                if hooks.active() {
                    let carries_on = others_open || !hooks.data_closed();
                    if carries_on && hooks.retained() && !hooks.fast_closed {
                        events.push_back((h, down(SubflowId::INITIAL, reason, rst)));
                    }
                    return;
                }
                *reset |= reason == CloseReason::Reset;
                events.push_back((h, Event::Closed { reason }));
            }
        }
    }

    /// Carries out `Connection::abort` (M3 spec §3.5) where it was called: every TCB is
    /// deleted, each synchronized one (TIME-WAIT included) with a RST at SND.MAX, with
    /// MP_FASTCLOSE and a retained 4-tuple when MPTCP is in use.
    fn apply_aborts(&mut self, now: Instant) {
        for (&h, c) in &mut self.conns {
            if !std::mem::take(&mut c.aborting) || ended(c) {
                continue;
            }
            let key = c.hooks.abort();
            for sf in &mut c.subflows {
                let state = sf.tcb.state();
                if state == TcpState::Closed {
                    continue;
                }
                let rto = sf.tcb.retransmission_timeout();
                let seq = sf.tcb.delete(now);
                if state == TcpState::SynSent {
                    continue;
                }
                let (src, dst) = (sf.local, sf.remote);
                let (ack, flags, option) = (SeqNum(0), TcpFlags::RST, key.map(fastclose));
                // Not bounded by MAX_PENDING_RST: at most SUBFLOW_CAP, once per connection.
                (self.pending_rst).push_back(PendingRst {
                    src,
                    dst,
                    seq,
                    ack,
                    flags,
                    option,
                });
                if let Some(key) = key {
                    self.aborted.insert((src, dst), key, now + 3 * rto);
                }
            }
            c.reset = true;
            let reason = CloseReason::Aborted;
            self.events.push_back((h, Event::Closed { reason }));
        }
    }

    /// RFC 9293 §3.10.7.1: segment arrives in CLOSED. Never in reply to a RST. On a retained
    /// aborted 4-tuple the RST carries MP_FASTCLOSE (M3 spec §3.5).
    fn queue_rst(&mut self, seg: &Segment, now: Instant) {
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
        let option = self.aborted.key((seg.dst, seg.src), now).map(fastclose);
        self.pending_rst.push_back(PendingRst {
            src: seg.dst,
            dst: seg.src,
            seq,
            ack,
            flags,
            option,
        });
    }

    /// Writes one complete IP packet into `buf` and returns its length, or `None` if nothing is
    /// to be sent. `buf` must hold the largest MTU of any subflow of any connection: a subflow
    /// whose MTU exceeds `buf.len()` is skipped (nothing is built for it, so no sequence,
    /// mapping, pacing or timer state is consumed) until a large enough `buf` is passed.
    /// Driver contract: call this after every `read`, `write`, `close`, `abort`, `add_subflow`
    /// and `handle_packet` until it returns `None`: those calls can make a packet (window update,
    /// data, FIN, MP_JOIN SYN) due without any timer being armed.
    pub fn poll_transmit(&mut self, now: Instant, buf: &mut [u8]) -> Option<usize> {
        self.apply_aborts(now);
        while let Some(r) = self.pending_rst.pop_front() {
            let seg = Segment {
                src: r.src,
                dst: r.dst,
                seq: r.seq,
                ack: r.ack,
                flags: r.flags,
                wnd: 0,
                options: r.option.as_ref().map_or(&[], |o| o),
                payload: &[],
            };
            if let Some(n) = Self::build(&mut self.ip_id, &seg, buf) {
                return Some(n);
            }
        }
        if !self.pending_joins.is_empty() {
            self.start_queued_joins(now);
        }
        use std::ops::Bound::{Excluded, Included, Unbounded};
        let cursor = ConnectionHandle(self.cursor);
        // Round robin from the cursor, then wrap around; no allocation.
        for bounds in [(Included(cursor), Unbounded), (Unbounded, Excluded(cursor))] {
            for (h, c) in self.conns.range_mut(bounds) {
                c.update_recovery(now);
                c.select_control();
                // Step 1 (spec §3.1): each subflow's own traffic — ACKs, TCP retransmissions,
                // assigned data, control items — never through the scheduler.
                let mut sent = None;
                for (i, sf) in c.subflows.iter_mut().enumerate() {
                    let mut hk = SubflowHooks {
                        conn: &mut c.hooks,
                        sf: &mut sf.mp,
                    };
                    // Whatever is due (a third ACK, data) stays due until `buf` can hold it.
                    if buf.len() < sf.tcb.mtu() {
                        continue;
                    }
                    hk.prepare_send(&mut sf.tcb, now, sf.id);
                    if c.closed_by_app && !hk.conn.close() {
                        sf.tcb.close();
                    }
                    if sf.tcb.poll_send(now, &mut hk, &mut self.scratch).is_some() {
                        sent = Some(i);
                        break;
                    }
                }
                // Steps 2–3: plan one mapping, install it, send it on its subflow.
                if sent.is_none() {
                    if let Some(i) = c.schedule(now, buf.len()) {
                        let sf = &mut c.subflows[i];
                        let mut hk = SubflowHooks {
                            conn: &mut c.hooks,
                            sf: &mut sf.mp,
                        };
                        if sf.tcb.poll_send(now, &mut hk, &mut self.scratch).is_some() {
                            sent = Some(i);
                        }
                    }
                }
                let Some(i) = sent else {
                    continue;
                };
                let sf = &mut c.subflows[i];
                let mut hk = SubflowHooks {
                    conn: &mut c.hooks,
                    sf: &mut sf.mp,
                };
                self.cursor = h.0 + 1;
                let w = &self.scratch;
                let seg = Segment {
                    src: sf.local,
                    dst: sf.remote,
                    seq: w.seq,
                    ack: w.ack,
                    flags: w.flags,
                    wnd: w.wnd,
                    options: w.options(),
                    payload: &w.payload,
                };
                if let Some(n) = Self::build(&mut self.ip_id, &seg, buf) {
                    let rto = sf.tcb.retransmission_timeout();
                    hk.on_transmitted(&seg, now, rto);
                    hk.sf.keepalive_sent(sf.tcb.keepalive_pending(), now, rto);
                    if let Some(j) = hk
                        .sf
                        .join
                        .as_ref()
                        .filter(|_| w.flags.contains(TcpFlags::SYN))
                    {
                        c.local_addrs.sent(j.addr_id);
                    }
                    if let Some(mptcp) = hk
                        .conn
                        .negotiation
                        .as_mut()
                        .and_then(|m| m.on_transmitted(w.flags))
                    {
                        self.events.push_back((*h, Event::Connected { mptcp }));
                    }
                    if w.flags.contains(TcpFlags::RST) {
                        Self::free_ended(&mut self.demux, *h, c);
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
                c.subflows
                    .iter()
                    .flat_map(|sf| {
                        let open = sf.tcb.state() != TcpState::Closed;
                        let tcb = sf
                            .tcb
                            .poll_send_at()
                            .filter(|_| !c.hooks.retained() || open);
                        let join = (sf.mp.join.as_ref().filter(|_| open))
                            .and_then(|j| j.deadline(c.cfg.r2_data));
                        let strand = sf.mp.strand_at.filter(|_| open);
                        let keepalive = sf.mp.keepalive.and_then(|k| k.deadline);
                        let keepalive = keepalive.filter(|_| open);
                        tcb.into_iter().chain(join).chain(strand).chain(keepalive)
                    })
                    .chain(c.hooks.recovery_deadline())
                    .chain(c.opp_deadline())
                    .chain(c.hooks.signals.next_wake())
                    .chain(c.aborting.then_some(Instant::from_nanos(0)))
                    .min()
            })
            .chain(self.aborted.next_expiry())
            .min()
    }

    /// Runs `Tcb::on_timeout` on every due TCB (Closed ones included: a SYN-SENT close reports
    /// its `Closed(Normal)` there) and the MP_JOIN third-ACK items, then frees the TCBs that
    /// are `Closed`: ended joined subflows with their ports, and connections.
    pub fn handle_timeout(&mut self, now: Instant) {
        self.apply_aborts(now);
        self.aborted.expire(now);
        for (&h, c) in self.conns.iter_mut().filter(|(_, c)| !c.detached) {
            c.update_recovery(now);
            for i in 0..c.subflows.len() {
                let last = !others_open(&c.subflows, i);
                let sf = &mut c.subflows[i];
                let mut hk = SubflowHooks {
                    conn: &mut c.hooks,
                    sf: &mut sf.mp,
                };
                let mut r = Reaction::None;
                if hk.sf.strand_at.is_some_and(|t| t <= now) && sf.tcb.state() != TcpState::Closed {
                    // Like a FIN exchange's end, a joined subflow reports `SubflowDown`.
                    r = sf
                        .tcb
                        .abort_with(CloseReason::Reset, Some(tcprst(0x04, true)), now);
                } else if sf.tcb.state() != TcpState::Closed && hk.sf.keepalive_failed(now) {
                    // The REMOVE_ADDR keepalive went unanswered (M3 spec §3.3, §3.4).
                    r = sf
                        .tcb
                        .abort_with(CloseReason::Reset, Some(tcprst(0x00, false)), now);
                } else if sf.tcb.poll_send_at().is_some_and(|t| t <= now) {
                    r = sf.tcb.on_timeout(now, &mut hk);
                }
                if let Some(j) = &mut hk.sf.join {
                    if r == Reaction::None && sf.tcb.state() != TcpState::Closed {
                        r = j.on_timeout(&mut sf.tcb, now, c.cfg.r2_data);
                    }
                }
                // A join that timed out (SYN R2, third-ACK give-up) failed (M3 spec §3.3).
                if r == Reaction::Closed(CloseReason::Timeout) && hk.sf.joining() {
                    hk.sf.join_failed = Some(None);
                }
                // Once a join was started, a subflow ended at R2 is reset, so that the peer
                // frees it too and schedules nothing more on it; before that, the initial
                // subflow keeps the M0/M1 behaviour.
                if (hk.sf.join.is_some() || hk.conn.joined_ever)
                    && r == Reaction::Closed(CloseReason::Timeout)
                    && !sf.tcb.reset_pending()
                {
                    sf.tcb
                        .abort_with(CloseReason::Timeout, Some(tcprst(0x00, true)), now);
                }
                Self::report(&mut self.events, h, c, i, r, last, now);
            }
            Self::free_ended(&mut self.demux, h, c);
        }
        let (demux, events) = (&mut self.demux, &mut self.events);
        self.conns.retain(|&h, c| {
            if c.hooks.retained() || c.subflows.iter().any(|sf| sf.tcb.reset_pending()) {
                return true;
            }
            if c.subflows
                .iter()
                .any(|sf| sf.tcb.state() != TcpState::Closed)
            {
                return true;
            }
            for sf in &c.subflows {
                let key = (sf.local, sf.remote);
                if demux.get(&key) == Some(&(h, sf.id)) {
                    demux.remove(&key);
                }
            }
            for q in c.queued_joins.drain(..) {
                events.push_back((h, down(q.id, CloseReason::Reset, None)));
            }
            // A reset connection's data is not readable; otherwise keep it until drained.
            c.detached = !c.reset && c.hooks.has_unread();
            c.detached
        });
    }
}

/// `SubflowDown`; `rst`: the MP_TCPRST of the peer RST that ended the subflow.
fn down(subflow: SubflowId, reason: CloseReason, rst: Option<MpTcpRst>) -> Event {
    Event::SubflowDown {
        subflow,
        reason,
        rst,
    }
}

/// IPv4 needs an MTU of at least 68, IPv6 at least 1280; `None` for mixed families.
fn min_mtu(local: IpAddr, remote: IpAddr) -> Option<u16> {
    match (local, remote) {
        (IpAddr::V4(_), IpAddr::V4(_)) => Some(68),
        (IpAddr::V6(_), IpAddr::V6(_)) => Some(1280),
        _ => None,
    }
}

/// Some subflow other than `subflows[i]` is open.
fn others_open(subflows: &[Subflow], i: usize) -> bool {
    (subflows.iter().enumerate()).any(|(j, s)| j != i && s.tcb.state() != TcpState::Closed)
}

/// `Closed` was reported, or (a `close` in SYN-SENT) is due without further input.
fn ended(c: &Connection) -> bool {
    let initial = c.subflows[0].tcb.state();
    c.detached
        || if c.hooks.active() {
            !c.hooks.retained()
        } else {
            matches!(initial, TcpState::Closed | TcpState::TimeWait)
        }
}

/// The connection's data level has closed (MPTCP; no data state yet counts as open).
fn closed(c: &Connection) -> bool {
    c.hooks.data.is_some() && !c.hooks.retained()
}

#[cfg(test)]
mod mptcp_tests;
