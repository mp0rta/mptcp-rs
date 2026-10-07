//! M1 negotiation and DSN storage. Temporarily test-gated until full data/close integration.
//!
//! Step 3 supplies TX assignment, mapping option plans and shared window advertisements. Before
//! Step 6 enables public MPTCP, remove the staging gates in lib, connection, endpoint and Tcb;
//! use this same negotiation logic in production (no separate test implementation).
pub(crate) mod data;
use crate::crypto::key_token_idsn;
use data::{RecvAssembler, RxMaps, SendStore, TxMaps, promote32};

use crate::tcp::{ConnectConfig, PlainHooks, SegmentHooks, SendBuf};
use crate::wire::packet::{Segment, TcpFlags};
use crate::wire::{
    mptcp::{self, CAP_C, CAP_H, MpCapable, MptcpOption},
    tcp_options::{TcpOpt, walk},
};

pub(crate) struct ConnectionHooks {
    plain: PlainHooks,
    pub negotiation: Option<Negotiation>,
    pub data: Option<DataState>,
    recv_cap: usize,
    send_cap: usize,
}

pub(crate) struct DataState {
    pub recv: RecvAssembler,
    pub send: SendStore,
    pub tx: TxMaps,
    rx: RxMaps,
    unmapped: usize,
    reset: bool,
    pub sanity_failures: u64,
}

impl ConnectionHooks {
    pub fn new(cfg: &ConnectConfig) -> Self {
        Self {
            plain: PlainHooks::new(cfg),
            negotiation: None,
            data: None,
            recv_cap: cfg.recv_buffer as usize,
            send_cap: cfg.send_buffer as usize,
        }
    }
    pub fn write(&mut self, bytes: &[u8]) -> usize {
        self.data
            .as_mut()
            .map_or_else(|| self.plain.write(bytes), |d| d.send.write(bytes))
    }
    pub fn read(&mut self, out: &mut [u8]) -> usize {
        match &mut self.data {
            Some(d) => d.recv.read(out),
            None => self.plain.read(out),
        }
    }
    pub fn has_unread(&self) -> bool {
        self.data
            .as_ref()
            .map_or_else(|| self.plain.has_unread(), |d| d.recv.has_unread())
    }
}
impl SendBuf for ConnectionHooks {
    fn peek_with<R>(&self, ssn: u32, max: usize, f: impl FnOnce(&[u8]) -> R) -> Option<R> {
        match &self.data {
            Some(d) => d.tx.peek_with(ssn, max, f),
            None => self.plain.peek_with(ssn, max, f),
        }
    }
    fn assigned_end(&self) -> u32 {
        self.data
            .as_ref()
            .map_or_else(|| self.plain.assigned_end(), |d| d.tx.assigned_end())
    }
    fn mark_acked(&mut self, ssn: u32) {
        match &mut self.data {
            Some(d) => d.tx.mark_acked(ssn),
            None => self.plain.mark_acked(ssn),
        }
    }
}
impl SegmentHooks for ConnectionHooks {
    fn options_for(&mut self, flags: TcpFlags, out: &mut [u8]) -> usize {
        if let (Some(m), Some(d)) = (&self.negotiation, &self.data) {
            if m.state == State::Confirmed && flags.contains(TcpFlags::ACK) {
                return mptcp::encode(
                    &MptcpOption::Dss(mptcp::Dss {
                        data_fin: false,
                        data_ack: Some(mptcp::DataAck::Ack64(d.recv.next)),
                        mapping: None,
                    }),
                    out,
                )
                .expect("DSS ACK fits");
            }
        }
        self.negotiation
            .as_mut()
            .map_or(0, |m| m.options_for(flags, out))
    }
    fn on_valid_segment(&mut self, seg: &Segment<'_>) {
        let Some(m) = &mut self.negotiation else {
            return;
        };
        m.on_valid_segment(seg);
        if self.data.is_none() && matches!(m.state, State::PreConfirmed | State::Confirmed) {
            let mut send = SendStore::new(m.local_idsn.wrapping_add(1), self.send_cap);
            // Writes during SYN-SENT were queued before knowing whether MPC succeeds.
            let mut ssn = 1;
            while let Some(n) = self
                .plain
                .peek_with(ssn, self.send_cap, |bytes| send.write(bytes))
            {
                debug_assert!(n > 0);
                ssn = ssn.wrapping_add(n as u32);
                self.plain.mark_acked(ssn);
            }
            self.data = Some(DataState {
                recv: RecvAssembler::new(m.peer_idsn.unwrap().wrapping_add(1), self.recv_cap, 64),
                send,
                tx: TxMaps::new(1, 1024),
                rx: RxMaps::new(1024),
                unmapped: 0,
                reset: false,
                sanity_failures: 0,
            });
        }
        if seg.flags.contains(TcpFlags::SYN) || seg.flags.contains(TcpFlags::RST) {
            return;
        }
        let Some(d) = &mut self.data else {
            return;
        };
        // Validate the whole option list before mutating mapping or DATA_ACK state.
        let (mut dss, mut capable) = (None, None);
        for opt in walk(seg.options) {
            match opt {
                Err(_) => return,
                Ok(TcpOpt::Mptcp(raw)) => match mptcp::parse(raw) {
                    Ok(MptcpOption::Dss(v)) if dss.is_none() => dss = Some(v),
                    Ok(MptcpOption::Capable(v)) if capable.is_none() => capable = Some(v),
                    Ok(MptcpOption::Dss(_) | MptcpOption::Capable(_)) | Err(_) => return,
                    _ => {}
                },
                _ => {}
            }
        }
        if let Some(c) = capable {
            if let Some(len) = c.data_len {
                if c.sender_key != m.peer_key
                    || c.receiver_key != Some(m.local_key)
                    || !d
                        .rx
                        .install(1, m.peer_idsn.unwrap().wrapping_add(1), u32::from(len))
                {
                    d.reset = true;
                    return;
                }
                d.unmapped = 0;
            }
        }
        if let Some(v) = dss {
            if let Some(mapping) = v.mapping {
                let dsn = match mapping.dsn {
                    mptcp::Dsn::Dsn32(x) => promote32(x, d.recv.next),
                    mptcp::Dsn::Dsn64(x) => x,
                };
                // Infinite mappings and DATA_FIN lifecycle are integrated by Steps 4/5.
                let len = u32::from(mapping.data_len).saturating_sub(u32::from(v.data_fin));
                if len > 0 && !d.rx.install(mapping.ssn, dsn, len) {
                    d.reset = true;
                    return;
                }
                d.unmapped = 0;
            }
            if let Some(ack) = v.data_ack {
                let ack = match ack {
                    mptcp::DataAck::Ack32(x) => promote32(x, d.send.una),
                    mptcp::DataAck::Ack64(x) => x,
                };
                d.send.ack(ack);
            }
        }
    }

    fn delegates_data(&self) -> bool {
        self.data.is_some()
    }
    fn reset_requested(&self) -> bool {
        self.data.as_ref().is_some_and(|d| d.reset)
    }
    fn receipt_advanced(&mut self, ssn: u32) {
        if let Some(d) = &mut self.data {
            d.rx.ack(ssn);
        }
    }
    fn receive_data(
        &mut self,
        ssn: u32,
        tcp_ack: u32,
        bytes: &[u8],
    ) -> Vec<std::ops::Range<usize>> {
        let d = self.data.as_mut().unwrap();
        let mut accepted = Vec::new();
        let mut at = 0;
        while at < bytes.len() {
            let pos = ssn.wrapping_add(at as u32);
            if let Some((dsn, len)) = d.rx.translate(pos) {
                let len = len.min(bytes.len() - at);
                if at == 0
                    && (dsn.wrapping_add(len as u64).wrapping_sub(d.recv.next) as i64) > 0
                    && i64::from(ssn.wrapping_sub(tcp_ack) as i32)
                        > (dsn.wrapping_sub(d.recv.next) as i64)
                {
                    d.sanity_failures = d.sanity_failures.saturating_add(1);
                }
                let (_, n) = d.recv.accept(dsn, &bytes[at..at + len]);
                if n > 0 {
                    accepted.push(at..at + n);
                }
                at += len;
            } else {
                // Unmapped bytes are never retained, but count against the reset bound.
                let len = d.rx.unmapped_run(pos, bytes.len() - at);
                d.unmapped = d.unmapped.saturating_add(len);
                if d.unmapped > self.recv_cap {
                    d.reset = true;
                    return Vec::new();
                }
                accepted.push(at..at + len);
                at += len;
            }
        }
        accepted
    }

    fn accept_payload(&mut self, ssn: u32, data: &[u8]) {
        self.plain.accept_payload(ssn, data);
    }
    fn recv_window(&self) -> u32 {
        self.data
            .as_ref()
            .map_or_else(|| self.plain.recv_window(), |d| d.recv.free() as u32)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum State {
    SynSent,
    PreConfirmed,
    Confirmed,
    FellBack,
}

pub(crate) struct Negotiation {
    pub state: State,
    pub token: u32,
    local_key: u64,
    pub peer_idsn: Option<u64>,
    pub peer_key: Option<u64>,
    pub local_idsn: u64,
    pub send_right_edge: Option<u64>,
    syns_sent: u8,
    connected_pending: bool,
}

impl Negotiation {
    pub fn new(local_key: u64) -> Self {
        let (token, local_idsn) = key_token_idsn(local_key);
        Self {
            state: State::SynSent,
            token,
            local_key,
            local_idsn,
            send_right_edge: None,
            peer_idsn: None,
            peer_key: None,
            syns_sent: 0,
            connected_pending: false,
        }
    }

    fn on_valid_segment(&mut self, seg: &Segment<'_>) {
        if !self.connected_pending
            && self.state == State::PreConfirmed
            && seg.flags.contains(TcpFlags::ACK)
            && !seg.flags.contains(TcpFlags::RST)
        {
            let mut dss = false;
            for opt in walk(seg.options) {
                match opt {
                    Err(_) => return,
                    Ok(TcpOpt::Mptcp(raw)) => match mptcp::parse(raw) {
                        Ok(MptcpOption::Dss(_)) if !dss => dss = true,
                        Ok(MptcpOption::Dss(_)) | Err(_) => return,
                        _ => {}
                    },
                    _ => {}
                }
            }
            if dss {
                self.state = State::Confirmed;
            }
        }
        if !seg.flags.contains(TcpFlags::SYN | TcpFlags::ACK) || seg.flags.contains(TcpFlags::RST) {
            return;
        }
        self.connected_pending = true;
        if self.state != State::SynSent {
            return;
        }
        // Parse the whole list: a valid prefix cannot hide a malformed or duplicate MPC.
        let mut peer_key = None;
        for opt in walk(seg.options) {
            match opt {
                Err(_) => {
                    peer_key = None;
                    break;
                }
                Ok(TcpOpt::Mptcp(raw)) => match mptcp::parse(raw) {
                    Ok(MptcpOption::Capable(c))
                        if raw.len() == 12
                            && c.version == 1
                            && c.flags & !CAP_C == CAP_H
                            && peer_key.is_none() =>
                    {
                        peer_key = c.sender_key;
                    }
                    _ => {
                        peer_key = None;
                        break;
                    }
                },
                _ => {}
            }
        }
        self.peer_key = peer_key;
        self.peer_idsn = peer_key.map(|key| key_token_idsn(key).1);
        self.send_right_edge =
            peer_key.map(|_| self.local_idsn.wrapping_add(1 + u64::from(seg.wnd)));
        self.state = peer_key.map_or(State::FellBack, |_| State::PreConfirmed);
    }

    fn options_for(&mut self, flags: TcpFlags, out: &mut [u8]) -> usize {
        let keys = match self.state {
            State::SynSent if flags.contains(TcpFlags::SYN) => {
                if self.syns_sent == 3 {
                    self.state = State::FellBack;
                    return 0;
                }
                self.syns_sent += 1;
                (None, None)
            }
            State::PreConfirmed if flags.contains(TcpFlags::ACK) => {
                (Some(self.local_key), self.peer_key)
            }
            State::Confirmed if flags.contains(TcpFlags::ACK) => {
                return mptcp::encode(
                    &MptcpOption::Dss(mptcp::Dss {
                        data_fin: false,
                        data_ack: Some(mptcp::DataAck::Ack64(
                            self.peer_idsn.unwrap().wrapping_add(1),
                        )),
                        mapping: None,
                    }),
                    out,
                )
                .expect("DSS DATA_ACK fits TCP options");
            }
            _ => return 0,
        };
        mptcp::encode(
            &MptcpOption::Capable(MpCapable {
                version: 1,
                flags: CAP_H,
                sender_key: keys.0,
                receiver_key: keys.1,
                data_len: None,
                checksum: None,
            }),
            out,
        )
        .expect("MP_CAPABLE has a fixed layout fitting TCP options")
    }

    pub fn on_transmitted(&mut self, flags: TcpFlags) -> Option<bool> {
        if flags.contains(TcpFlags::ACK)
            && !flags.contains(TcpFlags::RST)
            && std::mem::take(&mut self.connected_pending)
        {
            Some(matches!(self.state, State::PreConfirmed | State::Confirmed))
        } else {
            None
        }
    }
}
