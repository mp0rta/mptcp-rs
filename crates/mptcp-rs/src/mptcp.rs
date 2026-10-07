//! Single-subflow MPTCP negotiation, data transfer, recovery and closure.
mod close;
pub(crate) mod data;
use crate::crypto::key_token_idsn;
use data::{RecvAssembler, RxMaps, SendStore, TxMaps, promote32};

use crate::tcp::{ConnectConfig, PlainHooks, SegmentHooks, SendBuf, Tcb};
use crate::time::Instant;
use crate::wire::packet::{Segment, TcpFlags};
use crate::wire::{
    mptcp::{self, CAP_C, CAP_H, MpCapable, MptcpOption},
    tcp_options::{TcpOpt, walk},
};
use std::time::Duration;

pub(crate) struct ConnectionHooks {
    plain: PlainHooks,
    pub negotiation: Option<Negotiation>,
    pub data: Option<DataState>,
    recv_cap: usize,
    send_cap: usize,
    // None: malformed/invalid; Some(false): valid options without DATA_ACK.
    // Current ACK coverage is retained after TCP releases a mapping.
    valid_data_ack: Option<bool>,
    pub fallback_event: bool,
    fast_closed: bool,
    ack_now: bool,
}

pub(crate) struct DataState {
    pub recv: RecvAssembler,
    close: close::Close,
    pub send: SendStore,
    pub tx: TxMaps,
    rx: RxMaps,
    unmapped: usize,
    reset: bool,
    pub sanity_failures: u64,
    recovery_head: Option<u64>,
    recovery_at: Option<Instant>,
    recovery_interval: Duration,
    reinject: bool,
    dss_confirmed: bool,
    fallback: bool,
    final_mapping: Option<mptcp::Mapping>,
    rx_infinite: Option<(u32, u64)>,
    tcp_acked_dsn: u64,
    local_isn: crate::SeqNum,
    tcp_acked_ssn: Option<u32>,
}

impl ConnectionHooks {
    pub fn new(cfg: &ConnectConfig) -> Self {
        Self {
            plain: PlainHooks::new(cfg),
            negotiation: None,
            data: None,
            recv_cap: cfg.recv_buffer as usize,
            send_cap: cfg.send_buffer as usize,
            valid_data_ack: None,
            fallback_event: false,
            fast_closed: false,
            ack_now: false,
        }
    }
    pub fn recovery_deadline(&self) -> Option<Instant> {
        self.data.as_ref().and_then(|d| {
            [d.recovery_at, d.close.at, d.close.no_subflow_at]
                .into_iter()
                .flatten()
                .min()
        })
    }
    pub fn update_recovery(&mut self, tcb: &Tcb, now: Instant) {
        let Some(d) = &mut self.data else {
            return;
        };
        if tcb.state() == crate::tcp::TcpState::Closed {
            return;
        }
        if !d.fallback
            && d.close.sent
            && !d.close.acked
            && !d.close.due
            && d.send.una == d.send.end
            && d.close.at.is_none()
        {
            d.close.interval = tcb.retransmission_timeout();
            d.close.at = Some(now + d.close.interval);
        }
        let head = (!d.fallback && d.send.una != d.send.next).then_some(d.send.una);
        if d.recovery_head != head {
            d.recovery_head = head;
            d.recovery_at = None;
            d.recovery_interval = tcb.retransmission_timeout();
            d.reinject = false;
        }
        if head.is_none() || d.tx.uncovered_len(d.send.una, 1) == 0 {
            d.recovery_at = None;
            d.reinject = false;
        } else if !d.reinject {
            let at = d.recovery_at.get_or_insert(now + d.recovery_interval);
            if now >= *at {
                d.reinject = true;
                d.recovery_at = None;
                d.recovery_interval = (d.recovery_interval * 2).min(Duration::from_secs(60));
            }
        }
    }
    pub fn prepare_send(&mut self, tcb: &mut Tcb, now: Instant) {
        self.update_recovery(tcb, now);
        if let Some(d) = self.data.as_mut().filter(|d| !d.fallback) {
            if d.close.acked {
                tcb.close();
            }
            // Bare TCP FIN retires this path, but DATA_FIN+FIN leaves it available
            // for our half-close response until our own DATA_FIN is acknowledged.
            if tcb.fin_received() && !d.recv.has_fin() {
                tcb.close();
            }
            if d.close.at.is_some_and(|at| now >= at) {
                d.close.at = None;
                d.close.due = true;
                d.close.interval = (d.close.interval * 2).min(Duration::from_secs(60));
            }
            if d.close.local.is_some()
                && d.send.next == d.send.end
                && !d.close.sent
                && !d.close.attached
            {
                d.close.due = true;
            }
            if d.close.due {
                tcb.request_ack();
            }
        }
        if std::mem::take(&mut self.ack_now) {
            tcb.request_ack();
        }
        if self
            .data
            .as_ref()
            .is_some_and(|d| d.final_mapping.is_some())
        {
            tcb.request_ack();
        }
        let demand = match (&self.negotiation, &self.data) {
            (Some(m), Some(d)) => {
                (d.send.next != d.send.end || d.reinject)
                    && (tcb.peer_window_closed()
                        || (!d.fallback
                            && m.send_right_edge
                                .is_some_and(|edge| edge.wrapping_sub(d.send.next) as i64 <= 0)))
            }
            _ => false,
        };
        tcb.set_probe_demand(demand);
        tcb.pending_send(
            now,
            self.unassigned_len(),
            self.candidate_len(),
            self.data_option_len(),
            self,
        );
    }
    pub fn assign(&mut self, tcb: &Tcb, now: Instant) -> bool {
        if tcb.state() != crate::tcp::TcpState::Established
            && !(tcb.state() == crate::tcp::TcpState::CloseWait
                && self
                    .data
                    .as_ref()
                    .is_some_and(|d| d.fallback || d.recv.has_fin()))
        {
            return false;
        }
        if let Some(d) = &self.data {
            if d.reinject {
                let head = d.send.una;
                let len =
                    d.tx.uncovered_len(head, d.send.run_len(head))
                        .min(d.send.next.wrapping_sub(head) as usize)
                        .min(u16::MAX as usize - usize::from(d.close.local.is_some()));
                let len = tcb
                    .send_budget(now, len, len, true, self.data_option_len(), self)
                    .bytes();
                let d = self.data.as_mut().unwrap();
                if d.send.assign(&mut d.tx, head, len) {
                    d.reinject = false;
                    if d.close.local == Some(head.wrapping_add(len as u64)) {
                        d.tx.attach_fin();
                        d.close.attached = true;
                    }
                    return true;
                }
                return false;
            }
        }
        let len = tcb
            .send_budget(
                now,
                self.unassigned_len(),
                self.candidate_len(),
                false,
                self.data_option_len(),
                self,
            )
            .bytes();
        if len == 0 {
            return false;
        }
        let d = self.data.as_mut().unwrap();
        if !d.send.assign(&mut d.tx, d.send.next, len) {
            return false;
        }
        if d.close.local == Some(d.send.next)
            && len < u16::MAX as usize
            && !(self.negotiation.as_ref().unwrap().state == State::PreConfirmed
                && d.tx.assigned_end().wrapping_sub(len as u32) == 1)
        {
            d.tx.attach_fin();
            d.close.attached = true;
        }
        true
    }
    fn candidate_len(&self) -> usize {
        self.data.as_ref().map_or(0, |d| {
            d.send
                .run_len(d.send.next)
                .min(self.unassigned_len())
                .min(u16::MAX as usize - usize::from(d.close.local.is_some()))
        })
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
    fn unassigned_len(&self) -> usize {
        match (&self.data, &self.negotiation) {
            (Some(d), Some(m)) => {
                (d.send.end.wrapping_sub(d.send.next) as usize).min(if d.fallback {
                    usize::MAX
                } else {
                    (m.send_right_edge.unwrap().wrapping_sub(d.send.next) as i64).max(0) as usize
                })
            }
            _ => 0,
        }
    }

    fn segment_limit(&self, ssn: u32) -> usize {
        self.data
            .as_ref()
            .map_or(usize::MAX, |d| d.tx.segment_limit(ssn))
    }
    fn is_reinjection(&self, ssn: u32) -> bool {
        self.data.as_ref().is_some_and(|d| d.tx.is_reinjection(ssn))
    }
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
            Some(d) => {
                if let Some(dsn) = d.tx.acked_dsn(ssn) {
                    d.tcp_acked_dsn = dsn;
                    d.tcp_acked_ssn = Some(ssn);
                    if !d.fallback && !d.dss_confirmed {
                        match self.valid_data_ack {
                            Some(true) => d.dss_confirmed = true,
                            Some(false) => {
                                d.fall_back(self.negotiation.as_mut().unwrap());
                                self.fallback_event = true;
                            }
                            None => {}
                        }
                    }
                }
                d.tx.mark_acked(ssn);
                if d.fallback {
                    d.send.ack(d.tcp_acked_dsn);
                }
            }
            None => self.plain.mark_acked(ssn),
        }
    }
}
impl SegmentHooks for ConnectionHooks {
    fn data_option_len(&self) -> usize {
        if self.data.as_ref().is_some_and(|d| !d.fallback) {
            28
        } else {
            0
        }
    }
    fn data_options_for(&mut self, ssn: u32, out: &mut [u8]) -> usize {
        let (Some(m), Some(d)) = (&self.negotiation, &self.data) else {
            return self.options_for(TcpFlags::ACK, out);
        };
        if d.fallback {
            return self.options_for(TcpFlags::ACK, out);
        }
        let mapping = d.tx.mapping(ssn).expect("payload has mapping");
        let data_fin = d.tx.data_fin(ssn);
        let option = if m.state == State::PreConfirmed && mapping.ssn == 1 {
            MptcpOption::Capable(MpCapable {
                version: 1,
                flags: CAP_H,
                sender_key: Some(m.local_key),
                receiver_key: m.peer_key,
                data_len: Some(mapping.data_len),
                checksum: None,
            })
        } else {
            MptcpOption::Dss(mptcp::Dss {
                data_fin,
                data_ack: Some(mptcp::DataAck::Ack64(d.recv.next)),
                mapping: Some(mapping),
            })
        };
        let n = mptcp::encode(&option, out).expect("fixed mapping layout fits");
        let padded = n.next_multiple_of(4);
        out[n..padded].fill(1);
        padded
    }
    fn window_offer(&self, scale: u8, mss: u16) -> Option<u16> {
        self.data.as_ref().map(|d| d.recv.window_offer(scale, mss))
    }
    fn window_sent(&mut self, field: u16, scale: u8) {
        if let Some(d) = &mut self.data {
            d.recv.window_sent(field, scale);
        }
    }
    fn window_update_due(&self, scale: u8, mss: u16) -> bool {
        self.data
            .as_ref()
            .is_some_and(|d| d.recv.window_update_due(scale, mss))
    }
    fn duplicate_ack_allowed(&self, seg: &Segment<'_>) -> bool {
        self.data.is_none() || !walk(seg.options).any(|o| matches!(o, Ok(TcpOpt::Mptcp(raw)) if !matches!(mptcp::parse(raw), Ok(MptcpOption::Dss(_)))))
    }

    fn options_for(&mut self, flags: TcpFlags, out: &mut [u8]) -> usize {
        if let (Some(m), Some(d)) = (&self.negotiation, &mut self.data) {
            if let Some(mapping) = d.final_mapping {
                let n = mptcp::encode(
                    &MptcpOption::Dss(mptcp::Dss {
                        data_fin: false,
                        data_ack: None,
                        mapping: Some(mapping),
                    }),
                    out,
                )
                .expect("infinite mapping fits");
                let padded = n.next_multiple_of(4);
                out[n..padded].fill(1);
                return padded;
            }
            if d.fallback {
                return 0;
            }
            if d.close.due && flags.contains(TcpFlags::ACK) {
                let n = mptcp::encode(
                    &MptcpOption::Dss(mptcp::Dss {
                        data_fin: true,
                        data_ack: Some(mptcp::DataAck::Ack64(d.recv.next)),
                        mapping: Some(mptcp::Mapping {
                            dsn: mptcp::Dsn::Dsn64(d.close.local.unwrap()),
                            ssn: 0,
                            data_len: 1,
                            checksum: None,
                        }),
                    }),
                    out,
                )
                .expect("DATA_FIN fits");
                let padded = n.next_multiple_of(4);
                out[n..padded].fill(1);
                return padded;
            }
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
        self.valid_data_ack = None;
        // Validate the whole option list before mutating mapping or DATA_ACK state.
        let (mut dss, mut capable, mut fastclose) = (None, None, None);
        for opt in walk(seg.options).filter(|_| !seg.flags.contains(TcpFlags::SYN)) {
            match opt {
                Err(_) => return,
                Ok(TcpOpt::Mptcp(raw)) => match mptcp::parse(raw) {
                    Ok(MptcpOption::Dss(v)) if dss.is_none() => dss = Some(v),
                    Ok(MptcpOption::Capable(v)) if capable.is_none() => capable = Some(v),
                    Ok(MptcpOption::FastClose { receiver_key }) if fastclose.is_none() => {
                        fastclose = Some(receiver_key)
                    }
                    Ok(
                        MptcpOption::Dss(_)
                        | MptcpOption::Capable(_)
                        | MptcpOption::FastClose { .. },
                    )
                    | Err(_) => return,
                    _ => {}
                },
                _ => {}
            }
        }
        self.valid_data_ack = if dss.is_some_and(|v| v.data_ack.is_some()) {
            None
        } else {
            Some(false)
        };
        let Some(m) = &mut self.negotiation else {
            return;
        };
        if fastclose == Some(m.local_key)
            && matches!(m.state, State::PreConfirmed | State::Confirmed)
            && (seg.flags.contains(TcpFlags::ACK) || seg.flags.contains(TcpFlags::RST))
        {
            self.fast_closed = true;
            return;
        }
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
                close: close::Close::default(),
                tx: TxMaps::new(1, 1024),
                rx: RxMaps::new(1024),
                unmapped: 0,
                reset: false,
                sanity_failures: 0,
                recovery_head: None,
                recovery_at: None,
                recovery_interval: Duration::from_secs(1),
                reinject: false,
                dss_confirmed: false,
                fallback: false,
                final_mapping: None,
                rx_infinite: None,
                tcp_acked_dsn: m.local_idsn.wrapping_add(1),
                local_isn: seg.ack.wrapping_add(u32::MAX),
                tcp_acked_ssn: None,
            });
        }
        if seg.flags.contains(TcpFlags::SYN) {
            if let Some(d) = &mut self.data {
                d.recv.right_edge = d.recv.next.wrapping_add(self.recv_cap.min(65535) as u64);
            }
        }
        if seg.flags.contains(TcpFlags::SYN) || seg.flags.contains(TcpFlags::RST) {
            return;
        }
        let Some(d) = &mut self.data else {
            return;
        };
        if d.fallback {
            return;
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
                if v.data_fin
                    && (mapping.data_len == 0
                        || (mapping.data_len == 1 && mapping.ssn != 0)
                        || (mapping.data_len > 1 && seg.payload.is_empty()))
                {
                    return;
                }
                if mapping.data_len == 0 {
                    d.fall_back(m);
                    d.rx_infinite = Some((mapping.ssn, dsn));
                    d.send.ack(d.tcp_acked_dsn);
                    self.fallback_event = true;
                    return;
                }
                let len = u32::from(mapping.data_len).saturating_sub(u32::from(v.data_fin));
                if len > 0 && !d.rx.install(mapping.ssn, dsn, len) {
                    d.reset = true;
                    return;
                }
                if v.data_fin && d.recv.finish(dsn.wrapping_add(u64::from(len))) {
                    self.ack_now = true;
                }
                d.unmapped = 0;
            }
            if let Some(ack) = v.data_ack {
                let ack = match ack {
                    mptcp::DataAck::Ack32(x) => promote32(x, d.send.una),
                    mptcp::DataAck::Ack64(x) => x,
                };
                let fin_ack =
                    d.close.sent && d.close.local.is_some_and(|fin| ack == fin.wrapping_add(1));
                if d.send
                    .ack(if fin_ack { d.close.local.unwrap() } else { ack })
                {
                    if fin_ack {
                        d.close.acked = true;
                        d.close.at = None;
                        d.close.due = false;
                    }
                    self.valid_data_ack = Some(true);
                    // A corrected DATA_ACK can arrive after TCP has released the mapping.
                    // Keep its ACK coverage independently of the live TxMaps entries;
                    // stale/SYN-only TCP ACKs cannot confirm the data path.
                    if d.tcp_acked_ssn
                        .is_some_and(|ssn| seg.ack.ge(d.local_isn.wrapping_add(ssn)))
                    {
                        d.dss_confirmed = true;
                    }
                    let edge = ack.wrapping_add(u64::from(seg.wnd) << m.peer_scale);
                    if m.send_right_edge
                        .is_none_or(|old| edge.wrapping_sub(old) as i64 > 0)
                    {
                        m.send_right_edge = Some(edge);
                    }
                }
            }
        }
        // A current duplicate TCP ACK still covers our data even when an earlier
        // malformed DATA_ACK let TCP release the live mapping without confirmation.
        if !d.dss_confirmed
            && self.valid_data_ack == Some(false)
            && d.tcp_acked_ssn
                .is_some_and(|ssn| seg.ack.ge(d.local_isn.wrapping_add(ssn)))
        {
            d.fall_back(m);
            d.send.ack(d.tcp_acked_dsn);
            self.fallback_event = true;
        }
    }

    fn requires_tcp_sequence_check(&self, seg: &Segment<'_>) -> bool {
        walk(seg.options).any(|opt| matches!(opt,
            Ok(TcpOpt::Mptcp(raw)) if matches!(mptcp::parse(raw), Ok(MptcpOption::FastClose { .. }))))
    }
    fn delegates_data(&self) -> bool {
        self.data.is_some()
    }
    fn reset_requested(&self) -> bool {
        self.fast_closed || self.data.as_ref().is_some_and(|d| d.reset)
    }
    fn receipt_advanced(&mut self, ssn: u32) {
        if let Some(d) = &mut self.data {
            if let Some((base, dsn)) = &mut d.rx_infinite {
                *dsn = dsn.wrapping_add_signed(ssn.wrapping_sub(*base) as i32 as i64);
                *base = ssn;
            }
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
            let translated = if d.fallback {
                d.rx_infinite.map(|(ssn, dsn)| {
                    (
                        dsn.wrapping_add_signed(pos.wrapping_sub(ssn) as i32 as i64),
                        bytes.len() - at,
                    )
                })
            } else {
                d.rx.translate(pos)
            };
            if let Some((dsn, len)) = translated {
                let len = len.min(bytes.len() - at);
                let dsn_offset = dsn.wrapping_sub(d.recv.next) as i64;
                if at == 0
                    && dsn_offset.saturating_add(len as i64) > 0
                    && i64::from(ssn.wrapping_sub(tcp_ack) as i32) > dsn_offset
                {
                    d.sanity_failures = d.sanity_failures.saturating_add(1);
                }
                let n = if d.fallback {
                    d.recv.accept_tcp(dsn, &bytes[at..at + len])
                } else {
                    d.recv.accept(dsn, &bytes[at..at + len]).1
                };
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

impl DataState {
    fn fall_back(&mut self, m: &mut Negotiation) {
        self.fallback = true;
        self.close = close::Close::default();
        m.state = State::FellBack;
        self.recovery_at = None;
        self.reinject = false;
        self.rx_infinite = Some((1, m.peer_idsn.unwrap().wrapping_add(1)));
        self.final_mapping = Some(mptcp::Mapping {
            dsn: mptcp::Dsn::Dsn64(m.local_idsn.wrapping_add(1)),
            ssn: 1,
            data_len: 0,
            checksum: None,
        });
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
    peer_scale: u8,
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
            peer_scale: 0,
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
        self.peer_scale = walk(seg.options)
            .filter_map(|o| match o {
                Ok(TcpOpt::WindowScale(s)) => Some(s.min(14)),
                _ => None,
            })
            .next()
            .unwrap_or(0);
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
