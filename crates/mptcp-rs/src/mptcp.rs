//! M1 negotiation foundation. Temporarily test-gated until the DSS data path is integrated.
//!
//! Step 2 replaces plain payload buffering and supplies data-mapping option plans. Before
//! Step 6 enables public MPTCP, remove the staging gates in lib, connection, endpoint and Tcb;
//! use this same negotiation logic in production (no separate test implementation).
use crate::crypto::key_token_idsn;
use std::ops::{Deref, DerefMut};

use crate::tcp::{ConnectConfig, PlainHooks, SegmentHooks, SendBuf};
use crate::wire::packet::{Segment, TcpFlags};
use crate::wire::{
    mptcp::{self, CAP_C, CAP_H, MpCapable, MptcpOption},
    tcp_options::{TcpOpt, walk},
};

pub(crate) struct ConnectionHooks {
    plain: PlainHooks,
    pub negotiation: Option<Negotiation>,
}

impl ConnectionHooks {
    pub fn new(cfg: &ConnectConfig) -> Self {
        Self {
            plain: PlainHooks::new(cfg),
            negotiation: None,
        }
    }
}
impl Deref for ConnectionHooks {
    type Target = PlainHooks;
    fn deref(&self) -> &PlainHooks {
        &self.plain
    }
}
impl DerefMut for ConnectionHooks {
    fn deref_mut(&mut self) -> &mut PlainHooks {
        &mut self.plain
    }
}
impl SendBuf for ConnectionHooks {
    fn peek_with<R>(&self, ssn: u32, max: usize, f: impl FnOnce(&[u8]) -> R) -> Option<R> {
        self.plain.peek_with(ssn, max, f)
    }
    fn assigned_end(&self) -> u32 {
        self.plain.assigned_end()
    }
    fn mark_acked(&mut self, ssn: u32) {
        self.plain.mark_acked(ssn);
    }
}
impl SegmentHooks for ConnectionHooks {
    fn options_for(&mut self, flags: TcpFlags, out: &mut [u8]) -> usize {
        self.negotiation
            .as_mut()
            .map_or(0, |m| m.options_for(flags, out))
    }
    fn on_valid_segment(&mut self, seg: &Segment<'_>) {
        if let Some(m) = &mut self.negotiation {
            m.on_valid_segment(seg);
        }
    }

    fn accept_payload(&mut self, ssn: u32, data: &[u8]) {
        self.plain.accept_payload(ssn, data);
    }
    fn recv_window(&self) -> u32 {
        self.plain.recv_window()
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
