//! MP_JOIN subflow establishment (RFC 8684 §3.2, spec §5.6): the join options, the SYN/ACK
//! HMAC check and the third-ACK control item (spec §4 rule 2).
use std::time::Duration;

use super::SubflowHooks;
use crate::crypto::{join_hmac, key_token_idsn};
use crate::tcp::{CloseReason, Reaction, Tcb};
use crate::time::Instant;
use crate::wire::mptcp::{self, MpJoin, MptcpOption};
use crate::wire::packet::{Segment, TcpFlags};
use crate::wire::tcp_options::{TcpOpt, walk};

/// Control-queue retry cap (spec §3.1).
const MAX_INTERVAL: Duration = Duration::from_secs(60);

/// The MP_JOIN state of a joined subflow; kept once done (it marks the subflow as joined).
pub(crate) struct Join {
    /// Fixed for the attempt, SYN retransmissions included (RFC 8684 L2691–2692).
    pub local_nonce: u32,
    pub peer_nonce: Option<u32>,
    /// Our address ID for the subflow's local IP.
    pub addr_id: u8,
    /// The peer's address ID from its SYN/ACK (spec §5.6); read by address management (M3).
    #[cfg_attr(not(test), allow(dead_code))]
    pub peer_addr_id: Option<u8>,
    pub third_ack: ThirdAck,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ThirdAck {
    /// Not sent yet.
    NotYet,
    /// Sent since `since`; resent at `at` with a backed-off interval, given up at R2.
    Due {
        at: Instant,
        interval: Duration,
        since: Instant,
    },
    /// The peer acknowledged it (L1160–1162): the subflow is Active.
    Done,
}

impl Join {
    pub fn new(local_nonce: u32, addr_id: u8) -> Self {
        Self {
            local_nonce,
            peer_nonce: None,
            addr_id,
            peer_addr_id: None,
            third_ack: ThirdAck::NotYet,
        }
    }
    /// The subflow is still Joining: no data, every ACK carries the MP_JOIN ACK.
    pub fn joining(&self) -> bool {
        self.third_ack != ThirdAck::Done
    }
    /// The third-ACK item's next deadline: the resend, or the give-up at `since + r2`.
    pub fn deadline(&self, r2: Duration) -> Option<Instant> {
        match self.third_ack {
            ThirdAck::Due { at, since, .. } => Some(at.min(since + r2)),
            _ => None,
        }
    }
    /// Expiry of the third-ACK item: resend it, or reset the subflow at R2 (`cfg.r2_data`).
    pub fn on_timeout(&mut self, tcb: &mut Tcb, now: Instant, r2: Duration) -> Reaction {
        let ThirdAck::Due {
            at,
            interval,
            since,
        } = &mut self.third_ack
        else {
            return Reaction::None;
        };
        if now >= *since + r2 {
            return tcb.abort(CloseReason::Timeout, now);
        }
        if now >= *at {
            *interval = (*interval * 2).min(MAX_INTERVAL);
            *at = now + *interval;
            tcb.request_ack();
        }
        Reaction::None
    }
}

impl SubflowHooks<'_> {
    /// The MP_JOIN option while joining (`None` once done): SYN length 12, B=0; every ACK the
    /// subflow sends carries the third-ACK form (length 24, HMAC-A) and no DSS, so whichever
    /// ACK goes out first repairs a lost third ACK (RFC 8684 L1233–1234).
    pub(super) fn join_options(&self, flags: TcpFlags, out: &mut [u8]) -> Option<usize> {
        let j = self.sf.join.as_ref().filter(|j| j.joining())?;
        let m = self.conn.negotiation.as_ref()?;
        let peer_key = m.peer_key?;
        let option = if flags.contains(TcpFlags::SYN) {
            MpJoin::Syn {
                backup: false,
                addr_id: j.addr_id,
                token: key_token_idsn(peer_key).0,
                nonce: j.local_nonce,
            }
        } else if let Some(peer_nonce) = j
            .peer_nonce
            .filter(|_| flags.contains(TcpFlags::ACK) && !flags.contains(TcpFlags::RST))
        {
            let hmac = join_hmac(m.local_key, peer_key, j.local_nonce, peer_nonce);
            MpJoin::Ack {
                hmac160: hmac[..20].try_into().unwrap(),
            }
        } else {
            return Some(0);
        };
        Some(mptcp::encode(&MptcpOption::Join(option), out).expect("MP_JOIN fits TCP options"))
    }

    /// A TCP-valid segment on a joined subflow. The SYN/ACK must carry exactly one MP_JOIN
    /// whose HMAC-B matches (L1146–1148, L1241–1252), else the subflow is reset; the first
    /// acceptable ACK after our third ACK completes the join.
    pub(super) fn join_segment(&mut self, seg: &Segment<'_>) {
        let Some(j) = &mut self.sf.join else {
            return;
        };
        if !seg.flags.contains(TcpFlags::SYN) {
            if seg.flags.contains(TcpFlags::ACK)
                && !seg.flags.contains(TcpFlags::RST)
                && matches!(j.third_ack, ThirdAck::Due { .. })
            {
                j.third_ack = ThirdAck::Done;
            }
            return;
        }
        let m = self.conn.negotiation.as_ref().unwrap();
        let (mut synack, mut valid) = (None, true);
        for opt in walk(seg.options) {
            match opt {
                Ok(TcpOpt::Mptcp(raw)) => match mptcp::parse(raw) {
                    Ok(MptcpOption::Join(MpJoin::SynAck {
                        addr_id,
                        hmac64,
                        nonce,
                        ..
                    })) if synack.is_none() => synack = Some((addr_id, hmac64, nonce)),
                    _ => valid = false,
                },
                Ok(TcpOpt::WindowScale(s)) => self.sf.peer_scale = s.min(14),
                Ok(_) => {}
                Err(_) => valid = false,
            }
        }
        let expected = |nonce| {
            let mac = join_hmac(m.peer_key.unwrap(), m.local_key, nonce, j.local_nonce);
            u64::from_be_bytes(mac[..8].try_into().unwrap())
        };
        match synack.filter(|_| valid) {
            Some((addr_id, hmac64, nonce)) if hmac64 == expected(nonce) => {
                j.peer_nonce = Some(nonce);
                j.peer_addr_id = Some(addr_id);
            }
            _ => self.sf.reset = true,
        }
    }

    /// The MP_JOIN SYN went out (`joined_ever`), or the third ACK: its control item starts
    /// (RTO, then backed off).
    pub(super) fn join_transmitted(&mut self, flags: TcpFlags, now: Instant, rto: Duration) {
        if let Some(j) = &mut self.sf.join {
            self.conn.joined_ever |= flags.contains(TcpFlags::SYN);
            if j.peer_nonce.is_some()
                && j.third_ack == ThirdAck::NotYet
                && flags.contains(TcpFlags::ACK)
                && !flags.contains(TcpFlags::SYN)
                && !flags.contains(TcpFlags::RST)
            {
                j.third_ack = ThirdAck::Due {
                    at: now + rto,
                    interval: rto,
                    since: now,
                };
            }
        }
    }
}
