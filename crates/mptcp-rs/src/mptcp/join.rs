//! MP_JOIN subflow establishment (RFC 8684 §3.2, spec §5.6): the join options, the SYN/ACK
//! HMAC check and the third-ACK control item (spec §4 rule 2) of the initiator, and the
//! responder's SYN/ACK and third-ACK check (M4a spec G3). The role is per subflow (G3a).
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
    pub role: JoinRole,
    /// Fixed for the attempt, SYN retransmissions included (RFC 8684 L2691–2692).
    pub local_nonce: u32,
    pub peer_nonce: Option<u32>,
    /// Our address ID for the subflow's local IP.
    pub addr_id: u8,
    /// Our SYN's (initiator) or SYN/ACK's (responder) B bit: our advertised receive
    /// preference (M3 spec §3.6).
    pub backup: bool,
    /// The peer's address ID from its SYN/ACK or SYN (spec §5.6).
    pub peer_addr_id: Option<u8>,
    /// The responder's is `NotYet` until the third ACK is verified, then `Done`.
    pub third_ack: ThirdAck,
}

/// Which side of the MP_JOIN handshake we are (RFC 8684 L1181–1187: it picks the HMAC
/// direction).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum JoinRole {
    /// We sent the SYN (`Endpoint::add_subflow`).
    Initiator,
    /// A listener answered the peer's SYN.
    Responder,
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
    pub fn new(local_nonce: u32, addr_id: u8, backup: bool) -> Self {
        Self {
            role: JoinRole::Initiator,
            local_nonce,
            peer_nonce: None,
            addr_id,
            backup,
            peer_addr_id: None,
            third_ack: ThirdAck::NotYet,
        }
    }
    /// Answers the peer's MP_JOIN SYN, which carried `peer_nonce` and `peer_addr_id`.
    pub fn responder(
        local_nonce: u32,
        addr_id: u8,
        peer_nonce: u32,
        peer_addr_id: u8,
        backup: bool,
    ) -> Self {
        Self {
            role: JoinRole::Responder,
            peer_nonce: Some(peer_nonce),
            peer_addr_id: Some(peer_addr_id),
            ..Self::new(local_nonce, addr_id, backup)
        }
    }
    /// The subflow is still Joining: no data; every ACK of an initiator carries the MP_JOIN
    /// ACK.
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
            return tcb.abort_with(CloseReason::Timeout, Some(super::tcprst(0x00, true)), now);
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
    /// The MP_JOIN option while joining (`None` once done): SYN length 12 with our B bit; every
    /// ACK the subflow sends carries the third-ACK form (length 24, HMAC-A) and no DSS, so
    /// whichever ACK goes out first repairs a lost third ACK (RFC 8684 L1233–1234). A
    /// responder's SYN/ACK carries HMAC-B truncated to 64 bits and our nonce (L1110–1114,
    /// L1181–1187), and nothing else it sends while joining carries an MPTCP option.
    pub(super) fn join_options(&self, flags: TcpFlags, out: &mut [u8]) -> Option<usize> {
        let j = self.sf.join.as_ref().filter(|j| j.joining())?;
        let m = self.conn.negotiation.as_ref()?;
        let peer_key = m.peer_key?;
        let option = if j.role == JoinRole::Responder {
            if flags != TcpFlags::SYN | TcpFlags::ACK {
                return Some(0);
            }
            let peer_nonce = j.peer_nonce.unwrap();
            let mac = join_hmac(m.local_key, peer_key, j.local_nonce, peer_nonce);
            MpJoin::SynAck {
                backup: j.backup,
                addr_id: j.addr_id,
                hmac64: u64::from_be_bytes(mac[..8].try_into().unwrap()),
                nonce: j.local_nonce,
            }
        } else if flags.contains(TcpFlags::SYN) {
            MpJoin::Syn {
                backup: j.backup,
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
        if j.role == JoinRole::Responder {
            // A retransmitted third ACK: the fourth ACK was lost, so answer again (L1155–1159).
            if join_ack(seg).is_some() {
                self.sf.ack_now = true;
            }
            return;
        }
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
                        backup,
                        addr_id,
                        hmac64,
                        nonce,
                    })) if synack.is_none() => synack = Some((backup, addr_id, hmac64, nonce)),
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
            Some((backup, addr_id, hmac64, nonce)) if hmac64 == expected(nonce) => {
                j.peer_nonce = Some(nonce);
                j.peer_addr_id = Some(addr_id);
                // The peer's initial request (M3 spec §3.3); MP_PRIO changes it.
                self.sf.peer_backup = backup;
            }
            _ => {
                self.sf.reset = true;
                self.sf.reset_option = Some(super::tcprst(0x01, false));
                self.sf.join_failed = Some(None);
            }
        }
    }

    /// The responder's first segment after its SYN/ACK, the third ACK (`options_ok`: its
    /// option list passed `on_valid_segment`'s check): exactly one MP_JOIN ACK whose HMAC-A
    /// matches completes the join, and is acknowledged at once (L1155–1159). A wrong HMAC or
    /// no MP_JOIN resets this subflow only, with "Unspecified MPTCP error" (L1228–1234).
    pub(super) fn join_third_ack(&mut self, seg: &Segment<'_>, options_ok: bool) {
        if seg.flags.contains(TcpFlags::RST) {
            return;
        }
        let j = self.sf.join.as_mut().unwrap();
        let m = self.conn.negotiation.as_ref().unwrap();
        let joins = walk(seg.options)
            .filter(|o| matches!(o, Ok(TcpOpt::Mptcp(raw)) if mptcp::is_join(raw)));
        let peer_nonce = j.peer_nonce.unwrap();
        let mac = join_hmac(m.peer_key.unwrap(), m.local_key, peer_nonce, j.local_nonce);
        if options_ok && joins.count() == 1 && join_ack(seg) == Some(mac[..20].try_into().unwrap())
        {
            j.third_ack = ThirdAck::Done;
            self.sf.ack_now = true;
        } else {
            self.sf.reset = true;
            self.sf.reset_option = Some(super::tcprst(0x01, false));
        }
    }

    /// The MP_JOIN SYN or SYN/ACK went out (`joined_ever`), or the initiator's third ACK: its
    /// control item starts (RTO, then backed off).
    pub(super) fn join_transmitted(&mut self, flags: TcpFlags, now: Instant, rto: Duration) {
        if let Some(j) = &mut self.sf.join {
            self.conn.joined_ever |= flags.contains(TcpFlags::SYN);
            if j.role == JoinRole::Initiator
                && j.peer_nonce.is_some()
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

/// The HMAC of the first MP_JOIN ACK option (length 24) of a non-SYN `seg`.
fn join_ack(seg: &Segment<'_>) -> Option<[u8; 20]> {
    if seg.flags.contains(TcpFlags::SYN) {
        return None;
    }
    walk(seg.options).find_map(|o| match o {
        Ok(TcpOpt::Mptcp(raw)) => match mptcp::parse(raw) {
            Ok(MptcpOption::Join(MpJoin::Ack { hmac160 })) => Some(hmac160),
            _ => None,
        },
        _ => None,
    })
}
