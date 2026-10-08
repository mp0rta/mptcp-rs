use super::*;
use crate::tcp::cc::{CongestionEvent, RecoveryAck, Reno, Unbounded};
use crate::tcp::{PlainHooks, SegmentHooks, SendBuf};
use std::sync::{Arc, Mutex};

const ISN: SeqNum = SeqNum(0x1000);
const PEER_ISN: SeqNum = SeqNum(0xFFFF_FFF0);
/// Peer MSS in the send-path tests.
const MSS: u16 = 1000;

fn v4() -> (SocketAddr, SocketAddr) {
    (
        "10.0.0.1:50000".parse().unwrap(),
        "10.0.0.2:80".parse().unwrap(),
    )
}
fn v6() -> (SocketAddr, SocketAddr) {
    (
        "[fd00::1]:50000".parse().unwrap(),
        "[fd00::2]:80".parse().unwrap(),
    )
}
fn t(secs: u64) -> Instant {
    Instant::from_nanos(1_000_000_000) + Duration::from_secs(secs)
}
fn tm(ms: u64) -> Instant {
    t(0) + Duration::from_millis(ms)
}
/// Sequence number of data octet `n` (0-based).
fn data(n: u32) -> SeqNum {
    ISN.wrapping_add(1 + n)
}
fn pattern(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i % 251) as u8).collect()
}

struct Fixture<H = PlainHooks> {
    tcb: Tcb,
    h: H,
    out: SegmentWriter,
    addrs: (SocketAddr, SocketAddr),
}

impl Fixture {
    fn new(cfg: ConnectConfig, addrs: (SocketAddr, SocketAddr)) -> Self {
        Self {
            tcb: Tcb::new_active(&cfg, addrs.0, addrs.1, ISN, t(0)),
            h: PlainHooks::new(&cfg),
            out: SegmentWriter::default(),
            addrs,
        }
    }
    /// IPv4, `cc::Unbounded` passed explicitly (send-path tests must not depend on the
    /// default CC).
    fn unbounded(cfg: ConnectConfig) -> Self {
        let h = PlainHooks::new(&cfg);
        Fixture::with(cfg, Box::new(Unbounded), h)
    }
    /// ESTABLISHED at t(0): eff_mss = MSS, peer shift 0, peer window `wnd`, handshake ACK
    /// already sent.
    fn established(cfg: ConnectConfig, wnd: u16) -> Self {
        let mut f = Fixture::unbounded(cfg);
        f.establish(wnd);
        f
    }
    fn write(&mut self, data: &[u8]) {
        assert_eq!(self.h.write(data), data.len());
    }
}

impl<H: Hooks> Fixture<H> {
    fn with(cfg: ConnectConfig, cc: Box<dyn CongestionControl>, h: H) -> Self {
        let addrs = v4();
        Self {
            tcb: Tcb::with_cc(&cfg, addrs.0, addrs.1, ISN, t(0), cc),
            h,
            out: SegmentWriter::default(),
            addrs,
        }
    }
    fn establish(&mut self, wnd: u16) {
        assert_eq!(
            self.synack(wnd, &opts(Some(MSS), Some(0))),
            Reaction::Established
        );
        assert_eq!(self.send(t(0)).unwrap().flags, TcpFlags::ACK);
        assert_eq!(self.send(t(0)), None);
    }
    /// An ACK-only segment from the peer.
    fn ack_seq(&mut self, now: Instant, seq: SeqNum, ack: SeqNum, wnd: u16) -> Reaction {
        let seg = Segment {
            src: self.addrs.1,
            dst: self.addrs.0,
            seq,
            ack,
            flags: TcpFlags::ACK,
            wnd,
            options: &[],
            payload: &[],
        };
        self.tcb.on_segment(&seg, now, &mut self.h)
    }
    fn ack(&mut self, now: Instant, ack: SeqNum, wnd: u16) -> Reaction {
        self.ack_seq(now, PEER_ISN.wrapping_add(1), ack, wnd)
    }
    /// Every segment `poll_send` emits at `now`, with its payload.
    fn drain(&mut self, now: Instant) -> Vec<(SentMeta, Vec<u8>)> {
        let mut v = Vec::new();
        while let Some(m) = self.send(now) {
            v.push((m, self.out.payload.clone()));
            assert!(v.len() < 1000, "poll_send does not stop");
        }
        v
    }
    /// Fires every deadline until `Closed`; returns the send times and the close time.
    fn run_until_closed(&mut self) -> (Vec<Instant>, Instant) {
        let mut sends = Vec::new();
        loop {
            let at = self.tcb.poll_send_at().expect("a deadline");
            match self.timeout(at) {
                Reaction::None => {}
                Reaction::Closed(CloseReason::Timeout) => return (sends, at),
                r => panic!("unexpected {r:?}"),
            }
            let segs = self.drain(at);
            assert_eq!(segs.len(), 1, "one segment per expiry at {at:?}");
            sends.push(at);
        }
    }
    fn send(&mut self, now: Instant) -> Option<SentMeta> {
        self.tcb.poll_send(now, &mut self.h, &mut self.out)
    }
    fn timeout(&mut self, now: Instant) -> Reaction {
        self.tcb.on_timeout(now, &mut self.h)
    }
    fn recv(&mut self, flags: TcpFlags, ack: SeqNum, wnd: u16, opts: &[u8]) -> Reaction {
        let seg = Segment {
            src: self.addrs.1,
            dst: self.addrs.0,
            seq: PEER_ISN,
            ack,
            flags,
            wnd,
            options: opts,
            payload: &[],
        };
        self.tcb.on_segment(&seg, t(0), &mut self.h)
    }
    /// SYN sent at t(0), then a SYN/ACK acknowledging it.
    fn synack(&mut self, wnd: u16, opts: &[u8]) -> Reaction {
        self.send(t(0)).unwrap();
        self.recv(
            TcpFlags::SYN | TcpFlags::ACK,
            ISN.wrapping_add(1),
            wnd,
            opts,
        )
    }
}

fn opts(mss: Option<u16>, ws: Option<u8>) -> Vec<u8> {
    let mut b = [0u8; 8];
    let mut n = 0;
    if let Some(m) = mss {
        n += tcp_options::write_mss(&mut b[n..], m);
    }
    if let Some(s) = ws {
        n += tcp_options::write_ws(&mut b[n..], s);
    }
    b[..n].to_vec()
}

fn parsed(raw: &[u8]) -> Vec<TcpOpt<'_>> {
    tcp_options::walk(raw).map(Result::unwrap).collect()
}

#[test]
fn syn_carries_mss_and_ws() {
    for (addrs, mss) in [(v4(), 1460), (v6(), 1440)] {
        let mut f = Fixture::new(ConnectConfig::default(), addrs);
        assert_eq!(f.tcb.state(), TcpState::SynSent);
        let meta = f.send(t(0)).unwrap();
        assert_eq!(
            meta,
            SentMeta {
                seq: ISN,
                len: 0,
                flags: TcpFlags::SYN
            }
        );
        assert_eq!(f.out.seq, ISN);
        assert_eq!(f.out.flags, TcpFlags::SYN);
        assert_eq!(f.out.wnd, 65535);
        assert!(f.out.payload.is_empty());
        // Receive-side SACK is offered; timestamps remain unused.
        assert_eq!(
            parsed(f.out.options()),
            vec![
                TcpOpt::Mss(mss),
                TcpOpt::WindowScale(7),
                TcpOpt::SackPermitted
            ]
        );
        assert_eq!(f.send(t(0)), None);
    }
}

#[test]
fn syn_window_is_buffer_when_small() {
    let cfg = ConnectConfig {
        recv_buffer: 1000,
        ..ConnectConfig::default()
    };
    let mut f = Fixture::new(cfg, v4());
    f.send(t(0)).unwrap();
    assert_eq!(f.out.wnd, 1000);
    assert_eq!(
        parsed(f.out.options()),
        vec![
            TcpOpt::Mss(1460),
            TcpOpt::WindowScale(0),
            TcpOpt::SackPermitted
        ]
    );
}

#[test]
fn synack_establishes_and_acks() {
    let mut f = Fixture::new(ConnectConfig::default(), v4());
    assert_eq!(
        f.synack(5000, &opts(Some(1400), Some(8))),
        Reaction::Established
    );
    assert_eq!(f.tcb.state(), TcpState::Established);
    assert_eq!(f.tcb.eff_mss, 1400);
    let meta = f.send(t(0)).unwrap();
    assert_eq!(meta.flags, TcpFlags::ACK);
    assert_eq!(meta.len, 0);
    assert_eq!(f.out.seq, ISN.wrapping_add(1));
    assert_eq!(f.out.ack, PEER_ISN.wrapping_add(1));
    // 4 MiB receive buffer advertised with our shift 7.
    assert_eq!(f.out.wnd, 32768);
    assert!(f.out.options().is_empty());
    assert_eq!(f.send(t(0)), None);
    // Timers stop once established.
    assert_eq!(f.tcb.poll_send_at(), None);
}

#[test]
fn eff_mss_rules() {
    for (addrs, absent, cap) in [(v4(), 536, 1460), (v6(), 1220, 1440)] {
        for (peer, want) in [(None, absent), (Some(64), 64), (Some(9000), cap)] {
            let mut f = Fixture::new(ConnectConfig::default(), addrs);
            assert_eq!(f.synack(5000, &opts(peer, Some(7))), Reaction::Established);
            assert_eq!(f.tcb.eff_mss, want, "{addrs:?} peer {peer:?}");
        }
    }
}

#[test]
fn malformed_peer_mss_treated_as_absent() {
    let mut f = Fixture::new(ConnectConfig::default(), v4());
    // MSS kind with length 3: the walker reports it as Unknown.
    assert_eq!(f.synack(5000, &[2, 3, 5, 0]), Reaction::Established);
    assert_eq!(f.tcb.eff_mss, 536);
}

#[test]
fn peer_ws_above_14_clamped() {
    let mut f = Fixture::new(ConnectConfig::default(), v4());
    assert_eq!(
        f.synack(5000, &opts(Some(1460), Some(15))),
        Reaction::Established
    );
    assert_eq!(f.tcb.snd_shift, 14);
    assert_eq!(f.tcb.rcv_shift, 7);
}

#[test]
fn synack_window_taken_unscaled() {
    let mut f = Fixture::new(ConnectConfig::default(), v4());
    assert_eq!(
        f.synack(1000, &opts(Some(1460), Some(8))),
        Reaction::Established
    );
    assert_eq!(f.tcb.snd_shift, 8);
    assert_eq!(f.tcb.snd_wnd, 1000);
}

/// Drives a SYN that is never answered; returns the SYN send times (s after t(0)) and the
/// time of `Closed(Timeout)`.
fn run_unanswered(cfg: ConnectConfig) -> (Vec<u64>, u64, Fixture) {
    let mut f = Fixture::new(cfg, v4());
    let mut sends = Vec::new();
    assert!(f.send(t(0)).is_some());
    loop {
        let at = f.tcb.poll_send_at().expect("a deadline while SYN-SENT");
        let secs = (at - t(0)).as_secs();
        assert_eq!(at, t(secs), "deadlines are whole seconds here");
        match f.timeout(at) {
            Reaction::None => {}
            Reaction::Closed(CloseReason::Timeout) => return (sends, secs, f),
            r => panic!("unexpected {r:?}"),
        }
        let meta = f.send(at).expect("SYN retransmitted after RTO");
        assert_eq!(meta.flags, TcpFlags::SYN);
        assert_eq!(f.out.seq, ISN);
        sends.push(secs);
        assert_eq!(f.send(at), None);
    }
}

#[test]
fn syn_retransmits_with_backoff_until_r2() {
    let (sends, closed, mut f) = run_unanswered(ConnectConfig::default());
    // RTO 1, 2, 4, ... 32, then capped at 60 s.
    assert_eq!(sends, vec![1, 3, 7, 15, 31, 63, 123]);
    assert_eq!(closed, 180);
    assert_eq!(f.tcb.state(), TcpState::Closed);
    assert_eq!(f.tcb.poll_send_at(), Some(t(180)));
    // Exactly once.
    assert_eq!(f.timeout(t(500)), Reaction::None);
    assert_eq!(f.send(t(500)), None);
    assert_eq!(f.tcb.poll_send_at(), Some(t(180)));
}

#[test]
fn early_timeout_call_does_not_retransmit() {
    let mut f = Fixture::new(ConnectConfig::default(), v4());
    f.send(t(0)).unwrap();
    assert_eq!(f.tcb.poll_send_at(), Some(t(1)));
    assert_eq!(f.timeout(t(0) + Duration::from_millis(999)), Reaction::None);
    assert_eq!(f.send(t(0) + Duration::from_millis(999)), None);
}

#[test]
fn r2_syn_clamped_to_180s() {
    let cfg = ConnectConfig {
        r2_syn: Duration::from_secs(10),
        ..ConnectConfig::default()
    };
    let (sends, closed, _) = run_unanswered(cfg);
    assert_eq!(sends, vec![1, 3, 7, 15, 31, 63, 123]);
    assert_eq!(closed, 180);
    // A longer R2 is honoured.
    let cfg = ConnectConfig {
        r2_syn: Duration::from_secs(200),
        ..ConnectConfig::default()
    };
    let (sends, closed, _) = run_unanswered(cfg);
    assert_eq!(sends, vec![1, 3, 7, 15, 31, 63, 123, 183]);
    assert_eq!(closed, 200);
}

#[test]
fn rst_in_syn_sent_with_acceptable_ack_resets() {
    let rst_ack = TcpFlags::RST | TcpFlags::ACK;
    let mut f = Fixture::new(ConnectConfig::default(), v4());
    f.send(t(0)).unwrap();
    // Wrong ACK (not our SYN), or no ACK at all: dropped, no reply.
    assert_eq!(f.recv(rst_ack, ISN, 0, &[]), Reaction::None);
    assert_eq!(f.recv(rst_ack, ISN.wrapping_add(2), 0, &[]), Reaction::None);
    assert_eq!(f.recv(TcpFlags::RST, SeqNum(0), 0, &[]), Reaction::None);
    assert_eq!(f.tcb.state(), TcpState::SynSent);
    assert_eq!(f.send(t(0)), None);

    assert_eq!(
        f.recv(rst_ack, ISN.wrapping_add(1), 0, &[]),
        Reaction::Closed(CloseReason::Reset)
    );
    assert_eq!(f.tcb.state(), TcpState::Closed);
    assert_eq!(f.tcb.poll_send_at(), Some(t(0)));
    // Exactly once.
    assert_eq!(f.recv(rst_ack, ISN.wrapping_add(1), 0, &[]), Reaction::None);
    assert_eq!(f.timeout(t(500)), Reaction::None);
    assert_eq!(f.send(t(0)), None);
}

#[test]
fn unacceptable_ack_in_syn_sent_answered_with_rst() {
    let mut f = Fixture::new(ConnectConfig::default(), v4());
    f.send(t(0)).unwrap();
    let bad = ISN.wrapping_add(5);
    assert_eq!(
        f.recv(TcpFlags::SYN | TcpFlags::ACK, bad, 5000, &[]),
        Reaction::None
    );
    assert_eq!(f.tcb.state(), TcpState::SynSent);
    let meta = f.send(t(0)).unwrap();
    assert_eq!(meta.flags, TcpFlags::RST);
    assert_eq!(f.out.seq, bad);
    assert!(f.out.options().is_empty());
    assert_eq!(f.send(t(0)), None);
    // The SYN timer still runs.
    assert_eq!(f.tcb.poll_send_at(), Some(t(1)));
}

#[test]
fn segment_without_ack_ignored_in_syn_sent() {
    let mut f = Fixture::new(ConnectConfig::default(), v4());
    f.send(t(0)).unwrap();
    // A bare SYN (simultaneous open) is not supported by this client; dropped.
    assert_eq!(f.recv(TcpFlags::SYN, SeqNum(0), 5000, &[]), Reaction::None);
    // ACK without SYN: dropped (RFC 9293 §3.10.7.3 fifth step).
    assert_eq!(
        f.recv(TcpFlags::ACK, ISN.wrapping_add(1), 5000, &[]),
        Reaction::None
    );
    assert_eq!(f.tcb.state(), TcpState::SynSent);
    assert_eq!(f.send(t(0)), None);
}

#[test]
fn synack_after_rto_fired_sends_only_ack() {
    let mut f = Fixture::new(ConnectConfig::default(), v4());
    f.send(t(0)).unwrap();
    // The SYN RTO fires, then the SYN/ACK arrives before the retransmission is polled.
    assert_eq!(f.timeout(t(1)), Reaction::None);
    assert_eq!(
        f.recv(
            TcpFlags::SYN | TcpFlags::ACK,
            ISN.wrapping_add(1),
            5000,
            &opts(Some(1460), Some(7))
        ),
        Reaction::Established
    );
    let meta = f.send(t(1)).unwrap();
    assert_eq!(meta.flags, TcpFlags::ACK);
    assert_eq!(f.out.seq, ISN.wrapping_add(1));
    assert_eq!(f.send(t(1)), None);
    assert_eq!(f.tcb.snd_nxt, ISN.wrapping_add(1));
    assert_eq!(f.tcb.rto_at, None);
    assert_eq!(f.tcb.poll_send_at(), None);
}

#[test]
fn synack_without_ws_disables_scaling_both_ways() {
    for addrs in [v4(), v6()] {
        let mut f = Fixture::new(ConnectConfig::default(), addrs);
        assert_eq!(
            f.synack(5000, &opts(Some(1460), None)),
            Reaction::Established
        );
        assert_eq!((f.tcb.snd_shift, f.tcb.rcv_shift), (0, 0));
        assert_eq!(f.tcb.snd_wnd, 5000);
        f.send(t(0)).unwrap();
        // 4 MiB free, unscaled: capped at 65535.
        assert_eq!(f.out.wnd, 65535);
    }
}

// ---- Send path (Task 7) ----

const PSH_ACK: TcpFlags = TcpFlags(TcpFlags::PSH.0 | TcpFlags::ACK.0);

#[test]
fn sends_full_segments_up_to_window() {
    let mut f = Fixture::established(ConnectConfig::default(), 10 * MSS);
    let bytes = pattern(25 * MSS as usize);
    f.write(&bytes);
    let segs = f.drain(t(0));
    assert_eq!(segs.len(), 10);
    for (i, (meta, payload)) in segs.iter().enumerate() {
        let off = i * MSS as usize;
        assert_eq!(meta.seq, data(off as u32));
        assert_eq!(meta.len, u32::from(MSS));
        assert_eq!(meta.flags, TcpFlags::ACK, "segment {i}: no PSH");
        assert_eq!(payload[..], bytes[off..off + MSS as usize]);
    }
    assert_eq!(f.out.ack, PEER_ISN.wrapping_add(1));
    // Window full, data in flight: only the RTO is pending.
    assert_eq!(f.tcb.poll_send_at(), Some(t(1)));
}

#[test]
fn psh_on_last_segment_of_written_data() {
    let mut f = Fixture::established(ConnectConfig::default(), 10 * MSS);
    f.tcb.set_nodelay(true);
    f.write(&pattern(3 * MSS as usize / 2));
    let segs = f.drain(t(0));
    let got: Vec<_> = segs.iter().map(|(m, _)| (m.seq, m.len, m.flags)).collect();
    assert_eq!(
        got,
        vec![
            (data(0), u32::from(MSS), TcpFlags::ACK),
            (data(u32::from(MSS)), u32::from(MSS) / 2, PSH_ACK),
        ]
    );
}

#[test]
fn nagle_holds_small_segment_while_unacked() {
    let mut f = Fixture::established(ConnectConfig::default(), 10 * MSS);
    f.write(&[1; 100]);
    let segs = f.drain(t(0));
    assert_eq!(segs.len(), 1);
    assert_eq!((segs[0].0.seq, segs[0].0.len), (data(0), 100));
    assert_eq!(segs[0].0.flags, PSH_ACK);
    f.write(&[2; 100]);
    assert!(
        f.drain(tm(10)).is_empty(),
        "held while 100 B unacknowledged"
    );
    // No SWS override while data is in flight: only the RTO is pending.
    assert_eq!(f.tcb.poll_send_at(), Some(t(1)));
    assert_eq!(f.ack(tm(50), data(100), 10 * MSS), Reaction::None);
    let segs = f.drain(tm(50));
    assert_eq!(segs.len(), 1);
    assert_eq!((segs[0].0.seq, segs[0].0.len), (data(100), 100));
    assert_eq!(segs[0].1, vec![2; 100]);
}

#[test]
fn rto_retransmits_with_backoff_and_karn() {
    let mut f = Fixture::established(ConnectConfig::default(), 10 * MSS);
    let bytes = pattern(500);
    f.write(&bytes);
    assert_eq!(f.drain(t(0)).len(), 1);
    assert_eq!(f.tcb.poll_send_at(), Some(t(1)));
    assert_eq!(f.timeout(tm(999)), Reaction::None);
    assert!(f.drain(tm(999)).is_empty());
    for (streak, (at, next)) in [(1, 3), (3, 7)].into_iter().enumerate() {
        assert_eq!(f.timeout(t(at)), Reaction::None);
        assert_eq!(f.tcb.rto_streak(), streak as u32 + 1);
        let segs = f.drain(t(at));
        assert_eq!(segs.len(), 1, "retransmission at {at} s");
        assert_eq!((segs[0].0.seq, segs[0].0.len), (data(0), 500));
        assert_eq!(segs[0].1, bytes);
        assert_eq!(f.tcb.poll_send_at(), Some(t(next)));
    }
    // The ACK covers a retransmitted segment: no RTT sample, RTO stays backed off.
    assert_eq!(f.ack(tm(3100), data(500), 10 * MSS), Reaction::None);
    assert_eq!(f.tcb.rto_streak(), 0, "SND.UNA advanced");
    assert_eq!(f.tcb.srtt(), None);
    assert_eq!(f.tcb.rtt.rto(), Duration::from_secs(4));
    assert_eq!(f.tcb.poll_send_at(), None);
    // A fresh segment is timed and its ACK yields a sample, collapsing the RTO.
    f.write(&[7; 100]);
    assert_eq!(f.drain(tm(3200)).len(), 1);
    assert_eq!(f.tcb.poll_send_at(), Some(tm(7200)));
    assert_eq!(f.ack(tm(3400), data(600), 10 * MSS), Reaction::None);
    assert_eq!(f.tcb.rtt.srtt(), Some(Duration::from_millis(200)));
    assert_eq!(f.tcb.rtt.rto(), Duration::from_secs(1));
}

#[test]
fn rto_reinit_3s_after_syn_retransmission() {
    let mut f = Fixture::unbounded(ConnectConfig::default());
    f.send(t(0)).unwrap();
    assert_eq!(f.timeout(t(1)), Reaction::None);
    assert_eq!(f.send(t(1)).unwrap().flags, TcpFlags::SYN);
    assert_eq!(
        f.recv(
            TcpFlags::SYN | TcpFlags::ACK,
            ISN.wrapping_add(1),
            10 * MSS,
            &opts(Some(MSS), Some(0))
        ),
        Reaction::Established
    );
    f.write(&[1; 100]);
    let segs = f.drain(t(1));
    assert_eq!(segs.len(), 1, "data carries the handshake ACK");
    assert_eq!(segs[0].0.len, 100);
    assert_eq!(f.tcb.poll_send_at(), Some(t(4)));
}

#[test]
fn r2_data_closes() {
    let cfg = ConnectConfig {
        r2_data: Duration::from_secs(100),
        ..ConnectConfig::default()
    };
    let mut f = Fixture::established(cfg, 10 * MSS);
    f.write(&[1; 500]);
    assert_eq!(f.drain(t(0)).len(), 1);
    let (sends, closed) = f.run_until_closed();
    assert_eq!(sends, [1, 3, 7, 15, 31, 63].map(t));
    assert_eq!(closed, t(100));
    assert_eq!(f.tcb.state(), TcpState::Closed);
    assert_eq!(f.tcb.poll_send_at(), Some(t(100)));
    // Exactly once.
    assert_eq!(f.timeout(t(500)), Reaction::None);
    assert_eq!(f.send(t(500)), None);
}

#[test]
fn r2_restarts_when_snd_una_advances() {
    let mut f = Fixture::established(ConnectConfig::default(), 10 * MSS);
    f.write(&[1; 2000]);
    assert_eq!(f.drain(t(0)).len(), 2);
    // The first segment is acknowledged at 0.1 s; R2 now counts from there.
    assert_eq!(f.ack(tm(100), data(1000), 10 * MSS), Reaction::None);
    let (sends, closed) = f.run_until_closed();
    assert_eq!(sends[0], tm(1100));
    assert_eq!(closed, tm(100_100));
}

#[test]
fn sender_sws_override_after_500ms() {
    let mut f = Fixture::unbounded(ConnectConfig::default());
    assert_eq!(
        f.synack(8192, &opts(Some(1460), Some(0))),
        Reaction::Established
    );
    assert_eq!(f.drain(t(0)).len(), 1); // handshake ACK
    assert_eq!(f.ack(t(0), ISN.wrapping_add(1), 300), Reaction::None);
    assert_eq!(f.tcb.snd_wnd, 300);
    f.write(&pattern(1000));
    // (1) 300 < 1460, (2) D = 1000 > U = 300, (3) 300 < 8192 / 2: nothing sent.
    assert!(f.drain(t(0)).is_empty());
    assert_eq!(f.tcb.poll_send_at(), Some(tm(500)));
    assert_eq!(f.timeout(tm(499)), Reaction::None);
    assert!(f.drain(tm(499)).is_empty());
    assert_eq!(f.timeout(tm(500)), Reaction::None);
    let segs = f.drain(tm(500));
    assert_eq!(segs.len(), 1);
    assert_eq!((segs[0].0.seq, segs[0].0.len), (data(0), 300));
    assert_eq!(segs[0].0.flags, TcpFlags::ACK);
    assert_eq!(segs[0].1, pattern(300));
}

#[test]
fn zero_window_probe_is_zero_length_at_una_minus_1() {
    let mut f = Fixture::established(ConnectConfig::default(), 0);
    f.write(&pattern(500));
    assert!(f.drain(t(0)).is_empty());
    assert_eq!(f.tcb.poll_send_at(), Some(t(1)));
    for (at, next) in [(1, 3), (3, 7)] {
        assert_eq!(f.timeout(t(at)), Reaction::None);
        let segs = f.drain(t(at));
        assert_eq!(segs.len(), 1, "probe at {at} s");
        let (meta, payload) = &segs[0];
        assert_eq!(meta.seq, ISN); // SND.UNA − 1
        assert_eq!((meta.len, meta.flags), (0, TcpFlags::ACK));
        assert!(payload.is_empty());
        assert_eq!(f.out.ack, PEER_ISN.wrapping_add(1));
        assert_eq!(f.tcb.poll_send_at(), Some(t(next)));
    }
    // The window opens: data flows and persist stops.
    assert_eq!(f.ack(t(4), data(0), 10 * MSS), Reaction::None);
    let segs = f.drain(t(4));
    assert_eq!(segs.len(), 1);
    assert_eq!((segs[0].0.seq, segs[0].0.len), (data(0), 500));
    assert_eq!(f.tcb.persist_at, None);
    assert_eq!(f.tcb.poll_send_at(), Some(t(5)));
}

#[test]
fn persist_not_armed_while_unacked() {
    let mut f = Fixture::established(ConnectConfig::default(), 10 * MSS);
    f.write(&pattern(500));
    assert_eq!(f.drain(t(0)).len(), 1);
    // Window closes with the data still unacknowledged.
    assert_eq!(f.ack(tm(100), data(0), 0), Reaction::None);
    assert_eq!(f.tcb.snd_wnd, 0);
    assert!(f.drain(tm(100)).is_empty());
    assert_eq!(f.tcb.persist_at, None);
    assert_eq!(f.tcb.poll_send_at(), Some(t(1)));
    assert_eq!(f.timeout(t(1)), Reaction::None);
    let segs = f.drain(t(1));
    assert_eq!(segs.len(), 1);
    assert_eq!((segs[0].0.seq, segs[0].0.len), (data(0), 500));
    assert_eq!(f.tcb.persist_at, None);
}

#[test]
fn answered_probes_do_not_hit_r2() {
    let mut f = Fixture::established(ConnectConfig::default(), 0);
    f.write(&pattern(500));
    assert!(f.drain(t(0)).is_empty());
    let mut probes = Vec::new();
    loop {
        let at = f.tcb.poll_send_at().unwrap();
        if at > t(300) {
            break;
        }
        assert_eq!(f.timeout(at), Reaction::None);
        let segs = f.drain(at);
        assert_eq!(segs.len(), 1);
        assert_eq!((segs[0].0.seq, segs[0].0.len), (ISN, 0));
        probes.push(at);
        assert_eq!(f.ack(at, data(0), 0), Reaction::None);
    }
    // ×2 per probe, capped at 60 s.
    assert_eq!(probes, [1, 3, 7, 15, 31, 63, 123, 183, 243].map(t));
    assert_eq!(f.tcb.state(), TcpState::Established);
}

#[test]
fn unanswered_probes_close_at_r2() {
    let mut f = Fixture::established(ConnectConfig::default(), 0);
    f.write(&pattern(500));
    assert!(f.drain(t(0)).is_empty());
    let (probes, closed) = f.run_until_closed();
    assert_eq!(probes, [1, 3, 7, 15, 31, 63].map(t));
    // R2 (100 s) counts from the first unanswered probe.
    assert_eq!(closed, t(101));
}

#[test]
fn ack_processing_rules() {
    let mut f = Fixture::established(ConnectConfig::default(), 10 * MSS);
    f.write(&pattern(1000));
    assert_eq!(f.drain(t(0)).len(), 1);
    // ACK of data not yet sent: answered with an ACK, otherwise ignored.
    assert_eq!(f.ack(tm(10), data(5000), 20000), Reaction::None);
    let segs = f.drain(tm(10));
    assert_eq!(segs.len(), 1);
    assert_eq!((segs[0].0.seq, segs[0].0.len), (data(1000), 0));
    assert_eq!(segs[0].0.flags, TcpFlags::ACK);
    assert_eq!((f.tcb.snd_una, f.tcb.snd_wnd), (data(0), 10000));
    // Window update from a later segment, then an older one (SEG.SEQ < SND.WL1) is ignored.
    let peer = PEER_ISN.wrapping_add(1);
    assert_eq!(
        f.ack_seq(tm(20), peer.wrapping_add(4), data(1000), 20000),
        Reaction::None
    );
    assert_eq!((f.tcb.snd_una, f.tcb.snd_wnd), (data(1000), 20000));
    assert_eq!(f.ack_seq(tm(30), peer, data(1000), 0), Reaction::None);
    assert_eq!(f.tcb.snd_wnd, 20000);
    // A peer window field is scaled by the shift from its SYN/ACK.
    let mut f = Fixture::unbounded(ConnectConfig::default());
    f.synack(100, &opts(Some(MSS), Some(3)));
    assert_eq!(f.tcb.snd_wnd, 100, "SYN/ACK window unscaled");
    assert_eq!(f.ack(t(0), ISN.wrapping_add(1), 100), Reaction::None);
    assert_eq!(f.tcb.snd_wnd, 800);
    assert_eq!(f.tcb.max_snd_wnd, 800);
}

#[derive(Default)]
struct CcLog {
    init: Option<u32>,
    acks: Vec<(u32, Option<Duration>, u32)>,
    events: Vec<(CongestionEvent, u32)>,
}

/// Fixed 2-segment window that records what the `Tcb` reports.
struct Recording(Arc<Mutex<CcLog>>);

impl CongestionControl for Recording {
    fn init(&mut self, smss: u32, _: bool) {
        self.0.lock().unwrap().init = Some(smss);
    }
    fn on_ack(&mut self, a: &AckSample) {
        self.0
            .lock()
            .unwrap()
            .acks
            .push((a.acked, a.rtt, a.in_flight));
    }
    fn on_congestion(&mut self, ev: CongestionEvent, in_flight: u32, _: Instant) {
        self.0.lock().unwrap().events.push((ev, in_flight));
    }
    fn on_recovery_ack(&mut self, _: RecoveryAck) {}
    fn cwnd(&self) -> u32 {
        2 * u32::from(MSS)
    }
}

#[test]
fn cc_gates_sending_and_sees_acks_and_rto() {
    let log = Arc::new(Mutex::new(CcLog::default()));
    let cfg = ConnectConfig::default();
    let h = PlainHooks::new(&cfg);
    let mut f = Fixture::with(cfg, Box::new(Recording(log.clone())), h);
    f.establish(10 * MSS);
    assert_eq!(log.lock().unwrap().init, Some(u32::from(MSS)));
    f.write(&pattern(5000));
    let segs = f.drain(t(0));
    assert_eq!(segs.len(), 2, "cwnd = 2 segments");
    assert_eq!(f.ack(tm(100), data(1000), 10 * MSS), Reaction::None);
    assert_eq!(
        log.lock().unwrap().acks,
        vec![(1000, Some(Duration::from_millis(100)), 1000)]
    );
    let segs = f.drain(tm(100));
    assert_eq!(segs.len(), 1);
    assert_eq!(segs[0].0.seq, data(2000));
    // RTO restarted by the ACK at 0.1 s.
    assert_eq!(f.tcb.poll_send_at(), Some(tm(1100)));
    assert_eq!(f.timeout(tm(1100)), Reaction::None);
    // FlightSize at the RTO: data(1000)..data(3000).
    assert_eq!(
        log.lock().unwrap().events,
        vec![(CongestionEvent::Rto, 2000)]
    );
    // Go-back from SND.UNA within this CC's fixed 2-segment window.
    let segs = f.drain(tm(1100));
    assert_eq!(seq_lens(&segs), [(data(1000), 1000), (data(2000), 1000)]);
}

#[test]
fn cc_gets_an_rtt_sample_per_ack_except_after_a_retransmission() {
    let log = Arc::new(Mutex::new(CcLog::default()));
    let cfg = ConnectConfig::default();
    let h = PlainHooks::new(&cfg);
    let mut f = Fixture::with(cfg, Box::new(Recording(log.clone())), h);
    f.establish(10 * MSS);
    f.write(&pattern(5000));
    assert_eq!(f.drain(t(0)).len(), 2);
    f.ack(tm(100), data(1000), 10 * MSS);
    assert_eq!(f.drain(tm(100)).len(), 1);
    // Segment 1 was not the RTO's timed segment, but the CC still gets its sample.
    f.ack(tm(150), data(2000), 10 * MSS);
    assert_eq!(f.drain(tm(150)).len(), 1);
    // The RTO resends segments 2 and 3 (Karn): their ACK carries no sample, ...
    assert_eq!(f.timeout(tm(1150)), Reaction::None);
    assert_eq!(f.drain(tm(1150)).len(), 2);
    f.ack(tm(1200), data(4000), 10 * MSS);
    assert_eq!(f.drain(tm(1200)).len(), 1);
    // ... but new data sent after them does.
    f.ack(tm(1250), data(5000), 10 * MSS);
    let rtts: Vec<_> = log.lock().unwrap().acks.iter().map(|a| a.1).collect();
    assert_eq!(
        rtts,
        [Some(100), Some(150), None, Some(50)].map(|r| r.map(Duration::from_millis))
    );
}

/// A send buffer whose runs are at most 7 octets, as at many internal buffer boundaries.
struct ShortRuns(PlainHooks, usize);

impl SendBuf for ShortRuns {
    fn peek_with<R>(&self, rel_ssn: u32, max: usize, f: impl FnOnce(&[u8]) -> R) -> Option<R> {
        self.0.peek_with(rel_ssn, max.min(7), f)
    }
    fn assigned_end(&self) -> u32 {
        self.0.assigned_end()
    }
    fn mark_acked(&mut self, rel_ssn_una: u32) {
        self.0.mark_acked(rel_ssn_una)
    }
}

impl SegmentHooks for ShortRuns {
    fn options_for(&mut self, flags: TcpFlags, out: &mut [u8]) -> usize {
        if flags.contains(TcpFlags::SYN) {
            return 0;
        }
        out[..self.1].fill(1); // NOPs reserve protocol option space without MPTCP data semantics.
        self.1
    }
    fn accept_payload(&mut self, rel_ssn: u32, data: &[u8]) {
        self.0.accept_payload(rel_ssn, data)
    }
    fn recv_window(&self) -> u32 {
        self.0.recv_window()
    }
}

#[test]
fn segment_filled_across_short_runs() {
    let cfg = ConnectConfig::default();
    let h = ShortRuns(PlainHooks::new(&cfg), 0);
    let mut f = Fixture::with(cfg, Box::new(Unbounded), h);
    f.establish(10 * MSS);
    f.tcb.set_nodelay(true);
    let bytes = pattern(2500);
    assert_eq!(f.h.0.write(&bytes), 2500);
    let segs = f.drain(t(0));
    let lens: Vec<_> = segs.iter().map(|(m, _)| m.len).collect();
    assert_eq!(lens, [1000, 1000, 500]);
    let sent: Vec<u8> = segs.into_iter().flat_map(|(_, p)| p).collect();
    assert_eq!(sent, bytes);
}

#[test]
fn answered_retransmission_probes_do_not_hit_r2() {
    let mut f = Fixture::established(ConnectConfig::default(), 10 * MSS);
    f.write(&pattern(500));
    assert_eq!(f.drain(t(0)).len(), 1);
    // The window closes with the data unacknowledged: each RTO retransmission is the probe.
    assert_eq!(f.ack(tm(100), data(0), 0), Reaction::None);
    let mut sends = Vec::new();
    loop {
        let at = f.tcb.poll_send_at().unwrap();
        if at > t(300) {
            break;
        }
        assert_eq!(f.timeout(at), Reaction::None);
        let segs = f.drain(at);
        assert_eq!(segs.len(), 1);
        assert_eq!((segs[0].0.seq, segs[0].0.len), (data(0), 500));
        sends.push(at);
        assert_eq!(f.ack(at, data(0), 0), Reaction::None);
    }
    assert_eq!(sends, [1, 3, 7, 15, 31, 63, 123, 183, 243].map(t));
    assert_eq!(f.tcb.state(), TcpState::Established);
}

#[test]
fn zero_window_discards_pending_sws_override() {
    let mut f = Fixture::unbounded(ConnectConfig::default());
    f.synack(8192, &opts(Some(1460), Some(0)));
    f.drain(t(0));
    f.ack(t(0), ISN.wrapping_add(1), 300);
    f.write(&pattern(1000));
    assert!(f.drain(t(0)).is_empty());
    // The override fires, but the window closes before the next poll.
    assert_eq!(f.timeout(tm(500)), Reaction::None);
    f.ack(tm(500), ISN.wrapping_add(1), 0);
    assert!(f.drain(tm(500)).is_empty());
    assert_eq!(f.tcb.poll_send_at(), Some(tm(1500)), "persist only");
    // Reopened to a sub-SWS window: a fresh 500 ms override, not the stale one.
    f.ack(tm(600), ISN.wrapping_add(1), 300);
    assert!(f.drain(tm(600)).is_empty());
    assert_eq!(f.tcb.poll_send_at(), Some(tm(1100)));
}

// ---- Receive path ----

/// Sequence number of peer data octet `n` (0-based).
fn pdata(n: u32) -> SeqNum {
    PEER_ISN.wrapping_add(1 + n)
}

fn rx_cfg(recv_buffer: u32) -> ConnectConfig {
    ConnectConfig {
        recv_buffer,
        ..ConnectConfig::default()
    }
}

impl<H: Hooks> Fixture<H> {
    /// A segment from the peer at peer data octet `off`, acknowledging everything we sent.
    fn seg_in(&mut self, now: Instant, off: u32, flags: TcpFlags, payload: &[u8]) -> Reaction {
        let ack = self.tcb.snd_nxt;
        self.seg_ack(now, off, ack, flags, payload)
    }
    /// As `seg_in`, with an explicit ACK number.
    fn seg_ack(
        &mut self,
        now: Instant,
        off: u32,
        ack: SeqNum,
        flags: TcpFlags,
        payload: &[u8],
    ) -> Reaction {
        let seg = Segment {
            src: self.addrs.1,
            dst: self.addrs.0,
            seq: pdata(off),
            ack,
            flags,
            wnd: 65535,
            options: &[],
            payload,
        };
        self.tcb.on_segment(&seg, now, &mut self.h)
    }
    fn data_in(&mut self, now: Instant, off: u32, payload: &[u8]) -> Reaction {
        self.seg_in(now, off, TcpFlags::ACK, payload)
    }
    /// Drains `poll_send`; every segment must be ACK-only. Returns each one's (ACK, window).
    fn acks(&mut self, now: Instant) -> Vec<(SeqNum, u16)> {
        let mut v = Vec::new();
        while let Some(m) = self.send(now) {
            assert_eq!((m.flags, m.len), (TcpFlags::ACK, 0));
            assert_eq!(m.seq, self.tcb.snd_max);
            v.push((self.out.ack, self.out.wnd));
            assert!(v.len() < 10, "poll_send does not stop");
        }
        v
    }
    /// `acks`, ACK numbers only.
    fn ack_nos(&mut self, now: Instant) -> Vec<SeqNum> {
        self.acks(now).into_iter().map(|a| a.0).collect()
    }
}

impl Fixture {
    fn read_all(&mut self) -> Vec<u8> {
        read_all(&mut self.h)
    }
}

fn read_all(h: &mut PlainHooks) -> Vec<u8> {
    let mut v = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        let n = h.read(&mut buf);
        if n == 0 {
            return v;
        }
        v.extend_from_slice(&buf[..n]);
    }
}

#[test]
fn in_order_data_delivered_and_delayed_ack() {
    let mut f = Fixture::established(ConnectConfig::default(), 10 * MSS);
    let p = pattern(3000);
    assert_eq!(f.data_in(t(0), 0, &p[..1000]), Reaction::None);
    assert!(f.acks(t(0)).is_empty(), "one segment: the ACK is delayed");
    assert_eq!(f.tcb.poll_send_at(), Some(tm(200)));
    assert_eq!(f.timeout(tm(200)), Reaction::None);
    assert_eq!(f.ack_nos(tm(200)), vec![pdata(1000)]);
    assert_eq!(f.tcb.poll_send_at(), None);
    // Two full segments: the second is ACKed at once.
    f.data_in(tm(300), 1000, &p[1000..2000]);
    assert!(f.acks(tm(300)).is_empty());
    f.data_in(tm(310), 2000, &p[2000..3000]);
    assert_eq!(f.ack_nos(tm(310)), vec![pdata(3000)]);
    assert_eq!(f.tcb.poll_send_at(), None, "delayed-ACK timer stopped");
    assert_eq!(f.read_all(), p);
}

#[test]
fn delayed_ack_rides_on_data() {
    let mut f = Fixture::established(ConnectConfig::default(), 10 * MSS);
    f.data_in(t(0), 0, &pattern(100));
    f.write(&pattern(100));
    let segs = f.drain(t(0));
    assert_eq!(segs.len(), 1);
    assert_eq!((segs[0].0.len, f.out.ack), (100, pdata(100)));
    // The pending delayed ACK went out with the data: only the RTO remains.
    assert_eq!(f.tcb.poll_send_at(), Some(t(1)));
}

#[test]
fn out_of_order_held_and_dup_acked() {
    let mut f = Fixture::established(ConnectConfig::default(), 10 * MSS);
    let p = pattern(2000);
    f.data_in(t(0), 1000, &p[1000..]);
    assert_eq!(
        f.acks(t(0)),
        vec![(pdata(0), 32768)],
        "immediate duplicate ACK"
    );
    assert!(f.read_all().is_empty());
    // The gap-filling segment is ACKed at once and both become readable.
    f.data_in(t(0), 0, &p[..1000]);
    assert_eq!(f.ack_nos(t(0)), vec![pdata(2000)]);
    assert_eq!(f.read_all(), p);
    assert_eq!(f.tcb.poll_send_at(), None);
}

fn sack_receiver(cfg: ConnectConfig) -> Fixture {
    let mut f = Fixture::new(cfg, v4());
    let mut options = opts(Some(MSS), Some(0));
    options.extend_from_slice(&[4, 2]);
    assert_eq!(f.synack(65535, &options), Reaction::Established);
    f.send(t(0)).unwrap();
    assert!(f.tcb.sack_permitted);
    f
}

fn sack_blocks(out: &SegmentWriter) -> Vec<(SeqNum, SeqNum)> {
    parsed(out.options())
        .into_iter()
        .filter_map(|opt| match opt {
            TcpOpt::Sack(raw) => Some(
                raw.chunks_exact(8)
                    .map(|block| {
                        (
                            SeqNum(u32::from_be_bytes(block[..4].try_into().unwrap())),
                            SeqNum(u32::from_be_bytes(block[4..].try_into().unwrap())),
                        )
                    })
                    .collect::<Vec<_>>(),
            ),
            _ => None,
        })
        .flatten()
        .collect()
}

#[test]
fn sack_requires_peer_permission_and_orders_coalesced_blocks() {
    let mut plain = Fixture::established(ConnectConfig::default(), 65535);
    plain.data_in(t(0), 100, &[1; 100]);
    plain.send(t(0)).unwrap();
    assert!(plain.out.options().is_empty());

    let mut f = sack_receiver(ConnectConfig::default());
    for off in [100, 300, 500, 700, 900] {
        f.data_in(t(0), off, &[1; 100]);
        f.send(t(0)).unwrap();
        assert_eq!(sack_blocks(&f.out)[0], (pdata(off), pdata(off + 100)));
        assert!(f.out.options_len <= 40);
    }
    assert_eq!(
        sack_blocks(&f.out),
        vec![
            (pdata(900), pdata(1000)),
            (pdata(700), pdata(800)),
            (pdata(500), pdata(600)),
            (pdata(300), pdata(400)),
        ]
    );
    f.data_in(t(0), 200, &[1; 100]);
    f.send(t(0)).unwrap();
    assert_eq!(sack_blocks(&f.out)[0], (pdata(100), pdata(400)));
    f.data_in(t(0), 0, &[1; 100]);
    f.send(t(0)).unwrap();
    assert_eq!(f.out.ack, pdata(400));
    assert!(
        !sack_blocks(&f.out)
            .iter()
            .any(|&(left, _)| left.lt(f.out.ack))
    );
}

#[test]
fn sack_reports_only_bytes_held_within_the_window() {
    let mut f = sack_receiver(rx_cfg(200));
    f.data_in(t(0), 100, &[1; 200]);
    f.send(t(0)).unwrap();
    assert_eq!(sack_blocks(&f.out), vec![(pdata(100), pdata(200))]);
    f.data_in(t(0), 0, &[1; 100]);
    f.send(t(0)).unwrap();
    assert_eq!(f.out.ack, pdata(200));
    assert!(sack_blocks(&f.out).is_empty());
    assert_eq!(f.read_all(), vec![1; 200]);
}

#[test]
fn dsack_reports_old_and_partial_duplicates_once_across_wrap() {
    let mut f = sack_receiver(ConnectConfig::default());
    let p = pattern(250);
    f.data_in(t(0), 0, &p[..200]);
    f.timeout(tm(200));
    f.send(tm(200)).unwrap();
    // Below RCV.NXT: rejected by TCP's window check, but still reported as DSACK.
    f.data_in(tm(210), 0, &p[..100]);
    f.send(tm(210)).unwrap();
    assert_eq!(sack_blocks(&f.out), vec![(pdata(0), pdata(100))]);
    assert_eq!(f.out.ack, pdata(200));
    assert!(f.tcb.dsack.is_none());
    f.data_in(tm(220), 150, &p[150..250]);
    // DSACK changes ACK contents, not the existing delayed-ACK policy (RFC 2883 §2).
    assert_eq!(f.send(tm(220)), None);
    f.timeout(tm(420));
    f.send(tm(420)).unwrap();
    assert_eq!(sack_blocks(&f.out), vec![(pdata(150), pdata(200))]);
    assert_eq!(f.out.ack, pdata(250));
    f.tcb.ack_due = true;
    f.send(tm(420)).unwrap();
    assert!(sack_blocks(&f.out).is_empty());
    assert_eq!(f.read_all(), p);
    // Data before IRS + 1 was never received and must not be reported.
    f.seg_ack(
        tm(430),
        u32::MAX - 99,
        f.tcb.snd_una,
        TcpFlags::ACK,
        &[1; 50],
    );
    f.send(tm(430)).unwrap();
    assert!(sack_blocks(&f.out).is_empty());
    f.seg_in(tm(440), 250, TcpFlags::ACK | TcpFlags::FIN, &[]);
    f.send(tm(440)).unwrap();
    f.data_in(tm(450), 200, &p[200..]);
    f.send(tm(450)).unwrap();
    assert_eq!(sack_blocks(&f.out), vec![(pdata(200), pdata(250))]);
    assert_eq!(f.out.ack, pdata(251));
}

#[test]
fn dsack_above_ack_includes_the_containing_block_second() {
    let mut f = sack_receiver(ConnectConfig::default());
    f.data_in(t(0), 100, &[1; 200]);
    f.send(t(0)).unwrap();
    for (off, len) in [(150, 50), (100, 200)] {
        f.data_in(t(0), off, &vec![1; len]);
        f.send(t(0)).unwrap();
        assert_eq!(
            sack_blocks(&f.out),
            vec![
                (pdata(off), pdata(off + len as u32)),
                (pdata(100), pdata(300)),
            ]
        );
    }
    // Partly duplicate, partly new: report the duplicate bytes and merged held block.
    f.data_in(t(0), 250, &[1; 150]);
    f.send(t(0)).unwrap();
    assert_eq!(
        sack_blocks(&f.out),
        vec![(pdata(250), pdata(300)), (pdata(100), pdata(400)),]
    );
    f.data_in(t(0), 150, &[1; 50]);
    let mut short = [0; 12];
    assert_eq!(f.tcb.write_sacks(&mut short), 12);
    assert_eq!(&short[2..6], &pdata(100).0.to_be_bytes());
    assert_eq!(&short[6..10], &pdata(400).0.to_be_bytes());
    // No output: the pending DSACK must survive until an ACK is emitted.
    f.tcb.ack_due = false;
    assert_eq!(f.send(t(0)), None);
    assert!(f.tcb.dsack.is_some());
    f.data_in(t(0), 0, &[1; 100]);
    f.send(t(0)).unwrap();
    assert_eq!(f.read_all(), vec![1; 400]);
}

#[test]
fn sack_and_dsack_piggyback_on_data_without_exceeding_mtu() {
    for mtu in [68, 1500] {
        let mut f = sack_receiver(ConnectConfig {
            mtu,
            ..ConnectConfig::default()
        });
        f.data_in(t(0), 100, &[1; 100]);
        f.send(t(0)).unwrap();
        f.data_in(t(0), 150, &[1; 50]);
        f.write(&pattern(2000));
        f.send(t(0)).unwrap();
        assert!(!f.out.payload.is_empty());
        assert_eq!(
            sack_blocks(&f.out),
            vec![(pdata(150), pdata(200)), (pdata(100), pdata(200)),]
        );
        assert!(40 + f.out.options_len + f.out.payload.len() <= usize::from(mtu));
        assert!(f.tcb.dsack.is_none());
        f.send(t(0)).unwrap();
        assert_eq!(sack_blocks(&f.out), vec![(pdata(100), pdata(200))]);
        assert!(40 + f.out.options_len + f.out.payload.len() <= usize::from(mtu));
    }
}

#[test]
fn overlap_straddling_rcv_nxt_trimmed() {
    let mut f = Fixture::established(ConnectConfig::default(), 10 * MSS);
    let p = pattern(1400);
    f.data_in(t(0), 0, &p[..1000]);
    // Retransmission covering [rcv_nxt − 100, rcv_nxt + 400).
    f.data_in(t(0), 900, &p[900..1400]);
    assert_eq!(f.ack_nos(t(0)), vec![pdata(1400)]);
    assert_eq!(f.read_all(), p, "the new 400 B delivered once");
}

#[test]
fn segment_half_beyond_window_trimmed() {
    let mut f = Fixture::established(rx_cfg(2000), 10 * MSS);
    assert_eq!(f.tcb.rcv_shift, 0);
    let p = pattern(2500);
    // Out of order and straddling the right edge: [1000, 2000) is kept, the rest dropped.
    f.data_in(t(0), 1000, &p[1000..2500]);
    // The edge advertised before stays: the window is not shrunk to the free memory.
    assert_eq!(f.acks(t(0)), vec![(pdata(0), 2000)]);
    // In order and straddling it too: only the missing [0, 1000) is new.
    f.data_in(t(0), 0, &p[..2500]);
    assert_eq!(f.acks(t(0)), vec![(pdata(2000), 0)]);
    assert_eq!(f.read_all(), &p[..2000]);
}

/// A segment copied out of a `SegmentWriter`.
struct Wire {
    seq: SeqNum,
    ack: SeqNum,
    flags: TcpFlags,
    wnd: u16,
    payload: Vec<u8>,
}

fn emit(tcb: &mut Tcb, h: &mut PlainHooks, out: &mut SegmentWriter, now: Instant) -> Vec<Wire> {
    let mut v = Vec::new();
    while tcb.poll_send(now, h, out).is_some() {
        v.push(Wire {
            seq: out.seq,
            ack: out.ack,
            flags: out.flags,
            wnd: out.wnd,
            payload: out.payload.clone(),
        });
        assert!(v.len() < 1000, "poll_send does not stop");
    }
    v
}

fn deliver(tcb: &mut Tcb, h: &mut PlainHooks, w: &Wire, now: Instant) {
    assert_eq!(feed(tcb, h, w, now), Reaction::None);
}

fn feed(tcb: &mut Tcb, h: &mut PlainHooks, w: &Wire, now: Instant) -> Reaction {
    let (src, dst) = v4();
    let seg = Segment {
        src,
        dst,
        seq: w.seq,
        ack: w.ack,
        flags: w.flags,
        wnd: w.wnd,
        options: &[],
        payload: &w.payload,
    };
    tcb.on_segment(&seg, now, h)
}

#[test]
fn wraparound_transfer() {
    const N: usize = 64 << 10;
    let cfg = ConnectConfig::default();
    let (la, lb) = v4();
    let (isn_a, isn_b) = (SeqNum(0xFFFF_FF80), SeqNum(0xFFFF_FF00));
    let mut a = Tcb::new_established(&cfg, la, lb, isn_a, isn_b, Some(1460), Some(7), t(0));
    let mut b = Tcb::new_established(&cfg, lb, la, isn_b, isn_a, Some(1460), Some(7), t(0));
    let (mut ha, mut hb) = (PlainHooks::new(&cfg), PlainHooks::new(&cfg));
    let to_b = pattern(N);
    let to_a: Vec<u8> = (0..N).map(|i| (i % 241) as u8 ^ 0x5a).collect();
    assert_eq!(ha.write(&to_b), N);
    assert_eq!(hb.write(&to_a), N);
    let (mut got_a, mut got_b) = (Vec::new(), Vec::new());
    let mut out = SegmentWriter::default();
    let mut now = t(0);
    let mut lost = false;
    for _ in 0..10_000 {
        let from_a = emit(&mut a, &mut ha, &mut out, now);
        let from_b = emit(&mut b, &mut hb, &mut out, now);
        let quiet = from_a.is_empty() && from_b.is_empty();
        for w in &from_a {
            // A's first data segment crosses the wrap of its sequence space: lose it once, so B
            // reassembles everything after it across the wrap.
            if !lost && !w.payload.is_empty() {
                assert!(w.seq.0.checked_add(w.payload.len() as u32).is_none());
                lost = true;
                continue;
            }
            deliver(&mut b, &mut hb, w, now);
        }
        for w in &from_b {
            deliver(&mut a, &mut ha, w, now);
        }
        got_a.extend(read_all(&mut ha));
        got_b.extend(read_all(&mut hb));
        if got_a.len() == N && got_b.len() == N && a.in_flight() == 0 && b.in_flight() == 0 {
            break;
        }
        if quiet {
            now = [a.poll_send_at(), b.poll_send_at()]
                .into_iter()
                .flatten()
                .min()
                .expect("stalled without a timer");
            assert_eq!(a.on_timeout(now, &mut ha), Reaction::None);
            assert_eq!(b.on_timeout(now, &mut hb), Reaction::None);
        }
    }
    assert!(lost);
    assert!(got_a == to_a && got_b == to_b, "byte-exact both ways");
    let end = |isn: SeqNum| isn.wrapping_add(1 + N as u32);
    assert_eq!((a.snd_una, a.rcv_nxt), (end(isn_a), end(isn_b)));
    assert_eq!((b.snd_una, b.rcv_nxt), (end(isn_b), end(isn_a)));
}

#[test]
fn no_memory_means_not_acked() {
    const BUF: u32 = 4 << 20;
    let mut f = Fixture::established(ConnectConfig::default(), 10 * MSS);
    assert_eq!(f.tcb.rcv_shift, 7);
    let p = pattern(BUF as usize + 24);
    // The app does not read: two in-order segments leave 1000 B of free memory. The window
    // edge advertised by the handshake (RCV.NXT + 4 MiB) is kept by rounding up to 1024.
    let fill = BUF - 1000;
    f.data_in(t(0), 0, &p[..2_000_000]);
    f.data_in(t(0), 2_000_000, &p[2_000_000..fill as usize]);
    assert_eq!(f.h.recv_window(), 1000);
    assert_eq!(f.acks(t(0)), vec![(pdata(fill), 8)]);
    // The peer fills the 1024 B window: 1000 B stored, the last 24 B dropped and not ACKed.
    f.data_in(t(0), fill, &p[fill as usize..fill as usize + 1024]);
    let acks = f.acks(t(0));
    assert_eq!(acks.len(), 1);
    assert_eq!(acks[0].0, pdata(BUF));
    let got = f.read_all();
    assert_eq!(
        got.len() - fill as usize,
        1000,
        "the app reads exactly 1000 more"
    );
    assert_eq!(got, p[..BUF as usize]);
}

/// The app never reads; the peer sends `seg`-octet segments inside the last advertised window
/// (one octet when it is closed) and resends what was not ACKed. Checks every ACK (ruling R16):
/// the advertised edge never retracts by a scale unit or more from the largest edge
/// advertised, stays less than one unit beyond the memory, and a zero window appears only with
/// the memory full. Returns (probes, ACKs, zero windows).
fn stall(buffer: u32, shift: u8, seg: usize, n: u64) -> (u32, u32, u32) {
    let mut f = Fixture::established(rx_cfg(buffer), 10 * MSS);
    assert_eq!(f.tcb.rcv_shift, shift);
    let unit = 1i32 << shift;
    let mem_edge = pdata(buffer);
    let p = pattern(seg);
    let mut expect = Vec::new();
    // `edge`: the peer's view (the last ACK); `max_edge`: the largest edge advertised.
    let (mut edge, mut next) = (f.tcb.rcv_right_edge, 0u32);
    let (mut max_edge, mut probes, mut acks, mut zero_wnds) = (edge, 0, 0, 0);
    for i in 0..n {
        let now = tm(i);
        let len = (pdata(next).distance(edge).max(0) as usize).min(seg).max(1);
        let stored = len.min(f.h.recv_window() as usize);
        f.data_in(now, next, &p[..len]);
        if stored == 0 {
            probes += 1;
        }
        // What is not stored is not ACKed; the peer resends from the ACK.
        expect.extend_from_slice(&p[..stored]);
        next += stored as u32;
        for (ack, wnd) in f.acks(now) {
            let e = ack.wrapping_add(u32::from(wnd) << shift);
            assert!(mem_edge.distance(e) < unit, "overshoot at segment {i}");
            assert!(e.distance(max_edge) < unit, "retraction at segment {i}");
            if wnd == 0 {
                assert_eq!(f.h.recv_window(), 0, "zero window with free memory");
                zero_wnds += 1;
            }
            if e.gt(max_edge) {
                max_edge = e;
            }
            assert_eq!(f.tcb.rcv_right_edge, max_edge);
            edge = e;
            acks += 1;
        }
    }
    let got = f.read_all();
    assert_eq!(
        got.len(),
        buffer as usize,
        "the buffer is full, nothing beyond"
    );
    assert_eq!(got, expect);
    (probes, acks, zero_wnds)
}

#[test]
fn window_right_edge_never_shrinks() {
    let (probes, acks, zero_wnds) = stall(200_000, 2, 333, 1000);
    assert!(probes > 300 && acks > 500 && zero_wnds > 300);
}

#[test]
fn round_up_overshoot_below_one_scale_unit() {
    // 4 MiB at scale 7 with 1453 B segments: about 1450 re-advertisements before it fills.
    let (probes, acks, zero_wnds) = stall(4 << 20, 7, 1453, 3000);
    assert!(probes > 100 && acks > 1500 && zero_wnds > 100);
}

#[test]
fn receiver_sws_holds_small_window_updates() {
    let mut f = Fixture::established(rx_cfg(10_000), 10 * MSS);
    let p = pattern(10_000);
    for k in 0..10 {
        f.data_in(t(0), k * 1000, &p[(k * 1000) as usize..][..1000]);
    }
    let acks = f.acks(t(0));
    assert_eq!(acks.last(), Some(&(pdata(10_000), 0)), "window closed");
    // Threshold min(buffer / 2, eff_mss) = 1000: no update for 100 B reads until 1000 B.
    let mut buf = [0u8; 100];
    for k in 1..=10 {
        assert_eq!(f.h.read(&mut buf), 100);
        let acks = f.acks(t(0));
        if k < 10 {
            assert!(acks.is_empty(), "update after {}", k * 100);
        } else {
            assert_eq!(acks, vec![(pdata(10_000), 1000)]);
        }
    }
    assert!(f.acks(t(0)).is_empty(), "one update per edge move");
}

#[test]
fn out_of_window_segment_gets_ack_unchanged() {
    let mut f = Fixture::established(rx_cfg(2000), 10 * MSS);
    let p = pattern(500);
    // Beyond the right edge.
    f.data_in(t(0), 2000, &[7; 100]);
    assert_eq!(f.acks(t(0)), vec![(pdata(0), 2000)]);
    assert!(f.read_all().is_empty());
    // Entirely old: a duplicate draws an ACK that also covers the delayed one.
    f.data_in(t(0), 0, &p);
    assert!(f.acks(t(0)).is_empty());
    f.data_in(t(0), 0, &p);
    assert_eq!(f.acks(t(0)), vec![(pdata(500), 1500)]);
    // Never in response to a RST.
    f.seg_in(t(0), 5000, TcpFlags::RST | TcpFlags::ACK, &[]);
    assert!(f.acks(t(0)).is_empty());
    assert_eq!(f.read_all(), p);
}

#[test]
fn retransmitted_synack_in_established_is_acked() {
    let mut f = Fixture::established(ConnectConfig::default(), 10 * MSS);
    assert_eq!(
        f.recv(
            TcpFlags::SYN | TcpFlags::ACK,
            ISN.wrapping_add(1),
            1000,
            &opts(Some(MSS), Some(0))
        ),
        Reaction::None
    );
    assert_eq!(f.acks(t(0)), vec![(pdata(0), 32768)]);
    assert_eq!(f.tcb.state(), TcpState::Established);
}

#[test]
fn ooo_range_cap() {
    let mut f = Fixture::established(ConnectConfig::default(), 10 * MSS);
    let p = pattern(200);
    let mut acks = Vec::new();
    // 70 disjoint one-octet segments with holes between them.
    for i in 0..70 {
        let off = 2 + 2 * i;
        f.data_in(t(0), off, &p[off as usize..][..1]);
        acks.extend(f.acks(t(0)));
    }
    assert_eq!(f.tcb.rcv_ooo.len(), 64);
    assert_eq!(
        acks,
        vec![(pdata(0), 32768); 64],
        "the 6 over the cap are not ACKed"
    );
    // At the cap, a segment joining existing ranges is still taken.
    f.data_in(t(0), 3, &p[3..4]);
    assert_eq!(f.acks(t(0)).len(), 1);
    assert_eq!(f.tcb.rcv_ooo.len(), 63);
    // Filling every hole delivers each octet once.
    f.data_in(t(0), 0, &p);
    assert_eq!(f.ack_nos(t(0)), vec![pdata(200)]);
    assert_eq!(f.read_all(), p);
    assert!(f.tcb.rcv_ooo.is_empty());
}

#[test]
fn full_memory_advertises_zero_window_and_reopens() {
    const BUF: u32 = 4 << 20;
    let mut f = Fixture::established(ConnectConfig::default(), 10 * MSS);
    let p = pattern(BUF as usize + 2000);
    let fill = BUF - 1000;
    f.data_in(t(0), 0, &p[..2_000_000]);
    f.data_in(t(0), 2_000_000, &p[2_000_000..fill as usize]);
    assert_eq!(f.acks(t(0)), vec![(pdata(fill), 8)]);
    // 1000 of the 1024 B stored: memory is full, so the window is 0 (the edge retracts by
    // less than 2^7, RFC 7323 §2.4) instead of a rounded-up 128 B nobody can store.
    f.data_in(t(0), fill, &p[fill as usize..][..1024]);
    assert_eq!(f.acks(t(0)), vec![(pdata(BUF), 0)]);
    f.data_in(t(0), BUF, &p[BUF as usize..][..1]);
    assert_eq!(
        f.acks(t(0)),
        vec![(pdata(BUF), 0)],
        "probe answered, still closed"
    );
    // Our data in flight; the peer's pure ACK at its SND.NXT (beyond our zero window, where
    // its dropped 24 B ended) still acknowledges it.
    f.write(&pattern(500));
    assert_eq!(f.drain(t(0)).len(), 1);
    f.seg_ack(t(0), BUF + 24, data(500), TcpFlags::ACK, &[]);
    assert_eq!(f.tcb.snd_una, data(500));
    assert_eq!(f.acks(t(0)), vec![(pdata(BUF), 0)]);
    // A small read stays below the SWS threshold: no update.
    let mut buf = vec![0u8; 65536];
    assert_eq!(f.h.read(&mut buf[..500]), 500);
    assert!(f.acks(t(0)).is_empty());
    // A read past it reopens the window, and the transfer continues.
    assert_eq!(f.h.read(&mut buf[500..]), 65036);
    assert_eq!(f.acks(t(0)), vec![(pdata(BUF), 512)]);
    f.data_in(t(1), BUF, &p[BUF as usize..]);
    assert_eq!(f.ack_nos(t(1)), Vec::<SeqNum>::new());
    assert_eq!(f.timeout(tm(1200)), Reaction::None);
    assert_eq!(f.ack_nos(tm(1200)), vec![pdata(BUF + 2000)]);
    let mut got = buf;
    got.extend(f.read_all());
    assert_eq!(got, p);
}

#[test]
fn zero_window_still_takes_acks() {
    let mut f = Fixture::established(rx_cfg(10_000), 10 * MSS);
    let p = pattern(10_000);
    for k in 0..10 {
        f.seg_ack(
            t(0),
            k * 1000,
            data(0),
            TcpFlags::ACK,
            &p[(k * 1000) as usize..][..1000],
        );
    }
    assert_eq!(f.acks(t(0)).last(), Some(&(pdata(10_000), 0)));
    assert_eq!(f.tcb.rcv_wnd(), 0);
    f.write(&pattern(300));
    assert_eq!(f.drain(t(0)).len(), 1);
    // A one-octet probe at RCV.NXT: its text is refused, its ACK field is taken.
    f.seg_ack(t(0), 10_000, data(100), TcpFlags::ACK, &[9]);
    assert_eq!((f.tcb.snd_una, f.h.recv_window()), (data(100), 0));
    assert_eq!(f.acks(t(0)), vec![(pdata(10_000), 0)]);
    // A pure ACK at RCV.NXT + 1 (after the dropped probe octet).
    f.seg_ack(t(0), 10_001, data(300), TcpFlags::ACK, &[]);
    assert_eq!(f.tcb.snd_una, data(300));
    assert_eq!(f.acks(t(0)), vec![(pdata(10_000), 0)]);
    // An ACK of data not yet sent changes nothing.
    f.seg_ack(t(0), 10_001, data(900), TcpFlags::ACK, &[]);
    assert_eq!(f.tcb.snd_una, data(300));
    assert_eq!(f.acks(t(0)).len(), 1);
    assert_eq!(f.read_all(), p);
}

#[test]
fn text_processed_when_ack_is_old() {
    let mut f = Fixture::established(ConnectConfig::default(), 10 * MSS);
    f.write(&pattern(1000));
    assert_eq!(f.drain(t(0)).len(), 1);
    f.ack(t(0), data(1000), 10_000);
    assert_eq!(f.tcb.snd_una, data(1000));
    // SEG.ACK < SND.UNA: the ACK is ignored, the text is not.
    f.seg_ack(t(0), 0, data(0), TcpFlags::ACK, &pattern(100));
    assert_eq!(f.tcb.snd_una, data(1000));
    assert_eq!(f.read_all(), pattern(100));
}

/// Scale 7, the app reading irregular amounts slower than the peer streams 1453 B segments
/// (so the window closes and reads must reopen it), with
/// our eff_mss `mss` (64 puts the SWS threshold below the scale unit). Every ACK stays within
/// one unit of the largest edge and of the memory's edge; an update made by a read moves the
/// edge to a scale-aligned point inside the memory.
fn reading_receiver(mss: u16) {
    const BUF: u32 = 4 << 20;
    let mut f = Fixture::unbounded(ConnectConfig::default());
    f.synack(65535, &opts(Some(mss), Some(0)));
    assert_eq!(f.acks(t(0)).len(), 1);
    assert_eq!((f.tcb.rcv_shift, f.tcb.eff_mss), (7, mss));
    let p = pattern(1453);
    let (mut edge, mut max_edge) = (f.tcb.rcv_right_edge, f.tcb.rcv_right_edge);
    let (mut next, mut read, mut updates) = (0u32, 0u32, 0);
    let mut buf = vec![0u8; 4096];
    for i in 0..8000u64 {
        let now = tm(i);
        let len = (pdata(next).distance(edge).max(0) as usize)
            .min(p.len())
            .max(1);
        let before = f.tcb.rcv_nxt;
        f.data_in(now, next, &p[..len]);
        // The peer resends what was not ACKed.
        next += before.distance(f.tcb.rcv_nxt) as u32;
        let mut check = |f: &mut Fixture, after_read: bool, read: u32| {
            let mem_edge = pdata(read + BUF);
            for (ack, wnd) in f.acks(now) {
                let e = ack.wrapping_add(u32::from(wnd) << 7);
                assert!(mem_edge.distance(e) < 128, "overshoot at {i}");
                assert!(e.distance(max_edge) < 128, "retraction at {i}");
                if after_read {
                    assert!(e.le(mem_edge) && ack.distance(e) % 128 == 0);
                    updates += 1;
                }
                if e.gt(max_edge) {
                    max_edge = e;
                }
                edge = e;
            }
        };
        check(&mut f, false, read);
        let want = if i % 4 == 0 {
            (100 + i * 37 % 1500) as usize
        } else {
            0
        };
        read += f.h.read(&mut buf[..want]) as u32;
        check(&mut f, true, read);
    }
    assert!(updates > 100, "{updates} updates");
}

#[test]
fn reads_move_the_edge_aligned_within_one_unit() {
    reading_receiver(1000);
    reading_receiver(64);
}

#[test]
fn rounding_alone_draws_no_window_update() {
    const BUF: u32 = 4 << 20;
    let mut f = Fixture::established(ConnectConfig::default(), 10 * MSS);
    let p = pattern(BUF as usize);
    let fill = BUF - 1000;
    f.data_in(t(0), 0, &p[..2_000_000]);
    f.data_in(t(0), 2_000_000, &p[2_000_000..fill as usize]);
    assert_eq!(f.acks(t(0)), vec![(pdata(fill), 8)]);
    // 990 B in order: rounding the SWS edge up from the new RCV.NXT would move the advertised
    // edge past the largest one, but that is no window update; the ACK stays delayed.
    f.data_in(t(0), fill, &p[fill as usize..][..990]);
    assert!(f.acks(t(0)).is_empty());
    assert_eq!(f.timeout(tm(200)), Reaction::None);
    assert_eq!(f.acks(tm(200)), vec![(pdata(fill + 990), 1)]);
}

#[test]
fn sws_edge_never_moves_left() {
    // eff_mss 64 puts the SWS threshold (64) below the scale unit (128).
    const BUF: u32 = 4 << 20;
    let mut f = Fixture::unbounded(ConnectConfig::default());
    f.synack(65535, &opts(Some(64), Some(0)));
    assert_eq!(f.acks(t(0)).len(), 1);
    let p = pattern(BUF as usize);
    // 129 B of memory left: the SWS edge (RCV.NXT + 4 MiB) is re-advertised rounded up to
    // 256, so the largest edge is 127 B beyond it.
    let fill = BUF - 129;
    f.data_in(t(0), 0, &p[..2_000_000]);
    f.data_in(t(0), 2_000_000, &p[2_000_000..fill as usize]);
    assert_eq!(f.acks(t(0)), vec![(pdata(fill), 2)]);
    // A 64 B read meets the threshold, but the aligned point (RCV.NXT + 128) is 1 B before
    // the SWS edge: the edge stays, and so does the advertisement (128 back would retract the
    // largest edge by a whole unit).
    assert_eq!(f.h.read(&mut [0u8; 64]), 64);
    assert!(f.acks(t(0)).is_empty());
    f.data_in(t(0), 0, &p[..10]);
    assert_eq!(f.acks(t(0)), vec![(pdata(fill), 2)]);
}

// ---- Congestion control and loss recovery (Task 9) ----

fn seq_lens(segs: &[(SentMeta, Vec<u8>)]) -> Vec<(SeqNum, u32)> {
    segs.iter().map(|(m, _)| (m.seq, m.len)).collect()
}

/// Peer window in the Reno tests (shift 0).
const BIG: u16 = 65535;

impl Fixture {
    /// ESTABLISHED at t(0) with `Reno` (SMSS = MSS = 1000, so IW = 4 segments), peer window
    /// `BIG`, `bytes` written; then segments 0–2 are ACKed one by one at 10, 20 and 30 ms,
    /// each ACK opening two more. Leaves segments 3–9 outstanding (SND.UNA = data(3000),
    /// SND.MAX = data(10000)), cwnd 7 segments, RTO due at 1.03 s.
    fn reno_ramp(bytes: &[u8]) -> Self {
        let cfg = ConnectConfig::default();
        let h = PlainHooks::new(&cfg);
        let mut f = Fixture::with(cfg, Box::new(Reno::new()), h);
        f.establish(BIG);
        f.write(bytes);
        assert_eq!(f.drain(t(0)).len(), 4, "IW");
        for k in 1..=3 {
            assert_eq!(
                f.ack(tm(10 * k), data(k as u32 * 1000), BIG),
                Reaction::None
            );
            assert_eq!(f.drain(tm(10 * k)).len(), 2, "slow start");
        }
        assert_eq!((f.tcb.snd_una, f.tcb.snd_max), (data(3000), data(10_000)));
        assert_eq!(f.tcb.cc.cwnd(), 7000);
        assert_eq!(f.tcb.poll_send_at(), Some(tm(1030)));
        f
    }
    /// `n` duplicate ACKs of `ack` at `now`; each must draw nothing.
    fn dup_acks_quiet(&mut self, now: Instant, ack: SeqNum, n: usize) {
        for i in 0..n {
            assert_eq!(self.ack(now, ack, BIG), Reaction::None);
            assert!(
                self.drain(now).is_empty(),
                "duplicate ACK {i}: nothing sent"
            );
        }
    }
}

/// The default controller against a modeled bottleneck: base RTT 20 ms, 2500 segments/s (BDP
/// 50 segments of MSS) and a 100-segment drop-tail queue, as base-a's ratios (queue = 2·BDP).
/// Every segment is ACKed on arrival, so the RTT the sender sees rises with the queue once
/// cwnd passes the BDP. Standard slow start doubles on until the queue overflows near
/// 2·(BDP + queue); the default must leave slow start (an ACK of one SMSS growing cwnd by
/// less than one SMSS) well before that, and before the queue would drop anything. (HyStart++
/// leaves into CSS here, at cwnd 106 segments; CSS's five rounds at 1.25× per round still pass
/// BDP + queue later, at a quarter of the slow start rate.)
#[test]
fn default_cc_leaves_slow_start_before_queue_overflow() {
    const BDP: u32 = 50;
    const QUEUE: u32 = 100;
    let base = Duration::from_millis(20);
    let service = Duration::from_micros(400);
    let mut f = Fixture::new(ConnectConfig::default(), v4());
    f.synack(BIG, &opts(Some(MSS), Some(7)));
    f.write(&pattern(2 << 20));
    let mut link_free = t(0);
    let mut acks = std::collections::VecDeque::new();
    let mut max_queue = 0;
    let mut send = |f: &mut Fixture, now: Instant, acks: &mut std::collections::VecDeque<_>| {
        for (m, _) in f.drain(now) {
            if m.len == 0 {
                continue;
            }
            let queued = (link_free.max(now) - now).as_nanos() / service.as_nanos();
            max_queue = max_queue.max(queued as u32);
            link_free = link_free.max(now) + service;
            acks.push_back((link_free + base, m.seq.wrapping_add(m.len)));
        }
    };
    send(&mut f, t(0), &mut acks);
    let limit = (2 * (BDP + QUEUE)) * u32::from(MSS);
    let exit = loop {
        let (at, ack) = acks.pop_front().expect("ACK-clocked");
        let before = f.tcb.cc.cwnd();
        assert_eq!(f.ack(at, ack, BIG), Reaction::None);
        let grew = f.tcb.cc.cwnd() - before;
        if grew < u32::from(MSS) {
            break Some(before);
        }
        if f.tcb.cc.cwnd() >= limit {
            break None;
        }
        send(&mut f, at, &mut acks);
    };
    let exit = exit.expect("slow start ran on to 2·(BDP + queue)");
    assert!(
        exit < (BDP + QUEUE) * u32::from(MSS),
        "left slow start at cwnd {exit}"
    );
    assert!(max_queue < QUEUE, "queue reached {max_queue}");
}

#[test]
fn initial_window_is_rfc5681() {
    // The default CC (CUBIC) takes RFC 5681 IW: 3 segments for SMSS 1460, 4 for 1000, 2 for
    // 2200.
    for (mtu, mss, segs) in [(1500, 1460, 3), (1500, 1000, 4), (9000, 2200, 2)] {
        let cfg = ConnectConfig {
            mtu,
            ..ConnectConfig::default()
        };
        let mut f = Fixture::new(cfg, v4());
        f.synack(BIG, &opts(Some(mss), Some(0)));
        f.write(&pattern(10 * mss as usize));
        let sent = f.drain(t(0));
        assert_eq!(
            seq_lens(&sent),
            (0..segs)
                .map(|i| (data(i * u32::from(mss)), u32::from(mss)))
                .collect::<Vec<_>>(),
            "SMSS {mss}"
        );
    }
    // The SYN was retransmitted: one segment (RFC 5681 §3.1).
    let mut f = Fixture::new(ConnectConfig::default(), v4());
    f.send(t(0)).unwrap();
    assert_eq!(f.timeout(t(1)), Reaction::None);
    f.send(t(1)).unwrap();
    f.recv(
        TcpFlags::SYN | TcpFlags::ACK,
        ISN.wrapping_add(1),
        BIG,
        &opts(Some(1460), Some(0)),
    );
    f.write(&pattern(10 * 1460));
    assert_eq!(seq_lens(&f.drain(t(1))), [(data(0), 1460)]);
}

#[test]
fn three_dupacks_fast_retransmit() {
    let bytes = pattern(20 * MSS as usize);
    let mut f = Fixture::reno_ramp(&bytes);
    // Segment 3 is lost; 4–9 arrive and each draws a duplicate ACK.
    f.dup_acks_quiet(tm(40), data(3000), 2);
    assert_eq!(f.ack(tm(41), data(3000), BIG), Reaction::None);
    let segs = f.drain(tm(41));
    assert_eq!(seq_lens(&segs), [(data(3000), 1000)], "fast retransmit");
    assert_eq!(segs[0].1, bytes[3000..4000]);
    // ssthresh = FlightSize / 2 = 3500, cwnd = ssthresh + 3·SMSS; no RTT sample from it.
    assert_eq!(f.tcb.cc.cwnd(), 6500);
    assert_eq!(f.tcb.rtt_timed, None);
    // The nominal timer stays put, but this segment cannot time out until one RTO after
    // its fast retransmission.
    assert_eq!(f.tcb.rto_at, Some(tm(1030)));
    assert_eq!(f.tcb.poll_send_at(), Some(tm(1041)));
    // Each further duplicate ACK inflates cwnd by SMSS; new data goes out once it fits.
    f.dup_acks_quiet(tm(42), data(3000), 1);
    assert_eq!(f.tcb.cc.cwnd(), 7500);
    f.ack(tm(43), data(3000), BIG);
    assert_eq!(seq_lens(&f.drain(tm(43))), [(data(10_000), 1000)]);
    f.ack(tm(44), data(3000), BIG);
    assert_eq!(seq_lens(&f.drain(tm(44))), [(data(11_000), 1000)]);
    // The retransmission fills the hole: a full ACK (>= recover) ends recovery with
    // cwnd = min(ssthresh, FlightSize + SMSS) = min(3500, 2000 + 1000).
    assert_eq!(f.ack(tm(60), data(10_000), BIG), Reaction::None);
    assert_eq!(f.tcb.cc.cwnd(), 3000);
    assert_eq!(seq_lens(&f.drain(tm(60))), [(data(12_000), 1000)]);
    // Out of recovery: duplicate ACKs count from zero again.
    f.dup_acks_quiet(tm(70), data(10_000), 2);
}

#[test]
fn rto_waits_for_fast_retransmission() {
    let mut f = Fixture::reno_ramp(&pattern(20 * MSS as usize));
    f.dup_acks_quiet(tm(990), data(3000), 2);
    f.ack(tm(1000), data(3000), BIG);
    assert_eq!(seq_lens(&f.drain(tm(1000))), [(data(3000), 1000)]);
    assert_eq!(f.tcb.poll_send_at(), Some(tm(2000)));

    // The old deadline must neither retransmit nor back off RTO or cwnd.
    assert_eq!(f.timeout(tm(1030)), Reaction::None);
    assert!(f.drain(tm(1030)).is_empty());
    assert_eq!(f.tcb.rtt.rto(), INITIAL_RTO);
    assert_eq!(f.tcb.cc.cwnd(), 6500);

    // Other timers still run while the retransmitted segment is awaiting its RTO.
    f.seg_ack(tm(1100), 0, data(3000), TcpFlags::ACK, &[9; 10]);
    assert_eq!(f.tcb.poll_send_at(), Some(tm(1300)));
    assert_eq!(f.timeout(tm(1300)), Reaction::None);
    assert_eq!(seq_lens(&f.drain(tm(1300))), [(data(10_000), 0)]);
    assert_eq!(f.tcb.poll_send_at(), Some(tm(2000)));

    assert_eq!(f.timeout(tm(2000)), Reaction::None);
    assert_eq!(seq_lens(&f.drain(tm(2000))), [(data(3000), 1000)]);
    assert_eq!(f.tcb.rtt.rto(), 2 * INITIAL_RTO);
    assert_eq!(f.tcb.cc.cwnd(), 1000);
    assert_eq!(f.tcb.poll_send_at(), Some(tm(4000)));
}

#[test]
fn partial_ack_retransmission_has_its_own_rto_deadline() {
    let mut f = Fixture::reno_ramp(&pattern(20 * MSS as usize));
    f.dup_acks_quiet(tm(40), data(3000), 2);
    f.ack(tm(41), data(3000), BIG);
    f.drain(tm(41));
    f.dup_acks_quiet(tm(42), data(3000), 1);

    f.ack(tm(100), data(6000), BIG);
    f.drain(tm(100));
    f.ack(tm(1000), data(8000), BIG);
    assert_eq!(
        seq_lens(&f.drain(tm(1000))),
        [(data(8000), 1000), (data(11_000), 1000)]
    );
    // NewReno restarts the nominal timer on the first partial ACK only.
    assert_eq!(f.tcb.rto_at, Some(tm(1100)));
    assert_eq!(f.tcb.poll_send_at(), Some(tm(2000)));
    assert_eq!(f.timeout(tm(1100)), Reaction::None);
    assert!(f.drain(tm(1100)).is_empty());
    assert_eq!(f.tcb.cc.cwnd(), 4500);
    assert_eq!(f.tcb.rtt.rto(), INITIAL_RTO);
    assert_eq!(f.timeout(tm(2000)), Reaction::None);
    assert_eq!(seq_lens(&f.drain(tm(2000))), [(data(8000), 1000)]);
}

#[test]
fn acknowledged_retransmission_does_not_delay_later_data_across_wrap() {
    let cfg = ConnectConfig::default();
    let isn = SeqNum(u32::MAX - 500);
    let start = isn.wrapping_add(1);
    let mut f = Fixture::unbounded(cfg.clone());
    f.tcb = Tcb::with_cc(&cfg, f.addrs.0, f.addrs.1, isn, t(0), Box::new(Unbounded));
    f.send(t(0)).unwrap();
    assert_eq!(
        f.recv(
            TcpFlags::SYN | TcpFlags::ACK,
            start,
            BIG,
            &opts(Some(MSS), Some(0))
        ),
        Reaction::Established
    );
    f.drain(t(0));
    f.write(&pattern(2000));
    assert_eq!(f.drain(t(0)).len(), 2);
    f.dup_acks_quiet(tm(990), start, 2);
    f.ack(tm(1000), start, BIG);
    assert_eq!(seq_lens(&f.drain(tm(1000))), [(start, 1000)]);
    assert_eq!(f.tcb.poll_send_at(), Some(tm(2000)));

    // ACKing the retransmission releases its deadline even though its end wrapped.
    f.ack(tm(1010), start.wrapping_add(2000), BIG);
    assert_eq!(f.tcb.rto_not_before, None);
    assert_eq!(f.tcb.poll_send_at(), None);
    f.write(&pattern(500));
    assert_eq!(
        seq_lens(&f.drain(tm(1010))),
        [(start.wrapping_add(2000), 500)]
    );
    assert_eq!(f.tcb.poll_send_at(), Some(tm(2010)));
}

#[test]
fn newreno_partial_ack_retransmits_next_hole() {
    let bytes = pattern(20 * MSS as usize);
    let mut f = Fixture::reno_ramp(&bytes);
    // Segments 3, 6 and 8 are lost: 4, 5, 7 and 9 draw four duplicate ACKs.
    f.dup_acks_quiet(tm(40), data(3000), 2);
    f.ack(tm(41), data(3000), BIG);
    assert_eq!(seq_lens(&f.drain(tm(41))), [(data(3000), 1000)]);
    f.dup_acks_quiet(tm(42), data(3000), 1);
    assert_eq!(f.tcb.cc.cwnd(), 7500);
    // The retransmitted 3 arrives: partial ACK up to the next hole, which is retransmitted at
    // once. cwnd = 7500 − 3000 + SMSS = 5500 also lets one new segment go.
    assert_eq!(f.ack(tm(100), data(6000), BIG), Reaction::None);
    let segs = f.drain(tm(100));
    assert_eq!(seq_lens(&segs), [(data(6000), 1000), (data(10_000), 1000)]);
    assert_eq!(segs[0].1, bytes[6000..7000]);
    assert_eq!(f.tcb.cc.cwnd(), 5500);
    // The first partial ACK restarts the retransmission timer.
    assert_eq!(f.tcb.poll_send_at(), Some(tm(1100)));
    // Second partial ACK: the third hole; cwnd = 5500 − 2000 + SMSS. The nominal timer is
    // not restarted, but a timeout cannot retry this segment before its own RTO elapses.
    assert_eq!(f.ack(tm(200), data(8000), BIG), Reaction::None);
    let segs = f.drain(tm(200));
    assert_eq!(seq_lens(&segs), [(data(8000), 1000), (data(11_000), 1000)]);
    assert_eq!(segs[0].1, bytes[8000..9000]);
    assert_eq!(f.tcb.cc.cwnd(), 4500);
    assert_eq!(f.tcb.rto_at, Some(tm(1100)));
    assert_eq!(f.tcb.poll_send_at(), Some(tm(1200)));
    // Everything arrives: full ACK, nothing outstanding, cwnd = min(3500, SMSS + SMSS).
    assert_eq!(f.ack(tm(300), data(12_000), BIG), Reaction::None);
    assert_eq!(f.tcb.cc.cwnd(), 2000);
    assert_eq!(
        seq_lens(&f.drain(tm(300))),
        [(data(12_000), 1000), (data(13_000), 1000)]
    );
}

#[test]
fn rto_go_back_resends_window_without_rto_each() {
    let bytes = pattern(20 * MSS as usize);
    let mut f = Fixture::reno_ramp(&bytes);
    // 3–5 arrived and 6–9 were lost, and every ACK since 30 ms was lost too.
    assert_eq!(f.timeout(tm(1030)), Reaction::None);
    // Loss window: one segment, SND.UNA's.
    let segs = f.drain(tm(1030));
    assert_eq!(seq_lens(&segs), [(data(3000), 1000)]);
    assert_eq!(segs[0].1, bytes[3000..4000]);
    assert_eq!(f.tcb.cc.cwnd(), 1000);
    assert_eq!(f.tcb.snd_nxt, data(4000));
    // A pure ACK sent meanwhile carries SEQ = SND.MAX, not the pulled-back SND.NXT.
    f.seg_ack(tm(1050), 500, data(3000), TcpFlags::ACK, &[1; 10]);
    let acks = f.drain(tm(1050));
    assert_eq!(
        seq_lens(&acks),
        [(data(10_000), 0)],
        "out-of-order data: immediate ACK"
    );
    // The ACK covers data beyond SND.NXT (but within SND.MAX): acceptable, SND.NXT follows.
    assert_eq!(f.ack(tm(1100), data(6000), BIG), Reaction::None);
    assert_eq!(f.tcb.snd_una, data(6000));
    // Slow start resends the rest of the window, ACK-clocked, without another RTO.
    let segs = f.drain(tm(1100));
    assert_eq!(seq_lens(&segs), [(data(6000), 1000), (data(7000), 1000)]);
    assert_eq!(f.ack(tm(1200), data(7000), BIG), Reaction::None);
    let segs = f.drain(tm(1200));
    assert_eq!(seq_lens(&segs), [(data(8000), 1000), (data(9000), 1000)]);
    let resent: Vec<u8> = segs.into_iter().flat_map(|(_, p)| p).collect();
    assert_eq!(resent, bytes[8000..10_000]);
    // Resent segments are never timed (Karn).
    assert_eq!(f.tcb.rtt_timed, None);
    // Past SND.MAX: new data, timed again.
    assert_eq!(f.ack(tm(1300), data(8000), BIG), Reaction::None);
    assert_eq!(f.tcb.cc.cwnd(), 4000);
    let segs = f.drain(tm(1300));
    assert_eq!(
        seq_lens(&segs),
        [(data(10_000), 1000), (data(11_000), 1000)]
    );
    assert_eq!(f.tcb.snd_max, data(12_000));
    assert_eq!(f.tcb.rtt_timed, Some((data(11_000), tm(1300))));
    assert!(
        f.tcb.poll_send_at().unwrap() > tm(3000),
        "no RTO pending soon"
    );
}

#[test]
fn dupacks_below_recover_after_rto_do_not_fast_retransmit() {
    let mut f = Fixture::reno_ramp(&pattern(20 * MSS as usize));
    assert_eq!(f.timeout(tm(1030)), Reaction::None);
    assert_eq!(seq_lens(&f.drain(tm(1030))), [(data(3000), 1000)]);
    assert_eq!(f.ack(tm(1100), data(4000), BIG), Reaction::None);
    assert_eq!(
        seq_lens(&f.drain(tm(1100))),
        [(data(4000), 1000), (data(5000), 1000)]
    );
    // Three duplicate ACKs that do not cover more than recover (SND.MAX − 1 at the RTO):
    // no fast retransmit, no window change (RFC 6582 §4); the RTO stays the backup.
    f.dup_acks_quiet(tm(1150), data(4000), 4);
    assert_eq!(f.tcb.cc.cwnd(), 2000);
    assert_eq!(f.tcb.poll_send_at(), Some(tm(3100)));
}

#[test]
fn data_or_window_change_is_not_dupack() {
    let mut f = Fixture::reno_ramp(&pattern(20 * MSS as usize));
    let peer = PEER_ISN.wrapping_add(1);
    f.dup_acks_quiet(tm(40), data(3000), 1);
    // A segment carrying data (b) is not a duplicate ACK.
    let seg = Segment {
        src: f.addrs.1,
        dst: f.addrs.0,
        seq: peer,
        ack: data(3000),
        flags: TcpFlags::ACK,
        wnd: BIG,
        options: &[],
        payload: &[9; 100],
    };
    assert_eq!(f.tcb.on_segment(&seg, tm(41), &mut f.h), Reaction::None);
    assert!(f.drain(tm(41)).is_empty(), "delayed ACK only");
    // Nor is one whose window differs from the last ACK's (e); the next with that same window
    // is.
    let peer = peer.wrapping_add(100);
    for (at, wnd) in [(42, 60_000), (43, 60_000)] {
        assert_eq!(f.ack_seq(tm(at), peer, data(3000), wnd), Reaction::None);
        assert!(f.drain(tm(at)).iter().all(|(m, _)| m.len == 0));
    }
    assert_eq!(f.tcb.snd_wnd, 60_000);
    // Only two duplicates so far: the third triggers the fast retransmit.
    assert_eq!(f.ack_seq(tm(44), peer, data(3000), 60_000), Reaction::None);
    let segs = f.drain(tm(44));
    assert_eq!(
        segs.iter()
            .find(|(m, _)| m.len > 0)
            .map(|(m, _)| (m.seq, m.len)),
        Some((data(3000), 1000))
    );
}

// ---- Close and reset (Task 10) ----

const FIN_ACK: TcpFlags = TcpFlags(TcpFlags::FIN.0 | TcpFlags::ACK.0);
const PSH_FIN_ACK: TcpFlags = TcpFlags(TcpFlags::PSH.0 | TcpFlags::FIN.0 | TcpFlags::ACK.0);
const NORMAL: Reaction = Reaction::Closed(CloseReason::Normal);
const RESET: Reaction = Reaction::Closed(CloseReason::Reset);

fn flagged(segs: &[(SentMeta, Vec<u8>)]) -> Vec<(SeqNum, u32, TcpFlags)> {
    segs.iter().map(|(m, _)| (m.seq, m.len, m.flags)).collect()
}

fn payloads(segs: &[(SentMeta, Vec<u8>)]) -> Vec<u8> {
    segs.iter().flat_map(|(_, p)| p.clone()).collect()
}

#[test]
fn fin_outside_window_is_trimmed() {
    for len in [1000, 1001] {
        let cfg = ConnectConfig {
            recv_buffer: 1000,
            ..ConnectConfig::default()
        };
        let mut f = Fixture::established(cfg, 10 * MSS);
        let bytes = vec![3; len];
        f.seg_ack(t(0), 0, data(0), FIN_ACK, &bytes);
        assert!(
            !f.tcb.fin_received(),
            "FIN lies outside the advertised window"
        );
        assert_eq!(f.tcb.state(), TcpState::Established);
        assert_eq!(f.acks(t(0)), [(pdata(1000), 0)]);
        assert_eq!(f.read_all(), bytes[..1000]);

        // Once a read reopens the window, the trimmed suffix and FIN are retransmitted.
        assert_eq!(f.acks(t(1)), [(pdata(1000), 1000)]);
        f.seg_ack(t(1), 1000, data(0), FIN_ACK, &bytes[1000..]);
        assert!(f.tcb.fin_received());
        assert_eq!(f.tcb.state(), TcpState::CloseWait);
        assert_eq!(f.read_all(), bytes[1000..]);
        assert_eq!(f.ack_nos(t(1)), [pdata(len as u32 + 1)]);
    }
}

#[test]
fn fin_at_last_sequence_number_in_window_is_accepted() {
    let cfg = ConnectConfig {
        recv_buffer: 1000,
        ..ConnectConfig::default()
    };
    let mut f = Fixture::established(cfg, 10 * MSS);
    f.seg_ack(t(0), 0, data(0), FIN_ACK, &[3; 999]);
    assert!(f.tcb.fin_received());
    assert_eq!(f.tcb.state(), TcpState::CloseWait);
    assert_eq!(f.ack_nos(t(0)), [pdata(1000)]);
    assert_eq!(f.read_all(), [3; 999]);
}

impl Fixture {
    /// ESTABLISHED, `close()` with nothing queued, the FIN sent at t(0) and ACKed at 10 ms.
    fn fin_wait_2() -> Self {
        let mut f = Fixture::established(ConnectConfig::default(), 10 * MSS);
        f.tcb.close();
        assert_eq!(flagged(&f.drain(t(0))), [(data(0), 0, FIN_ACK)]);
        assert_eq!(f.ack(tm(10), data(1), 10 * MSS), Reaction::None);
        assert_eq!(f.tcb.state(), TcpState::FinWait2);
        f
    }
}

#[test]
fn active_close_fin_after_data() {
    let bytes = pattern(3 * MSS as usize);
    let mut f = Fixture::established(ConnectConfig::default(), 10 * MSS);
    f.write(&bytes);
    f.tcb.close();
    assert_eq!(f.tcb.state(), TcpState::FinWait1);
    // The FIN rides on the last data segment when the window has room for it.
    let sent = f.drain(t(0));
    assert_eq!(
        flagged(&sent),
        [
            (data(0), 1000, TcpFlags::ACK),
            (data(1000), 1000, TcpFlags::ACK),
            (data(2000), 1000, PSH_FIN_ACK)
        ]
    );
    assert_eq!(payloads(&sent), bytes);
    assert_eq!(f.tcb.snd_max, data(3001));
    // A second close does nothing: no second FIN.
    f.tcb.close();
    assert_eq!(f.tcb.state(), TcpState::FinWait1);
    assert!(f.drain(t(0)).is_empty());

    // The data fills the window exactly: the FIN follows alone once the window moves.
    let mut f = Fixture::established(ConnectConfig::default(), 3 * MSS);
    f.write(&bytes);
    f.tcb.close();
    assert_eq!(
        flagged(&f.drain(t(0))),
        [
            (data(0), 1000, TcpFlags::ACK),
            (data(1000), 1000, TcpFlags::ACK),
            (data(2000), 1000, PSH_ACK)
        ]
    );
    assert_eq!(f.ack(tm(100), data(3000), 3 * MSS), Reaction::None);
    assert_eq!(flagged(&f.drain(tm(100))), [(data(3000), 0, FIN_ACK)]);
    assert_eq!(f.tcb.state(), TcpState::FinWait1);
}

#[test]
fn fin_resent_by_rto_go_back_and_alone() {
    let bytes = pattern(2500);
    let mut f = Fixture::established(ConnectConfig::default(), 10 * MSS);
    f.tcb.set_nodelay(true);
    f.write(&bytes);
    f.tcb.close();
    let first = f.drain(t(0));
    assert_eq!(
        flagged(&first),
        [
            (data(0), 1000, TcpFlags::ACK),
            (data(1000), 1000, TcpFlags::ACK),
            (data(2000), 500, PSH_FIN_ACK)
        ]
    );
    // RTO: SND.UNA's segment, then the go-back resends the rest, the FIN on the last again.
    assert_eq!(f.timeout(t(1)), Reaction::None);
    let resent = f.drain(t(1));
    assert_eq!(flagged(&resent), flagged(&first));
    assert_eq!(payloads(&resent), bytes);
    // The segment at SND.UNA carries the FIN.
    assert_eq!(f.ack(tm(1100), data(2000), 10 * MSS), Reaction::None);
    let at = f.tcb.poll_send_at().unwrap();
    assert_eq!(f.timeout(at), Reaction::None);
    assert_eq!(flagged(&f.drain(at)), [(data(2000), 500, PSH_FIN_ACK)]);
    // Only the FIN is outstanding: it is resent alone.
    assert_eq!(f.ack(at, data(2500), 10 * MSS), Reaction::None);
    let at = f.tcb.poll_send_at().unwrap();
    assert_eq!(f.timeout(at), Reaction::None);
    assert_eq!(flagged(&f.drain(at)), [(data(2500), 0, FIN_ACK)]);
    // Its ACK: FIN-WAIT-2, nothing outstanding, no timer.
    assert_eq!(f.ack(at, data(2501), 10 * MSS), Reaction::None);
    assert_eq!(f.tcb.state(), TcpState::FinWait2);
    assert_eq!(f.tcb.in_flight(), 0);
    assert_eq!(f.tcb.poll_send_at(), None);
}

#[test]
fn fin_resent_by_partial_ack() {
    let cfg = ConnectConfig::default();
    let h = PlainHooks::new(&cfg);
    let mut f = Fixture::with(cfg, Box::new(Reno::new()), h);
    f.establish(BIG);
    f.write(&pattern(8 * MSS as usize));
    f.tcb.close();
    assert_eq!(f.drain(t(0)).len(), 4, "IW");
    f.ack(tm(10), data(1000), BIG);
    assert_eq!(f.drain(tm(10)).len(), 2);
    // Segment 7 fills the usable window exactly: no room for the FIN on it.
    f.ack(tm(20), data(2000), BIG);
    assert_eq!(
        flagged(&f.drain(tm(20))),
        [
            (data(6000), 1000, TcpFlags::ACK),
            (data(7000), 1000, PSH_ACK)
        ]
    );
    f.ack(tm(30), data(3000), BIG);
    assert_eq!(flagged(&f.drain(tm(30))), [(data(8000), 0, FIN_ACK)]);
    // Segment 3 and the FIN are lost; 4–7 draw duplicate ACKs.
    f.dup_acks_quiet(tm(40), data(3000), 2);
    f.ack(tm(41), data(3000), BIG);
    assert_eq!(seq_lens(&f.drain(tm(41))), [(data(3000), 1000)]);
    f.dup_acks_quiet(tm(42), data(3000), 1);
    // The partial ACK (below recover = the FIN) resends the FIN alone.
    assert_eq!(f.ack(tm(100), data(8000), BIG), Reaction::None);
    assert_eq!(flagged(&f.drain(tm(100))), [(data(8000), 0, FIN_ACK)]);
    assert_eq!(f.ack(tm(200), data(8001), BIG), Reaction::None);
    assert_eq!(f.tcb.state(), TcpState::FinWait2);
}

#[test]
fn peer_fin_is_not_a_duplicate_ack() {
    let mut f = Fixture::reno_ramp(&pattern(20 * MSS as usize));
    let peer = PEER_ISN.wrapping_add(1);
    f.dup_acks_quiet(tm(40), data(3000), 2);
    // A FIN with SEG.ACK = SND.UNA and the same window (RFC 5681 §2 (c)): only its ACK goes out.
    let fin = Segment {
        src: f.addrs.1,
        dst: f.addrs.0,
        seq: peer,
        ack: data(3000),
        flags: FIN_ACK,
        wnd: BIG,
        options: &[],
        payload: &[],
    };
    assert_eq!(f.tcb.on_segment(&fin, tm(41), &mut f.h), Reaction::None);
    assert_eq!(f.tcb.state(), TcpState::CloseWait);
    assert_eq!(seq_lens(&f.drain(tm(41))), [(data(10_000), 0)]);
    // The next duplicate is the third.
    f.ack_seq(tm(42), peer.wrapping_add(1), data(3000), BIG);
    assert_eq!(seq_lens(&f.drain(tm(42))), [(data(3000), 1000)]);
}

#[test]
fn active_close_reaches_time_wait_then_frees() {
    let mut f = Fixture::fin_wait_2();
    assert_eq!(f.tcb.poll_send_at(), None);
    // Half-closed: the peer's data is still received.
    f.data_in(tm(200), 0, &pattern(100));
    assert_eq!(f.read_all(), pattern(100));
    assert!(!f.tcb.fin_received());
    // The peer's FIN: TIME-WAIT, reported once, ACKed at once.
    assert_eq!(f.seg_in(t(1), 100, FIN_ACK, &[]), NORMAL);
    assert_eq!(f.tcb.state(), TcpState::TimeWait);
    assert!(f.tcb.fin_received());
    assert_eq!(f.ack_nos(t(1)), vec![pdata(101)]);
    // 2·MSL = 120 s.
    assert_eq!(f.tcb.poll_send_at(), Some(t(121)));
    assert_eq!(f.timeout(t(120)), Reaction::None);
    assert_eq!(f.tcb.state(), TcpState::TimeWait);
    assert_eq!(f.timeout(t(121)), Reaction::None);
    assert_eq!(f.tcb.state(), TcpState::Closed);
    assert_eq!(f.tcb.poll_send_at(), Some(t(121)));
    // Nothing more is reported or sent.
    assert_eq!(f.seg_in(t(122), 100, FIN_ACK, &[]), Reaction::None);
    assert_eq!(f.timeout(t(500)), Reaction::None);
    assert_eq!(f.send(t(500)), None);
}

#[test]
fn fin_ack_in_one_segment_from_fin_wait_1() {
    let mut f = Fixture::established(ConnectConfig::default(), 10 * MSS);
    f.write(&pattern(500));
    f.tcb.close();
    assert_eq!(flagged(&f.drain(t(0))), [(data(0), 500, PSH_FIN_ACK)]);
    // What Linux sends when its close() follows our EOF: its data and FIN, ACKing our FIN.
    let p = pattern(300);
    assert_eq!(f.seg_ack(tm(50), 0, data(501), FIN_ACK, &p), NORMAL);
    assert_eq!(f.tcb.state(), TcpState::TimeWait);
    assert_eq!(f.read_all(), p);
    assert!(f.tcb.fin_received());
    assert_eq!(f.ack_nos(tm(50)), vec![pdata(301)]);
    assert_eq!(f.tcb.poll_send_at(), Some(tm(120_050)));
    // Its retransmission is ACKed; nothing is reported or delivered again.
    assert_eq!(f.seg_ack(tm(60), 0, data(501), FIN_ACK, &p), Reaction::None);
    assert_eq!(f.ack_nos(tm(60)), vec![pdata(301)]);
    assert!(f.read_all().is_empty());
}

#[test]
fn time_wait_acks_retransmitted_fin_and_restarts() {
    let mut f = Fixture::fin_wait_2();
    assert_eq!(f.seg_in(t(1), 0, FIN_ACK, &[]), NORMAL);
    assert_eq!(f.ack_nos(t(1)), vec![pdata(1)]);
    assert_eq!(f.tcb.poll_send_at(), Some(t(121)));
    // The FIN again at +60 s: ACKed, 2·MSL restarts.
    assert_eq!(f.seg_in(t(61), 0, FIN_ACK, &[]), Reaction::None);
    assert_eq!(f.ack_nos(t(61)), vec![pdata(1)]);
    assert_eq!(f.tcb.poll_send_at(), Some(t(181)));
    assert_eq!(f.timeout(t(121)), Reaction::None);
    assert_eq!(f.tcb.state(), TcpState::TimeWait);
    // Other segments: data after the FIN is not delivered and draws nothing; a SYN draws a
    // challenge ACK; an unacceptable segment draws an ACK. None restarts the timer.
    f.data_in(t(130), 1, &[1; 10]);
    assert!(f.acks(t(130)).is_empty());
    assert!(f.read_all().is_empty());
    f.seg_in(t(131), 1, TcpFlags::SYN | TcpFlags::ACK, &[]);
    assert_eq!(f.ack_nos(t(131)), vec![pdata(1)]);
    f.data_in(t(132), 8 << 20, &[1; 10]);
    assert_eq!(f.ack_nos(t(132)), vec![pdata(1)]);
    assert_eq!(f.tcb.poll_send_at(), Some(t(181)));
    assert_eq!(f.timeout(t(180)), Reaction::None);
    assert_eq!(f.tcb.state(), TcpState::TimeWait);
    assert_eq!(f.timeout(t(181)), Reaction::None);
    assert_eq!(f.tcb.state(), TcpState::Closed);
}

#[test]
fn closing_emits_closed_once() {
    let mut f = Fixture::established(ConnectConfig::default(), 10 * MSS);
    f.tcb.close();
    assert_eq!(flagged(&f.drain(t(0))), [(data(0), 0, FIN_ACK)]);
    // The peer's FIN crosses ours (it does not ACK ours): CLOSING, ACKed at once.
    assert_eq!(f.seg_ack(tm(10), 0, data(0), FIN_ACK, &[]), Reaction::None);
    assert_eq!(f.tcb.state(), TcpState::Closing);
    assert_eq!(f.ack_nos(tm(10)), vec![pdata(1)]);
    // The ACK of our FIN: TIME-WAIT, reported once.
    assert_eq!(f.seg_ack(tm(20), 1, data(1), TcpFlags::ACK, &[]), NORMAL);
    assert_eq!(f.tcb.state(), TcpState::TimeWait);
    assert_eq!(f.tcb.poll_send_at(), Some(tm(120_020)));
    assert_eq!(
        f.seg_ack(tm(30), 1, data(1), TcpFlags::ACK, &[]),
        Reaction::None
    );
    assert!(f.acks(tm(30)).is_empty());
    // The peer's FIN arrives after close() but before our FIN went out: CLOSING, and our FIN
    // still goes (with the ACK of theirs).
    let mut f = Fixture::established(ConnectConfig::default(), 10 * MSS);
    f.tcb.close();
    assert_eq!(f.seg_ack(tm(10), 0, data(0), FIN_ACK, &[]), Reaction::None);
    assert_eq!(f.tcb.state(), TcpState::Closing);
    assert_eq!(flagged(&f.drain(tm(10))), [(data(0), 0, FIN_ACK)]);
    assert_eq!(f.out.ack, pdata(1));
    assert_eq!(f.seg_ack(tm(20), 1, data(1), TcpFlags::ACK, &[]), NORMAL);
}

#[test]
fn passive_close_close_wait_last_ack() {
    let mut f = Fixture::established(ConnectConfig::default(), 10 * MSS);
    let p = pattern(500);
    f.data_in(t(0), 0, &p);
    assert!(!f.tcb.fin_received());
    // The peer's FIN: CLOSE-WAIT, ACKed at once.
    assert_eq!(f.seg_in(tm(10), 500, FIN_ACK, &[]), Reaction::None);
    assert_eq!(f.tcb.state(), TcpState::CloseWait);
    assert!(f.tcb.fin_received());
    assert_eq!(f.ack_nos(tm(10)), vec![pdata(501)]);
    // A retransmitted FIN (it starts at 500) is only ACKed: RCV.NXT stays.
    assert_eq!(f.seg_in(tm(15), 500, FIN_ACK, &[]), Reaction::None);
    assert_eq!(f.ack_nos(tm(15)), vec![pdata(501)]);
    // The data, then EOF: nothing to read and the FIN received.
    assert_eq!(f.read_all(), p);
    assert_eq!(f.h.read(&mut [0; 16]), 0);
    // Data after the peer's FIN is not delivered.
    f.data_in(tm(20), 501, &[1; 10]);
    assert!(f.acks(tm(20)).is_empty());
    assert!(f.read_all().is_empty());
    // We still send; close: LAST-ACK, the FIN after the queued data.
    f.write(&pattern(300));
    f.tcb.close();
    assert_eq!(f.tcb.state(), TcpState::LastAck);
    assert_eq!(flagged(&f.drain(tm(30))), [(data(0), 300, PSH_FIN_ACK)]);
    assert_eq!(
        f.seg_ack(tm(40), 501, data(300), TcpFlags::ACK, &[]),
        Reaction::None
    );
    assert_eq!(f.tcb.state(), TcpState::LastAck);
    assert_eq!(
        f.seg_ack(tm(50), 501, data(301), TcpFlags::ACK, &[]),
        NORMAL
    );
    assert_eq!(f.tcb.state(), TcpState::Closed);
    assert_eq!(f.tcb.poll_send_at(), Some(tm(50)));
    assert_eq!(
        f.seg_ack(tm(60), 501, data(301), TcpFlags::ACK, &[]),
        Reaction::None
    );
    assert_eq!(f.timeout(t(500)), Reaction::None);
    assert_eq!(f.send(t(500)), None);
}

#[test]
fn simultaneous_close_closing() {
    let cfg = ConnectConfig::default();
    let (la, lb) = v4();
    let (isn_a, isn_b) = (SeqNum(0x1000), SeqNum(0x9000));
    let mut a = Tcb::new_established(&cfg, la, lb, isn_a, isn_b, Some(1460), Some(7), t(0));
    let mut b = Tcb::new_established(&cfg, lb, la, isn_b, isn_a, Some(1460), Some(7), t(0));
    let (mut ha, mut hb) = (PlainHooks::new(&cfg), PlainHooks::new(&cfg));
    let mut out = SegmentWriter::default();
    for w in emit(&mut a, &mut ha, &mut out, t(0)) {
        deliver(&mut b, &mut hb, &w, t(0));
    }
    for w in emit(&mut b, &mut hb, &mut out, t(0)) {
        deliver(&mut a, &mut ha, &w, t(0));
    }
    a.close();
    b.close();
    let (fa, fb) = (
        emit(&mut a, &mut ha, &mut out, t(0)),
        emit(&mut b, &mut hb, &mut out, t(0)),
    );
    assert_eq!((fa.len(), fa[0].flags), (1, FIN_ACK));
    assert_eq!((fb.len(), fb[0].flags), (1, FIN_ACK));
    // The FINs cross: both CLOSING.
    assert_eq!(feed(&mut a, &mut ha, &fb[0], tm(10)), Reaction::None);
    assert_eq!(feed(&mut b, &mut hb, &fa[0], tm(10)), Reaction::None);
    assert_eq!(
        (a.state(), b.state()),
        (TcpState::Closing, TcpState::Closing)
    );
    // Each ACKs the other's FIN: both TIME-WAIT, each reported once.
    let (aa, ab) = (
        emit(&mut a, &mut ha, &mut out, tm(10)),
        emit(&mut b, &mut hb, &mut out, tm(10)),
    );
    assert_eq!((aa.len(), aa[0].flags), (1, TcpFlags::ACK));
    assert_eq!((ab.len(), ab[0].flags), (1, TcpFlags::ACK));
    assert_eq!(feed(&mut a, &mut ha, &ab[0], tm(20)), NORMAL);
    assert_eq!(feed(&mut b, &mut hb, &aa[0], tm(20)), NORMAL);
    assert_eq!(
        (a.state(), b.state()),
        (TcpState::TimeWait, TcpState::TimeWait)
    );
    assert!(emit(&mut a, &mut ha, &mut out, tm(20)).is_empty());
    assert!(emit(&mut b, &mut hb, &mut out, tm(20)).is_empty());
    assert_eq!(a.poll_send_at(), Some(tm(120_020)));
}

#[test]
fn rst_exact_seq_resets() {
    // ESTABLISHED, FIN-WAIT-1 (data and FIN outstanding), CLOSE-WAIT and LAST-ACK.
    for (closed_by_us, fin_from_peer) in
        [(false, false), (true, false), (false, true), (true, true)]
    {
        let mut f = Fixture::established(ConnectConfig::default(), 10 * MSS);
        f.write(&pattern(500));
        let mut off = 0;
        if fin_from_peer {
            f.seg_in(t(0), 0, FIN_ACK, &[]);
            off = 1;
        }
        if closed_by_us {
            f.tcb.close();
        }
        f.drain(t(0));
        let before = f.tcb.state();
        assert_eq!(
            f.seg_in(tm(10), off, TcpFlags::RST, &[]),
            RESET,
            "{before:?}"
        );
        assert_eq!(f.tcb.state(), TcpState::Closed);
        assert_eq!(f.tcb.poll_send_at(), Some(tm(10)));
        assert_eq!(f.send(tm(10)), None);
        // Exactly once.
        assert_eq!(f.seg_in(tm(20), off, TcpFlags::RST, &[]), Reaction::None);
        assert_eq!(f.timeout(t(500)), Reaction::None);
    }
}

#[test]
fn rst_in_window_not_exact_gets_challenge_ack() {
    let mut f = Fixture::established(ConnectConfig::default(), 10 * MSS);
    assert_eq!(
        f.seg_in(t(0), 10, TcpFlags::RST | TcpFlags::ACK, &[]),
        Reaction::None
    );
    // <SEQ=SND.MAX><ACK=RCV.NXT><CTL=ACK>, never more than one.
    assert_eq!(f.acks(t(0)), vec![(pdata(0), 32768)]);
    assert_eq!(f.tcb.state(), TcpState::Established);
    // The exact one still resets.
    assert_eq!(f.seg_in(t(0), 0, TcpFlags::RST, &[]), RESET);
}

#[test]
fn rst_out_of_window_dropped() {
    let mut f = Fixture::established(rx_cfg(2000), 10 * MSS);
    // At the right edge (RCV.NXT + RCV.WND) and below RCV.NXT: no reaction, no output.
    assert_eq!(f.seg_in(t(0), 2000, TcpFlags::RST, &[]), Reaction::None);
    assert_eq!(
        f.recv(TcpFlags::RST | TcpFlags::ACK, data(0), 0, &[]),
        Reaction::None
    );
    assert_eq!(f.send(t(0)), None);
    assert_eq!(f.tcb.state(), TcpState::Established);
}

#[test]
fn rst_in_time_wait_frees_without_second_report() {
    let mut f = Fixture::fin_wait_2();
    assert_eq!(f.seg_in(t(1), 0, FIN_ACK, &[]), NORMAL);
    f.drain(t(1));
    assert_eq!(f.seg_in(t(2), 1, TcpFlags::RST, &[]), Reaction::None);
    assert_eq!(f.tcb.state(), TcpState::Closed);
    assert_eq!(f.tcb.poll_send_at(), Some(t(2)));
    assert_eq!(f.timeout(t(121)), Reaction::None);
}

#[test]
fn zero_window_allowance_bounded_and_takes_rst() {
    let mut f = Fixture::established(rx_cfg(10_000), 10 * MSS);
    let p = pattern(10_000);
    for k in 0..10 {
        f.data_in(t(0), k * 1000, &p[(k * 1000) as usize..][..1000]);
    }
    assert_eq!(f.acks(t(0)).last(), Some(&(pdata(10_000), 0)));
    assert_eq!(f.tcb.rcv_wnd(), 0);
    f.write(&pattern(300));
    assert_eq!(f.drain(t(0)).len(), 1);
    // Beyond the edge and the one octet a probe may have taken: the ACK field is not taken.
    f.seg_ack(t(0), 10_002, data(300), TcpFlags::ACK, &[]);
    assert_eq!(f.tcb.snd_una, data(0));
    assert_eq!(f.acks(t(0)), vec![(pdata(10_000), 0)]);
    // The window is empty: a RST off RCV.NXT is dropped silently; at RCV.NXT, even with text,
    // it resets.
    assert_eq!(f.seg_in(t(0), 10_001, TcpFlags::RST, &[]), Reaction::None);
    assert!(f.acks(t(0)).is_empty());
    assert_eq!(f.seg_in(t(0), 10_000, TcpFlags::RST, &[1, 2, 3]), RESET);
}

#[test]
fn unacked_fin_hits_r2() {
    let mut f = Fixture::established(ConnectConfig::default(), 10 * MSS);
    f.tcb.close();
    assert_eq!(flagged(&f.drain(t(0))), [(data(0), 0, FIN_ACK)]);
    let (sends, closed) = f.run_until_closed();
    assert_eq!(sends, [1, 3, 7, 15, 31, 63].map(t));
    assert_eq!(closed, t(100));
    assert_eq!(f.tcb.state(), TcpState::Closed);
}

#[test]
fn data_written_after_close_is_not_sent() {
    let mut f = Fixture::established(ConnectConfig::default(), 10 * MSS);
    f.write(&pattern(100));
    f.tcb.close();
    assert_eq!(flagged(&f.drain(t(0))), [(data(0), 100, PSH_FIN_ACK)]);
    f.write(&pattern(100));
    assert!(f.drain(t(0)).is_empty());
    assert_eq!(f.ack(tm(10), data(101), 10 * MSS), Reaction::None);
    assert_eq!(f.tcb.state(), TcpState::FinWait2);
    assert!(f.drain(tm(10)).is_empty());
    assert_eq!(f.tcb.poll_send_at(), None);
    // The FIN's ACK released no data octet from the send buffer.
    assert!(f.h.peek_with(101, 1, |_| ()).is_some());
}

#[test]
fn fin_waits_for_a_closed_window_with_probes() {
    let mut f = Fixture::established(ConnectConfig::default(), 0);
    f.tcb.close();
    assert!(f.drain(t(0)).is_empty());
    assert_eq!(f.tcb.poll_send_at(), Some(t(1)));
    assert_eq!(f.timeout(t(1)), Reaction::None);
    assert_eq!(flagged(&f.drain(t(1))), [(ISN, 0, TcpFlags::ACK)]);
    // The window opens: the FIN goes.
    assert_eq!(f.ack(t(2), data(0), 10 * MSS), Reaction::None);
    assert_eq!(flagged(&f.drain(t(2))), [(data(0), 0, FIN_ACK)]);
}

#[test]
fn no_window_update_after_peer_fin() {
    let mut f = Fixture::established(rx_cfg(10_000), 10 * MSS);
    let p = pattern(9000);
    for k in 0..9 {
        f.data_in(t(0), k * 1000, &p[(k * 1000) as usize..][..1000]);
    }
    assert_eq!(f.acks(t(0)).last(), Some(&(pdata(9000), 1000)));
    assert_eq!(f.seg_in(t(0), 9000, FIN_ACK, &[]), Reaction::None);
    assert_eq!(f.ack_nos(t(0)), vec![pdata(9001)]);
    // Reading frees 9000 B, but nothing more can arrive: no window update.
    assert_eq!(f.read_all(), p);
    assert!(f.acks(t(0)).is_empty());
}

#[test]
fn close_in_syn_sent_deletes_tcb() {
    let synack = TcpFlags::SYN | TcpFlags::ACK;
    let mut f = Fixture::new(ConnectConfig::default(), v4());
    f.send(t(0)).unwrap();
    f.tcb.close();
    // Gone at once: nothing more is sent or accepted, and the TCB is due now.
    assert_eq!(f.tcb.state(), TcpState::Closed);
    assert_eq!(f.send(t(0)), None);
    assert!(f.tcb.poll_send_at().unwrap() <= t(0));
    assert_eq!(
        f.recv(synack, ISN.wrapping_add(1), 5000, &[]),
        Reaction::None
    );
    assert_eq!(f.send(t(0)), None);
    // The next timeout reports it, once.
    assert_eq!(f.timeout(tm(5)), NORMAL);
    assert_eq!(f.tcb.poll_send_at(), Some(tm(5)));
    assert_eq!(f.timeout(t(1)), Reaction::None);
    f.tcb.close();
    assert_eq!(f.timeout(t(2)), Reaction::None);

    // Closed before the SYN was ever polled: no SYN goes out.
    let mut f = Fixture::new(ConnectConfig::default(), v4());
    f.tcb.close();
    assert_eq!(f.send(t(0)), None);
    assert_eq!(f.timeout(t(0)), NORMAL);
}

/// RFC 9293 §3.10.7.3: text and FIN carried by the SYN/ACK are processed once ESTABLISHED.
fn synack_with(payload: &[u8], fin: bool) -> Fixture {
    let mut f = Fixture::new(ConnectConfig::default(), v4());
    f.send(t(0)).unwrap();
    let mut flags = TcpFlags::SYN | TcpFlags::ACK;
    if fin {
        flags = flags | TcpFlags::FIN;
    }
    let o = opts(Some(1400), Some(7));
    let seg = Segment {
        src: f.addrs.1,
        dst: f.addrs.0,
        seq: PEER_ISN,
        ack: ISN.wrapping_add(1),
        flags,
        wnd: 5000,
        options: &o,
        payload,
    };
    assert_eq!(
        f.tcb.on_segment(&seg, t(0), &mut f.h),
        Reaction::Established
    );
    f
}

#[test]
fn synack_payload_is_delivered() {
    let mut f = synack_with(&[7; 100], false);
    assert_eq!(f.tcb.state(), TcpState::Established);
    let mut buf = [0u8; 200];
    assert_eq!(f.h.read(&mut buf), 100);
    assert_eq!(buf[..100], [7; 100]);
    f.send(t(0)).unwrap();
    assert_eq!(f.out.ack, PEER_ISN.wrapping_add(101));
}

#[test]
fn synack_fin_closes_receive_side() {
    for payload in [&[][..], &[5u8; 40][..]] {
        let mut f = synack_with(payload, true);
        assert_eq!(f.tcb.state(), TcpState::CloseWait);
        assert!(f.tcb.fin_received());
        assert_eq!(f.h.read(&mut [0u8; 64]), payload.len());
        f.send(t(0)).unwrap();
        assert_eq!(
            f.out.ack,
            PEER_ISN.wrapping_add(2 + payload.len() as u32),
            "ACK covers SYN, data and FIN"
        );
    }
}

/// Reno grown past IW by a 60 kB transfer that is fully acknowledged, at t = 0.5 s. Reno:
/// the restart window is sent at once, which a pacing controller would spread out.
fn grown_idle_fixture() -> Fixture {
    let cfg = ConnectConfig::default();
    let h = PlainHooks::new(&cfg);
    let mut f = Fixture::with(cfg, Box::new(Reno::new()), h);
    assert_eq!(
        f.synack(65535, &opts(Some(MSS), Some(0))),
        Reaction::Established
    );
    f.send(t(0)).unwrap();
    f.write(&pattern(60_000));
    let mut now = t(0);
    while f.tcb.snd_una != ISN.wrapping_add(60_001) {
        assert!(!f.drain(now).is_empty());
        now = now + Duration::from_millis(10);
        let ack = f.tcb.snd_max;
        f.ack(now, ack, 65535);
    }
    assert!(f.tcb.cc.cwnd() > 8 * u32::from(MSS), "cwnd grew");
    f
}

#[test]
fn idle_longer_than_rto_restarts_with_iw() {
    // RFC 5681 §4.1: no data sent for more than the RTO, nothing outstanding.
    let mut f = grown_idle_fixture();
    let later = t(0) + Duration::from_secs(30);
    f.write(&pattern(20_000));
    let sent: u32 = f.drain(later).iter().map(|(m, _)| m.len).sum();
    assert_eq!(sent, 4 * u32::from(MSS), "RW = IW");
}

#[test]
fn idle_shorter_than_rto_keeps_cwnd() {
    let mut f = grown_idle_fixture();
    let cwnd = f.tcb.cc.cwnd();
    let later = t(0) + Duration::from_millis(300);
    assert!(later < t(0) + f.tcb.rtt.rto());
    f.write(&pattern(20_000));
    let sent: u32 = f.drain(later).iter().map(|(m, _)| m.len).sum();
    assert_eq!(sent, 20_000.min(cwnd / u32::from(MSS) * u32::from(MSS)));
    assert!(sent > 4 * u32::from(MSS));
}

#[test]
fn window_update_survives_a_go_back_that_sends_nothing() {
    // After an RTO the go-back path runs with cwnd exhausted and sends nothing; it must not
    // record a window the read just reopened as already advertised.
    let cfg = ConnectConfig {
        recv_buffer: 2000,
        ..ConnectConfig::default()
    };
    let mut f = Fixture::new(cfg, v4());
    assert_eq!(
        f.synack(65535, &opts(Some(MSS), Some(0))),
        Reaction::Established
    );
    f.send(t(0)).unwrap();
    f.write(&pattern(3000));
    assert_eq!(f.drain(t(0)).len(), 3);
    // The peer fills our receive buffer.
    let payload = pattern(2000);
    let seg = Segment {
        src: f.addrs.1,
        dst: f.addrs.0,
        seq: PEER_ISN.wrapping_add(1),
        ack: ISN.wrapping_add(1),
        flags: TcpFlags::ACK,
        wnd: 65535,
        options: &[],
        payload: &payload,
    };
    f.tcb.on_segment(&seg, t(0), &mut f.h);
    f.timeout(tm(250)); // the delayed ACK
    let acks = f.drain(tm(250));
    assert_eq!(acks.last().unwrap().0.flags, TcpFlags::ACK);
    assert_eq!(f.out.wnd, 0, "buffer full");
    // RTO: one retransmission uses up the 1-MSS cwnd.
    let at = f.tcb.poll_send_at().unwrap();
    f.timeout(at);
    assert_eq!(f.send(at).unwrap().len, u32::from(MSS));
    // The go-back pass finds no room; the app then reads everything.
    assert_eq!(f.send(at), None);
    assert_eq!(f.h.read(&mut [0u8; 2000]), 2000);
    let m = f.send(at).expect("window update ACK");
    assert_eq!(m.len, 0);
    assert!(f.out.wnd > 0);
}

#[test]
fn protocol_options_and_sacks_reduce_payload_budget() {
    for mtu in [68, 1500] {
        let cfg = ConnectConfig {
            mtu,
            ..ConnectConfig::default()
        };
        let h = ShortRuns(PlainHooks::new(&cfg), 20);
        let mut f = Fixture::with(cfg, Box::new(Unbounded), h);
        f.establish(10 * MSS);
        f.tcb.sack_permitted = true;
        f.data_in(t(0), 100, &[1; 100]);
        f.h.0.write(&pattern(2000));
        f.send(t(0)).unwrap();
        assert!(!f.out.payload.is_empty());
        assert_eq!(&f.out.options[..20], &[1; 20]);
        assert!(f.out.options_len <= 40);
        assert_eq!(f.out.options_len % 4, 0);
        assert!(40 + f.out.options_len + f.out.payload.len() <= usize::from(mtu));
        assert!(f.out.options_len + f.out.payload.len() <= usize::from(MSS));
        if mtu == 68 {
            assert_eq!(f.out.payload.len(), 8);
            assert!(sack_blocks(&f.out).is_empty());
        } else {
            assert_eq!(sack_blocks(&f.out), vec![(pdata(100), pdata(200))]);
        }
    }
}

#[test]
fn mptcp_receipts_cross_relative_ssn_and_dsn_wrap_with_reordering() {
    use crate::mptcp::{ConnectionHooks, Negotiation, SubflowHooks, SubflowMp};
    use crate::wire::mptcp::{self, CAP_H, Dsn, Dss, Mapping, MpCapable, MptcpOption};
    let cfg = ConnectConfig {
        recv_buffer: 16,
        ..ConnectConfig::default()
    };
    let mut conn = ConnectionHooks::new(&cfg);
    conn.negotiation = Some(Negotiation::new(1));
    let mut sf = SubflowMp::new();
    let h = SubflowHooks {
        conn: &mut conn,
        sf: &mut sf,
    };
    let mut f = Fixture::with(cfg, Box::new(Unbounded), h);
    let mut options = [0; 40];
    let n = mptcp::encode(
        &MptcpOption::Capable(MpCapable {
            version: 1,
            flags: CAP_H,
            sender_key: Some(2),
            receiver_key: None,
            data_len: None,
            checksum: None,
        }),
        &mut options,
    )
    .unwrap();
    assert_eq!(f.synack(100, &options[..n]), Reaction::Established);
    f.send(t(0));
    f.h.conn
        .negotiation
        .as_mut()
        .unwrap()
        .on_transmitted(TcpFlags::ACK);
    f.tcb.rcv_ssn = u64::from(u32::MAX) - 1;
    f.tcb.rcv_nxt = PEER_ISN.wrapping_add(u32::MAX - 1);
    let recv = &mut f.h.conn.data.as_mut().unwrap().recv;
    recv.next = u64::MAX - 1;
    recv.right_edge = 8;
    for (ssn, dsn, data) in [
        (0, 0, b"cd".as_slice()),
        (u32::MAX - 1, u32::MAX - 1, b"ab"),
    ] {
        let n = mptcp::encode(
            &MptcpOption::Dss(Dss {
                data_fin: false,
                data_ack: None,
                mapping: Some(Mapping {
                    ssn,
                    dsn: Dsn::Dsn32(dsn),
                    data_len: 2,
                    checksum: None,
                }),
            }),
            &mut options,
        )
        .unwrap();
        let seg = Segment {
            src: f.addrs.1,
            dst: f.addrs.0,
            seq: PEER_ISN.wrapping_add(ssn),
            ack: ISN.wrapping_add(1),
            flags: TcpFlags::ACK,
            wnd: 100,
            options: &options[..n],
            payload: data,
        };
        f.tcb.on_segment(&seg, t(0), &mut f.h);
        f.send(t(0));
    }
    assert_eq!(f.tcb.rcv_ssn, u64::from(u32::MAX) + 3);
    assert_eq!(f.tcb.rcv_nxt, PEER_ISN.wrapping_add(2));
    assert_eq!(f.h.conn.data.as_ref().unwrap().recv.next, 2);
    let mut out = [0; 4];
    assert_eq!(f.h.conn.read(&mut out), 4);
    assert_eq!(&out, b"abcd");
}

#[test]
fn protocol_options_consuming_mss_preserve_fin_and_persist() {
    for zero in [false, true] {
        let cfg = ConnectConfig::default();
        let h = ShortRuns(PlainHooks::new(&cfg), 28);
        let mut f = Fixture::with(cfg, Box::new(Unbounded), h);
        f.establish(if zero { 0 } else { 1000 });
        f.tcb.eff_mss = 24;
        f.tcb.close();
        if zero {
            assert!(f.send(t(0)).is_none());
            assert!(f.tcb.persist_at.is_some());
            f.tcb.on_timeout(t(1), &mut f.h);
            assert_eq!(f.send(t(1)).unwrap().seq, ISN);
        } else {
            assert!(f.send(t(0)).unwrap().flags.contains(TcpFlags::FIN));
        }
    }
}

#[test]
fn assignment_budget_obeys_nagle_windows_and_reinjection() {
    let mut f = Fixture::established(ConnectConfig::default(), 1500);
    assert_eq!(
        f.tcb.send_budget(t(0), 2000, 2000, false, 28, &f.h).bytes(),
        972
    );
    f.write(&pattern(972));
    f.send(t(0)).unwrap();
    assert_eq!(
        f.tcb.send_budget(t(0), 100, 100, false, 28, &f.h).bytes(),
        0
    );
    assert_eq!(
        f.tcb.send_budget(t(0), 100, 100, true, 28, &f.h).bytes(),
        100
    );
    f.tcb.set_nodelay(true);
    assert_eq!(
        f.tcb.send_budget(t(0), 100, 100, false, 28, &f.h).bytes(),
        100
    );
    assert_eq!(
        f.tcb.send_budget(t(0), 100, 100, false, 1000, &f.h).bytes(),
        0
    );
}

// ---- Pacing gate, release timer and app-limited marking (M2 Task 3b) ----

/// Fixed cwnd and, if `rate` is set, a fixed pacing rate; records every ACK sample.
struct TestCc {
    rate: Option<u64>,
    cwnd: u32,
    samples: Samples,
}
type Samples = Arc<Mutex<Vec<AckSample>>>;

impl CongestionControl for TestCc {
    fn on_ack(&mut self, a: &AckSample) {
        self.samples.lock().unwrap().push(*a);
    }
    fn on_congestion(&mut self, _: CongestionEvent, _: u32, _: Instant) {}
    fn on_recovery_ack(&mut self, _: RecoveryAck) {}
    fn cwnd(&self) -> u32 {
        self.cwnd
    }
    fn pacing_rate(&self) -> Option<u64> {
        self.rate
    }
}

/// Segment payload with peer MSS 1460.
const SEG: u32 = 1460;
/// One segment per 10 ms.
const RATE: u64 = 146_000;
const BIG_CWND: u32 = 64 << 10;

impl Fixture {
    /// ESTABLISHED at t(0) with `TestCc`, peer MSS 1460, shift 0 and window `wnd`.
    fn test_cc(rate: Option<u64>, cwnd: u32, wnd: u16) -> (Self, Samples) {
        let samples = Samples::default();
        let cfg = ConnectConfig::default();
        let h = PlainHooks::new(&cfg);
        let cc = TestCc {
            rate,
            cwnd,
            samples: samples.clone(),
        };
        let mut f = Fixture::with(cfg, Box::new(cc), h);
        assert_eq!(
            f.synack(wnd, &opts(Some(1460), Some(0))),
            Reaction::Established
        );
        assert_eq!(f.send(t(0)).unwrap().flags, TcpFlags::ACK);
        (f, samples)
    }
    fn mark(&mut self, now: Instant, reason: AppLimited) {
        self.tcb.mark_unused_opportunity(now, reason, &self.h);
    }
}

fn flags_of(samples: &Samples) -> Vec<bool> {
    samples
        .lock()
        .unwrap()
        .iter()
        .map(|a| a.app_limited)
        .collect()
}

#[test]
fn pacing_blocks_budget_before_release() {
    let (mut f, _) = Fixture::test_cc(Some(RATE), BIG_CWND, BIG);
    f.write(&pattern(SEG as usize));
    assert_eq!(seq_lens(&f.drain(t(0))), [(data(0), SEG)]);
    let release = tm(10);
    let budget = |f: &Fixture, now, reinject| {
        let n = 10 * SEG as usize;
        f.tcb.send_budget(now, n, n, reinject, 0, &f.h)
    };
    for now in [t(0), tm(5), t(0) + Duration::from_nanos(9_999_999)] {
        assert_eq!(budget(&f, now, false), SendBudget::default(), "{now:?}");
        assert_eq!(budget(&f, now, true), SendBudget::default(), "{now:?}");
    }
    // At the release: one segment, whatever cwnd and the window would allow.
    for reinject in [false, true] {
        let b = budget(&f, release, reinject);
        assert_eq!((b.seg_payload, b.full_segments, b.bytes()), (1460, 1, 1460));
    }
}

#[test]
fn pacing_release_time_in_poll_send_at() {
    let (mut f, _) = Fixture::test_cc(Some(RATE), BIG_CWND, BIG);
    f.write(&pattern(3 * SEG as usize));
    assert_eq!(f.drain(t(0)).len(), 1, "one segment per release");
    // ACKed at once: nothing in flight, no ACK expected, no RTO.
    assert_eq!(f.ack(tm(1), data(SEG), BIG), Reaction::None);
    assert!(f.drain(tm(1)).is_empty());
    assert_eq!(f.tcb.poll_send_at(), Some(tm(10)));
    assert_eq!(seq_lens(&f.drain(tm(10))), [(data(SEG), SEG)]);
    assert_eq!(f.tcb.poll_send_at(), Some(tm(20)));
}

#[test]
fn pacing_deadline_consumed_when_blocked_otherwise() {
    // (a) cwnd full: cwnd is one segment. (b) The peer window closes.
    for cwnd_full in [true, false] {
        let cwnd = if cwnd_full { SEG } else { BIG_CWND };
        let (mut f, _) = Fixture::test_cc(Some(RATE), cwnd, if cwnd_full { BIG } else { 1460 });
        f.write(&pattern(2 * SEG as usize));
        assert_eq!(f.drain(t(0)).len(), 1);
        if !cwnd_full {
            assert_eq!(f.ack(tm(1), data(SEG), 0), Reaction::None);
            assert!(f.drain(tm(1)).is_empty());
            assert!(f.tcb.peer_window_closed());
        }
        let release = tm(10);
        assert_eq!(f.tcb.poll_send_at(), Some(release), "cwnd_full {cwnd_full}");
        assert_eq!(f.timeout(release), Reaction::None);
        let next = f.tcb.poll_send_at().expect("RTO or persist");
        assert!(next > release, "cwnd_full {cwnd_full}: {next:?}");
        for _ in 0..3 {
            assert!(f.drain(release).is_empty());
            assert_eq!(f.tcb.poll_send_at(), Some(next), "fires once");
        }
    }
}

#[test]
fn pacing_does_not_delay_acks() {
    let (mut f, _) = Fixture::test_cc(Some(RATE), BIG_CWND, BIG);
    f.write(&pattern(3 * SEG as usize));
    assert_eq!(f.drain(t(0)).len(), 1);
    // Out-of-order data: ACKed at once although data sending waits for the release.
    let r = f.seg_ack(tm(1), 10, data(0), TcpFlags::ACK, b"x");
    assert_eq!(r, Reaction::None);
    let segs = f.drain(tm(1));
    assert_eq!(segs.len(), 1);
    assert_eq!((segs[0].0.len, segs[0].0.flags), (0, TcpFlags::ACK));
    assert_eq!(f.out.ack, pdata(0));
}

#[test]
fn retransmission_is_paced() {
    // One segment per 2 s: the RTO at 1 s comes before the release.
    let (mut f, _) = Fixture::test_cc(Some(730), BIG_CWND, BIG);
    f.write(&pattern(SEG as usize));
    assert_eq!(f.drain(t(0)).len(), 1);
    assert_eq!(
        f.tcb.poll_send_at(),
        Some(t(1)),
        "nothing unsent: the RTO only"
    );
    assert_eq!(f.timeout(t(1)), Reaction::None);
    assert!(f.drain(t(1)).is_empty(), "the retransmission waits");
    assert_eq!(f.tcb.poll_send_at(), Some(t(2)));
    assert_eq!(f.timeout(t(2)), Reaction::None);
    assert_eq!(seq_lens(&f.drain(t(2))), [(data(0), SEG)]);
}

#[test]
fn reno_unpaced_unchanged() {
    // Reno never paces, also after RTT samples: the ramp sends two segments per ACK at once.
    // CUBIC paces from its first RTT sample (M2 Task 4b), so Reno alone pins the unpaced path.
    let f = Fixture::reno_ramp(&pattern(20_000));
    assert_eq!(f.tcb.cc.pacing_rate(), None);
}

#[test]
fn default_cc_paces_after_first_rtt_sample() {
    let mut f = cubic_fixture(BIG);
    f.write(&pattern(20_000));
    // No RTT sample yet: the IW goes out at once.
    assert_eq!(f.drain(t(0)).len(), 4);
    // The ACK of two segments at 10 ms: srtt 10 ms, cwnd 6000, slow start ratio 2:
    // 1 200 000 octets/s, one 1000-octet segment per 833 333 ns.
    f.ack(tm(10), data(2000), BIG);
    assert_eq!(f.tcb.cc.pacing_rate(), Some(1_200_000));
    let gap = Duration::from_nanos(833_333);
    let mut release = tm(10);
    for k in 0..4u32 {
        assert_eq!(
            seq_lens(&f.drain(release)),
            [(data(4000 + 1000 * k), 1000)],
            "release {k}"
        );
        release = release + gap;
        if k == 3 {
            break;
        }
        assert_eq!(f.tcb.poll_send_at(), Some(release));
        let before = tm(10) + (gap * (k + 1) - Duration::from_nanos(1));
        assert!(f.drain(before).is_empty());
        if k == 1 {
            // While data waits for the release, an out-of-order segment is ACKed at once.
            f.seg_ack(before, 10, data(2000), TcpFlags::ACK, b"x");
            let segs = f.drain(before);
            assert_eq!(segs.len(), 1);
            assert_eq!((segs[0].0.len, segs[0].0.flags), (0, TcpFlags::ACK));
            assert_eq!(f.tcb.poll_send_at(), Some(release));
        }
    }
    // cwnd full (6000 outstanding): the release fires once and sends nothing.
    assert_eq!(f.tcb.poll_send_at(), Some(release));
    assert!(f.drain(release).is_empty());
}

#[test]
fn app_limited_flag_recorded_at_send() {
    let (mut f, samples) = Fixture::test_cc(None, BIG_CWND, BIG);
    f.write(&pattern(2 * SEG as usize));
    assert_eq!(f.drain(t(0)).len(), 2);
    f.mark(t(0), AppLimited::NoData);
    assert_eq!(f.tcb.app_limited_until, Some(2 * u64::from(SEG)));
    assert_eq!(f.tcb.app_limited(), Some(AppLimited::NoData));
    f.write(&pattern(2 * SEG as usize));
    assert_eq!(f.drain(t(0)).len(), 2);
    assert_eq!(
        f.tcb.app_limited(),
        None,
        "data went out: the reason clears"
    );
    for k in 1..=2 {
        f.ack(tm(10 * u64::from(k)), data(k * SEG), BIG);
    }
    assert_eq!(
        f.tcb.app_limited_until,
        Some(2 * u64::from(SEG)),
        "delivered == marker"
    );
    f.ack(tm(30), data(3 * SEG), BIG);
    assert_eq!(f.tcb.app_limited_until, None, "delivered > marker");
    f.ack(tm(40), data(4 * SEG), BIG);
    f.write(&pattern(SEG as usize));
    assert_eq!(f.drain(tm(40)).len(), 1);
    f.ack(tm(50), data(5 * SEG), BIG);
    assert_eq!(flags_of(&samples), [false, false, true, true, false]);
    let delivered: Vec<u64> = samples
        .lock()
        .unwrap()
        .iter()
        .map(|a| a.delivered)
        .collect();
    assert_eq!(delivered, [1, 2, 3, 4, 5].map(|k| k * u64::from(SEG)));
}

#[test]
fn app_limited_resume_from_zero_in_flight() {
    let (mut f, samples) = Fixture::test_cc(None, BIG_CWND, BIG);
    f.mark(t(0), AppLimited::NoData);
    assert_eq!(f.tcb.app_limited_until, Some(0));
    f.write(&pattern(SEG as usize));
    assert_eq!(f.drain(t(0)).len(), 1);
    f.ack(tm(10), data(SEG), BIG);
    assert_eq!(f.tcb.app_limited_until, None);
    f.write(&pattern(SEG as usize));
    assert_eq!(f.drain(tm(10)).len(), 1);
    f.ack(tm(20), data(2 * SEG), BIG);
    assert_eq!(flags_of(&samples), [true, false]);
}

#[test]
fn retransmission_rerecords_app_limited() {
    let (mut f, samples) = Fixture::test_cc(None, BIG_CWND, BIG);
    f.write(&pattern(SEG as usize));
    assert_eq!(f.drain(t(0)).len(), 1);
    assert!(!f.tcb.sent[0].app_limited);
    f.mark(t(0), AppLimited::NoData);
    assert_eq!(f.timeout(t(1)), Reaction::None);
    assert_eq!(seq_lens(&f.drain(t(1))), [(data(0), SEG)]);
    f.ack(tm(1010), data(SEG), BIG);
    let s = samples.lock().unwrap()[0];
    assert!(s.app_limited, "the retransmission was sent marked");
    assert_eq!(s.rtt, None, "Karn");
}

#[test]
fn sample_uses_newest_transmission_not_highest_seq() {
    let (mut f, samples) = Fixture::test_cc(None, BIG_CWND, BIG);
    f.write(&pattern(2 * SEG as usize));
    assert_eq!(f.drain(t(0)).len(), 2);
    f.mark(t(0), AppLimited::NoData);
    assert_eq!(f.timeout(t(1)), Reaction::None);
    // Only S1 is resent (marked, newest) before the ACK covering S1 and S2 arrives.
    assert_eq!(f.send(t(1)).map(|m| (m.seq, m.len)), Some((data(0), SEG)));
    f.ack(tm(1010), data(2 * SEG), BIG);
    let s = samples.lock().unwrap()[0];
    assert!(
        s.app_limited,
        "S1's retransmission, not S2's original transmission"
    );
    assert_eq!(
        s.rtt, None,
        "the newest transmission is a retransmission (Karn)"
    );
    assert!(f.tcb.sent.is_empty());
}

#[test]
fn no_mark_without_room() {
    // cwnd full.
    let (mut f, _) = Fixture::test_cc(None, SEG, BIG);
    f.write(&pattern(SEG as usize));
    assert_eq!(f.drain(t(0)).len(), 1);
    f.mark(t(0), AppLimited::NoData);
    assert_eq!((f.tcb.app_limited(), f.tcb.app_limited_until), (None, None));
    // Peer window closed.
    let (mut f, _) = Fixture::test_cc(None, BIG_CWND, BIG);
    f.write(&pattern(SEG as usize));
    assert_eq!(f.drain(t(0)).len(), 1);
    f.ack(tm(1), data(SEG), 0);
    f.mark(tm(1), AppLimited::NoData);
    assert_eq!((f.tcb.app_limited(), f.tcb.app_limited_until), (None, None));
    // Pacing-blocked with assigned data pending: it has something to send.
    let (mut f, _) = Fixture::test_cc(Some(RATE), BIG_CWND, BIG);
    f.write(&pattern(3 * SEG as usize));
    assert_eq!(f.drain(t(0)).len(), 1);
    f.mark(t(0), AppLimited::NotScheduled);
    assert_eq!((f.tcb.app_limited(), f.tcb.app_limited_until), (None, None));
}

#[test]
fn drained_paced_sender_marked_before_next_burst() {
    let (mut f, samples) = Fixture::test_cc(Some(RATE), BIG_CWND, BIG);
    f.write(&pattern(SEG as usize));
    assert_eq!(f.drain(t(0)).len(), 1);
    f.ack(tm(1), data(SEG), BIG);
    assert!(f.drain(tm(1)).is_empty());
    assert_eq!(
        f.tcb.poll_send_at(),
        None,
        "nothing to send: the release is no timer"
    );
    // The pending release (10 ms) does not keep the sender from being app-limited.
    f.mark(tm(1), AppLimited::NoData);
    assert_eq!(f.tcb.app_limited(), Some(AppLimited::NoData));
    f.write(&pattern(SEG as usize));
    assert_eq!(f.drain(tm(100)).len(), 1);
    assert!(f.tcb.sent.back().unwrap().app_limited);
    f.ack(tm(110), data(2 * SEG), BIG);
    assert_eq!(flags_of(&samples), [false, true]);
}

#[test]
fn marker_refreshed_on_repeated_app_limited() {
    let (mut f, samples) = Fixture::test_cc(None, BIG_CWND, BIG);
    f.write(&pattern(SEG as usize));
    assert_eq!(f.drain(t(0)).len(), 1);
    f.ack(tm(10), data(SEG), BIG);
    f.mark(tm(10), AppLimited::NoData);
    assert_eq!(f.tcb.app_limited_until, Some(u64::from(SEG)));
    f.write(&pattern(SEG as usize));
    assert_eq!(f.drain(tm(10)).len(), 1);
    // The pass ends again with room and no data: delivered + in_flight.
    f.mark(tm(10), AppLimited::NoData);
    assert_eq!(f.tcb.app_limited_until, Some(2 * u64::from(SEG)));
    f.ack(tm(20), data(2 * SEG), BIG);
    assert_eq!(
        f.tcb.app_limited_until,
        Some(2 * u64::from(SEG)),
        "not cleared early"
    );
    f.write(&pattern(SEG as usize));
    assert_eq!(f.drain(tm(20)).len(), 1);
    assert!(f.tcb.sent.back().unwrap().app_limited);
    f.ack(tm(30), data(3 * SEG), BIG);
    assert_eq!(f.tcb.app_limited_until, None);
    assert_eq!(flags_of(&samples), [false, true, true]);
}

// ---- cwnd-limited (RFC 9438 §5.8, RFC 7661 §3): fix round 1 ----

/// The default CC (CUBIC), MSS 1000 (IW 4000), peer window `wnd`, ESTABLISHED at t(0).
fn cubic_fixture(wnd: u16) -> Fixture {
    let mut f = Fixture::new(ConnectConfig::default(), v4());
    assert_eq!(
        f.synack(wnd, &opts(Some(MSS), Some(0))),
        Reaction::Established
    );
    f.send(t(0)).unwrap();
    assert_eq!(f.tcb.cc.cwnd(), 4000);
    f
}

#[test]
fn cubic_rwnd_limited_does_not_grow_cwnd() {
    // A 2000-octet peer window below IW: the flow never fills cwnd.
    let mut f = cubic_fixture(2000);
    f.write(&pattern(200_000));
    for round in 1..=50 {
        let now = tm(10 * round);
        assert!(!f.drain(now).is_empty());
        // The second segment of the window at CUBIC's pacing release (625 µs here).
        f.drain(now + Duration::from_millis(1));
        let ack = f.tcb.snd_max;
        f.ack(now + Duration::from_millis(5), ack, 2000);
    }
    assert!(f.tcb.snd_una.gt(data(90_000)), "the transfer runs");
    assert_eq!(f.tcb.cc.cwnd(), 4000, "receiver-limited: no growth");
}

#[test]
fn cubic_app_limited_with_data_outstanding_does_not_grow_cwnd() {
    // The application writes one segment per 10 ms; one segment is always outstanding.
    let mut f = cubic_fixture(BIG);
    for round in 0..50u32 {
        let now = tm(10 * u64::from(round));
        f.write(&pattern(1000));
        assert_eq!(f.drain(now).len(), 1);
        if round > 0 {
            f.ack(now + Duration::from_millis(1), data(1000 * round), BIG);
        }
    }
    assert_eq!(f.tcb.cc.cwnd(), 4000, "application-limited: no growth");
}

#[test]
fn cwnd_limited_marks_acks_of_a_full_window() {
    // cwnd 4 segments: the burst fills it, so every ACK of it is cwnd-limited, also when the
    // ACKs come in one batch before anything more is sent.
    let (mut f, samples) = Fixture::test_cc(None, 4 * SEG, BIG);
    f.write(&pattern(8 * SEG as usize));
    assert_eq!(f.drain(t(0)).len(), 4);
    for k in 1..=4 {
        f.ack(tm(10), data(k * SEG), BIG);
    }
    let lim: Vec<bool> = samples
        .lock()
        .unwrap()
        .iter()
        .map(|a| a.cwnd_limited)
        .collect();
    assert_eq!(lim, [true; 4]);
    // The rest (4 segments) leaves cwnd full again; ACKed, the queue is empty.
    assert_eq!(f.drain(tm(10)).len(), 4);
    f.ack(tm(20), data(8 * SEG), BIG);
    // One segment with cwnd unused: not cwnd-limited.
    f.write(&pattern(SEG as usize));
    assert_eq!(f.drain(tm(20)).len(), 1);
    f.ack(tm(30), data(9 * SEG), BIG);
    let lim: Vec<bool> = samples
        .lock()
        .unwrap()
        .iter()
        .map(|a| a.cwnd_limited)
        .collect();
    assert_eq!(lim, [true, true, true, true, true, false]);
    // Receiver-limited: the peer window holds 2 segments of a 64 KiB cwnd.
    let (mut f, samples) = Fixture::test_cc(None, BIG_CWND, 2 * 1460);
    f.write(&pattern(8 * SEG as usize));
    for k in 1..=4 {
        assert_eq!(f.drain(tm(10 * u64::from(k))).len(), 2);
        f.ack(tm(10 * u64::from(k) + 5), data(2 * k * SEG), 2 * 1460);
    }
    let s = samples.lock().unwrap();
    assert_eq!(s.len(), 4);
    assert!(s.iter().all(|a| !a.cwnd_limited && !a.app_limited), "{s:?}");
}
