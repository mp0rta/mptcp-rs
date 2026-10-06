use super::*;
use crate::tcp::cc::CongestionEvent;
use crate::tcp::{PlainHooks, SegmentHooks, SendBuf};
use std::cell::RefCell;
use std::rc::Rc;

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
        // Only MSS and WS: no SACK-permitted, no timestamps.
        assert_eq!(
            parsed(f.out.options()),
            vec![TcpOpt::Mss(mss), TcpOpt::WindowScale(7)]
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
        vec![TcpOpt::Mss(1460), TcpOpt::WindowScale(0)]
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
    for (at, next) in [(1, 3), (3, 7)] {
        assert_eq!(f.timeout(t(at)), Reaction::None);
        let segs = f.drain(t(at));
        assert_eq!(segs.len(), 1, "retransmission at {at} s");
        assert_eq!((segs[0].0.seq, segs[0].0.len), (data(0), 500));
        assert_eq!(segs[0].1, bytes);
        assert_eq!(f.tcb.poll_send_at(), Some(t(next)));
    }
    // The ACK covers a retransmitted segment: no RTT sample, RTO stays backed off.
    assert_eq!(f.ack(tm(3100), data(500), 10 * MSS), Reaction::None);
    assert_eq!(f.tcb.rtt.srtt(), None);
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
struct Recording(Rc<RefCell<CcLog>>);

impl CongestionControl for Recording {
    fn init(&mut self, smss: u32) {
        self.0.borrow_mut().init = Some(smss);
    }
    fn on_ack(&mut self, acked: u32, rtt: Option<Duration>, in_flight: u32, _: Instant) {
        self.0.borrow_mut().acks.push((acked, rtt, in_flight));
    }
    fn on_congestion(&mut self, ev: CongestionEvent, in_flight: u32, _: Instant) {
        self.0.borrow_mut().events.push((ev, in_flight));
    }
    fn cwnd(&self) -> u32 {
        2 * u32::from(MSS)
    }
}

#[test]
fn cc_gates_sending_and_sees_acks_and_rto() {
    let log = Rc::new(RefCell::new(CcLog::default()));
    let cfg = ConnectConfig::default();
    let h = PlainHooks::new(&cfg);
    let mut f = Fixture::with(cfg, Box::new(Recording(log.clone())), h);
    f.establish(10 * MSS);
    assert_eq!(log.borrow().init, Some(u32::from(MSS)));
    f.write(&pattern(5000));
    let segs = f.drain(t(0));
    assert_eq!(segs.len(), 2, "cwnd = 2 segments");
    assert_eq!(f.ack(tm(100), data(1000), 10 * MSS), Reaction::None);
    assert_eq!(
        log.borrow().acks,
        vec![(1000, Some(Duration::from_millis(100)), 1000)]
    );
    let segs = f.drain(tm(100));
    assert_eq!(segs.len(), 1);
    assert_eq!(segs[0].0.seq, data(2000));
    // RTO restarted by the ACK at 0.1 s.
    assert_eq!(f.tcb.poll_send_at(), Some(tm(1100)));
    assert_eq!(f.timeout(tm(1100)), Reaction::None);
    // FlightSize at the RTO: data(1000)..data(3000).
    assert_eq!(log.borrow().events, vec![(CongestionEvent::Rto, 2000)]);
    let segs = f.drain(tm(1100));
    assert_eq!(segs.len(), 1);
    assert_eq!((segs[0].0.seq, segs[0].0.len), (data(1000), 1000));
}

/// A send buffer whose runs are at most 7 octets, as at many internal buffer boundaries.
struct ShortRuns(PlainHooks);

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
    let h = ShortRuns(PlainHooks::new(&cfg));
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
