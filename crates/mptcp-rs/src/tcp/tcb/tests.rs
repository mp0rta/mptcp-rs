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
            assert_eq!(m.seq, self.tcb.snd_nxt);
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
    assert_eq!(tcb.on_segment(&seg, now, h), Reaction::None);
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
