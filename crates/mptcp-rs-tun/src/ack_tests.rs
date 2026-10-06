//! Exercise the actual adapter input path, without requiring a TUN device.
use super::*;
use mptcp_rs::SeqNum;
use mptcp_rs::wire::packet::{Segment, TcpFlags, build, parse};

const PEER_ISN: u32 = 5000;

struct Fixture {
    ep: Endpoint<ChaCha20Rng>,
    pkt: Vec<u8>,
    peer: SocketAddr,
    local: SocketAddr,
    ack: SeqNum,
    mss: usize,
}

impl Fixture {
    fn new(v6: bool) -> Self {
        let local_ip = if v6 { "fd00::1" } else { "10.0.0.1" }.parse().unwrap();
        let peer: SocketAddr = if v6 { "[fd00::2]:80" } else { "10.0.0.2:80" }
            .parse()
            .unwrap();
        let mut ep = Endpoint::new(ChaCha20Rng::seed_from_u64(4));
        let t = Instant::from_nanos(0);
        ep.connect(t, local_ip, peer, ConnectConfig::default())
            .unwrap();
        let mut pkt = vec![0; 65535];
        let n = ep.poll_transmit(t, &mut pkt).unwrap();
        let syn = parse(&pkt[..n]).unwrap();
        let local = syn.src;
        let ack = SeqNum(syn.seq.0.wrapping_add(1));
        let mss = if v6 { 1440 } else { 1460 };
        let opts = [2, 4, (mss >> 8) as u8, mss as u8];
        let syn_ack = Segment {
            src: peer,
            dst: local,
            seq: SeqNum(PEER_ISN),
            ack,
            flags: TcpFlags::SYN | TcpFlags::ACK,
            wnd: 65535,
            options: &opts,
            payload: &[],
        };
        let n = build(&syn_ack, 0, &mut pkt).unwrap();
        ep.handle_packet(t, &pkt[..n]);
        let n = ep.poll_transmit(t, &mut pkt).expect("handshake ACK");
        assert_eq!(parse(&pkt[..n]).unwrap().ack.0, PEER_ISN + 1);
        assert!(matches!(
            ep.poll_event(),
            Some((_, Event::Connected { .. }))
        ));
        Self {
            ep,
            pkt,
            peer,
            local,
            ack,
            mss,
        }
    }

    fn data(&mut self, segment_offset: u32) -> Option<u32> {
        let payload = vec![0x5a; self.mss];
        let segment = Segment {
            src: self.peer,
            dst: self.local,
            seq: SeqNum(PEER_ISN + 1 + segment_offset * self.mss as u32),
            ack: self.ack,
            flags: TcpFlags::ACK,
            wnd: 65535,
            options: &[],
            payload: &payload,
        };
        let n = build(&segment, 0, &mut self.pkt).unwrap();
        receive_and_poll(
            &mut self.ep,
            Instant::from_nanos(1_000_000),
            &mut self.pkt,
            n,
        )
        .map(|n| {
            let ack = parse(&self.pkt[..n]).unwrap();
            assert!(ack.flags.contains(TcpFlags::ACK));
            assert!(ack.payload.is_empty());
            ack.ack.0
        })
    }
}

#[test]
fn every_segment_after_a_gap_gets_a_duplicate_ack() {
    for v6 in [false, true] {
        let mut f = Fixture::new(v6);
        for offset in 1..=3 {
            assert_eq!(f.data(offset), Some(PEER_ISN + 1));
        }
        // Filling the gap also gets an immediate ACK, without waiting 200 ms.
        let expected = PEER_ISN + 1 + 4 * f.mss as u32;
        assert_eq!(f.data(0), Some(expected));
    }
}

#[test]
fn in_order_burst_is_acknowledged_every_two_full_segments() {
    for v6 in [false, true] {
        let mut f = Fixture::new(v6);
        for offset in 0..8 {
            let expected = if offset % 2 == 1 {
                Some(PEER_ISN + 1 + (offset + 1) * f.mss as u32)
            } else {
                None
            };
            assert_eq!(f.data(offset), expected);
        }
    }
}

#[test]
fn single_segment_keeps_the_200ms_delayed_ack() {
    for v6 in [false, true] {
        let mut f = Fixture::new(v6);
        assert_eq!(f.data(0), None);
        let deadline = Instant::from_nanos(201_000_000);
        assert_eq!(f.ep.poll_timeout(), Some(deadline));
        let before = Instant::from_nanos(deadline.as_nanos() - 1);
        f.ep.handle_timeout(before);
        assert_eq!(f.ep.poll_transmit(before, &mut f.pkt), None);
        f.ep.handle_timeout(deadline);
        let n =
            f.ep.poll_transmit(deadline, &mut f.pkt)
                .expect("delayed ACK");
        assert_eq!(
            parse(&f.pkt[..n]).unwrap().ack.0,
            PEER_ISN + 1 + f.mss as u32
        );
    }
}
