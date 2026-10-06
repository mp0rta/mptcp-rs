mod support;

use mptcp_rs::wire::packet::TcpFlags;
use mptcp_rs::{CloseReason, Event, ReadError, SeqNum, WriteError};
use support::*;

#[test]
fn api_misuse_never_panics() {
    let mut ep = endpoint(1);
    let (h, syn, iss) = established(&mut ep, t(1), false);
    let c = ep.connection(h).unwrap();
    assert_eq!(c.write(&[]), Ok(0));
    assert_eq!(c.read(&mut []), Ok(0));
    c.close();
    c.close();
    assert_eq!(c.write(b"x"), Err(WriteError::Closed));
    assert_eq!(c.write(&[]), Err(WriteError::Closed));
    assert_eq!(c.read(&mut []), Ok(0));
    c.set_nodelay(true);
    send_seg(&mut ep, t(2), &syn, iss + 1, 0, TcpFlags::RST, &[]);
    assert_eq!(
        ep.connection(h).unwrap().write(b"x"),
        Err(WriteError::Closed)
    );
    ep.handle_timeout(t(2));
    assert!(ep.connection(h).is_none());
    assert!(ep.connection(h).is_none());
}

#[test]
fn bad_checksum_and_truncated_dropped() {
    let mut ep = endpoint(2);
    let (h, syn, iss) = established(&mut ep, t(1), false);
    let good = pkt(
        syn.dst,
        syn.src,
        SeqNum(iss + 1),
        SeqNum(syn.seq.0 + 1),
        TcpFlags::ACK,
        &[],
        b"data",
    );
    let mut bad = good.clone();
    *bad.last_mut().unwrap() ^= 0xff;
    ep.handle_packet(t(2), &bad);
    for n in [0, 1, 19, 20, 33, good.len() - 1] {
        ep.handle_packet(t(2), &good[..n]);
    }
    ep.handle_packet(t(2), &[0x45; 7]);
    assert!(drain(&mut ep, t(2)).is_empty());
    assert_eq!(ep.poll_event(), None);
    assert_eq!(
        ep.connection(h).unwrap().read(&mut [0u8; 8]),
        Err(ReadError::WouldBlock)
    );
    ep.handle_packet(t(2), &good);
    let mut buf = [0u8; 8];
    assert_eq!(ep.connection(h).unwrap().read(&mut buf), Ok(4));
    assert_eq!(&buf[..4], b"data");
}

#[test]
fn no_tcb_segment_gets_rst() {
    let mut ep = endpoint(3);
    let (a, b) = (peer_addr(false), "10.0.0.1:50000".parse().unwrap());
    // ACK present: <SEQ=SEG.ACK><CTL=RST>
    ep.handle_packet(
        t(1),
        &pkt(
            a,
            b,
            SeqNum(100),
            SeqNum(777),
            TcpFlags::ACK,
            &[],
            b"0123456789",
        ),
    );
    let r = parse_owned(&drain(&mut ep, t(1))[0]);
    assert_eq!(
        (r.src, r.dst, r.seq, r.flags),
        (b, a, SeqNum(777), TcpFlags::RST)
    );
    // No ACK: <SEQ=0><ACK=SEG.SEQ+SEG.LEN><CTL=RST,ACK>, SYN and FIN counted.
    ep.handle_packet(
        t(1),
        &pkt(a, b, SeqNum(1000), SeqNum(0), TcpFlags::SYN, &[], &[]),
    );
    ep.handle_packet(
        t(1),
        &pkt(
            a,
            b,
            SeqNum(2000),
            SeqNum(0),
            TcpFlags::FIN | TcpFlags::PSH,
            &[],
            b"abc",
        ),
    );
    ep.handle_packet(
        t(1),
        &pkt(a, b, SeqNum(u32::MAX), SeqNum(0), TcpFlags::PSH, &[], b"xy"),
    );
    let out: Vec<_> = drain(&mut ep, t(1))
        .iter()
        .map(|p| parse_owned(p))
        .collect();
    let got: Vec<_> = out.iter().map(|s| (s.seq, s.ack, s.flags)).collect();
    let ra = TcpFlags::RST | TcpFlags::ACK;
    assert_eq!(
        got,
        vec![
            (SeqNum(0), SeqNum(1001), ra),
            (SeqNum(0), SeqNum(2004), ra),
            (SeqNum(0), SeqNum(1), ra)
        ]
    );
    // Never in reply to a RST.
    ep.handle_packet(
        t(1),
        &pkt(
            a,
            b,
            SeqNum(5),
            SeqNum(6),
            TcpFlags::RST | TcpFlags::ACK,
            &[],
            &[],
        ),
    );
    ep.handle_packet(
        t(1),
        &pkt(a, b, SeqNum(5), SeqNum(0), TcpFlags::RST, &[], &[]),
    );
    assert!(drain(&mut ep, t(1)).is_empty());
    // A flood cannot grow the queue without bound.
    for i in 0..500 {
        ep.handle_packet(
            t(1),
            &pkt(a, b, SeqNum(i), SeqNum(1), TcpFlags::ACK, &[], &[]),
        );
    }
    assert_eq!(drain(&mut ep, t(1)).len(), 64);
}

#[test]
fn segment_after_time_wait_expired_gets_rst() {
    let mut ep = endpoint(4);
    let (h, syn, iss) = established(&mut ep, t(1), false);
    let isn = syn.seq.0;
    ep.connection(h).unwrap().close();
    let fin = parse_owned(&drain(&mut ep, t(1))[0]);
    assert!(fin.flags.contains(TcpFlags::FIN));
    send_seg(&mut ep, t(2), &syn, iss + 1, isn + 2, TcpFlags::ACK, &[]);
    send_seg(
        &mut ep,
        t(2),
        &syn,
        iss + 1,
        isn + 2,
        TcpFlags::ACK | TcpFlags::FIN,
        &[],
    );
    assert_eq!(
        ep.poll_event(),
        Some((
            h,
            Event::Closed {
                reason: CloseReason::Normal
            }
        ))
    );
    expect_ack(&drain(&mut ep, t(2)), iss + 2);
    // TIME-WAIT: still in the table, a retransmitted FIN is ACKed, not reset.
    ep.handle_timeout(t(100));
    assert!(ep.connection(h).is_some());
    send_seg(
        &mut ep,
        t(100),
        &syn,
        iss + 1,
        isn + 2,
        TcpFlags::ACK | TcpFlags::FIN,
        &[],
    );
    let a = drain(&mut ep, t(100));
    assert_eq!(parse_owned(&a[0]).flags, TcpFlags::ACK);
    // Expiry (120 s after the last FIN) frees it.
    let due = ep.poll_timeout().unwrap();
    assert_eq!(due, t(220));
    ep.handle_timeout(due);
    assert!(ep.connection(h).is_none());
    assert_eq!(ep.poll_timeout(), None);
    send_seg(
        &mut ep,
        t(221),
        &syn,
        iss + 2,
        isn + 2,
        TcpFlags::ACK,
        b"late",
    );
    let r = parse_owned(&drain(&mut ep, t(221))[0]);
    assert_eq!((r.flags, r.seq), (TcpFlags::RST, SeqNum(isn + 2)));
}

#[test]
fn endpoint_and_connection_are_send() {
    fn assert_send<T: Send>() {}
    assert_send::<mptcp_rs::Endpoint<rand_chacha::ChaCha20Rng>>();
    assert_send::<mptcp_rs::Connection>();
}
