//! Internet-checksum zero representations, RFC 1071 and RFC 1624 section 5.
use mptcp_rs::SeqNum;
use mptcp_rs::wire::packet::{PacketError, Segment, TcpFlags, build, parse};
use std::net::SocketAddr;

mod support;

fn folded_sum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    for pair in bytes.chunks(2) {
        sum += u32::from(u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)]));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum as u16
}

fn assert_tcp_zero_forms(src: SocketAddr, dst: SocketAddr) {
    let mut seg = Segment {
        src,
        dst,
        seq: SeqNum(1234),
        ack: SeqNum(4321),
        flags: TcpFlags::ACK,
        wnd: 63,
        options: &[],
        payload: &[0, 0],
    };
    let mut packet = [0u8; 100];
    let ip_len = if src.is_ipv4() { 20 } else { 40 };
    build(&seg, 0, &mut packet).unwrap();
    let payload = [packet[ip_len + 16], packet[ip_len + 17]];
    seg.payload = &payload;
    let n = build(&seg, 0, &mut packet).unwrap();
    assert_eq!(&packet[ip_len + 16..ip_len + 18], &[0, 0]);
    let mut pseudo = Vec::new();
    if src.is_ipv4() {
        pseudo.extend_from_slice(&packet[12..20]);
        pseudo.extend_from_slice(&[0, 6, 0, 22]);
    } else {
        pseudo.extend_from_slice(&packet[8..40]);
        pseudo.extend_from_slice(&[0, 0, 0, 22, 0, 0, 0, 6]);
    }
    for received in [0u16, u16::MAX] {
        packet[ip_len + 16..ip_len + 18].copy_from_slice(&received.to_be_bytes());
        let mut checked = pseudo.clone();
        checked.extend_from_slice(&packet[ip_len..n]);
        assert_eq!(
            folded_sum(&checked),
            u16::MAX,
            "independent checksum verification"
        );
        assert_eq!(
            parse(&packet[..n]).unwrap(),
            seg,
            "received {received:#06x}"
        );
        packet[n - 1] ^= 1;
        assert_eq!(parse(&packet[..n]), Err(PacketError::Checksum));
        packet[n - 1] ^= 1;
    }
}

#[test]
fn ipv4_tcp_accepts_both_checksum_zero_forms() {
    assert_tcp_zero_forms(
        "10.0.1.2:5219".parse().unwrap(),
        "10.77.0.2:58029".parse().unwrap(),
    );
}

#[test]
fn ipv6_tcp_accepts_both_checksum_zero_forms() {
    assert_tcp_zero_forms(
        "[fd00::1]:5219".parse().unwrap(),
        "[fd00::2]:58029".parse().unwrap(),
    );
}

#[test]
fn ipv4_header_accepts_both_checksum_zero_forms() {
    let seg = Segment {
        src: "10.0.1.2:5219".parse().unwrap(),
        dst: "10.77.0.2:58029".parse().unwrap(),
        seq: SeqNum(1),
        ack: SeqNum(2),
        flags: TcpFlags::ACK,
        wnd: 63,
        options: &[],
        payload: &[],
    };
    let mut packet = [0u8; 100];
    build(&seg, 0, &mut packet).unwrap();
    let id = u16::from_be_bytes([packet[10], packet[11]]);
    let n = build(&seg, id, &mut packet).unwrap();
    assert_eq!(&packet[10..12], &[0, 0]);
    for received in [0u16, u16::MAX] {
        packet[10..12].copy_from_slice(&received.to_be_bytes());
        assert_eq!(folded_sum(&packet[..20]), u16::MAX);
        assert_eq!(parse(&packet[..n]).unwrap(), seg);
        packet[8] ^= 1;
        assert_eq!(parse(&packet[..n]), Err(PacketError::IpChecksum));
        packet[8] ^= 1;
    }
}

#[test]
fn reconstructed_stalled_segment_accepts_both_zero_forms() {
    // Header and deterministic payload from the second stalled controlled transfer.
    let payload: Vec<_> = (73_397_940u64..73_397_940 + 1460)
        .map(|i| ((i * 31 + 7) % 251) as u8)
        .collect();
    let seg = Segment {
        src: "10.0.1.2:5219".parse().unwrap(),
        dst: "10.77.0.2:58029".parse().unwrap(),
        seq: SeqNum(3_709_745_470),
        ack: SeqNum(2_981_244_046),
        flags: TcpFlags::ACK,
        wnd: 63,
        options: &[],
        payload: &payload,
    };
    let mut packet = [0u8; 1500];
    let n = build(&seg, 0x26b8, &mut packet).unwrap();
    assert_eq!(&packet[36..38], &[0, 0]);
    for received in [0u16, u16::MAX] {
        packet[36..38].copy_from_slice(&received.to_be_bytes());
        assert_eq!(parse(&packet[..n]).unwrap(), seg);
    }
}

#[test]
fn all_ones_is_rejected_when_computed_checksum_is_nonzero() {
    for (src, dst) in [
        ("10.0.1.2:5219", "10.77.0.2:58029"),
        ("[fd00::1]:5219", "[fd00::2]:58029"),
    ] {
        let seg = Segment {
            src: src.parse().unwrap(),
            dst: dst.parse().unwrap(),
            seq: SeqNum(1),
            ack: SeqNum(2),
            flags: TcpFlags::ACK,
            wnd: 63,
            options: &[],
            payload: &[1, 2, 3],
        };
        let mut packet = [0u8; 100];
        let n = build(&seg, 0, &mut packet).unwrap();
        let ip_len = if seg.src.is_ipv4() { 20 } else { 40 };
        assert_ne!(&packet[ip_len + 16..ip_len + 18], &[0, 0]);
        packet[ip_len + 16..ip_len + 18].copy_from_slice(&u16::MAX.to_be_bytes());
        assert_eq!(parse(&packet[..n]), Err(PacketError::Checksum));
        if seg.src.is_ipv4() {
            build(&seg, 0, &mut packet).unwrap();
            assert_ne!(&packet[10..12], &[0, 0]);
            packet[10..12].copy_from_slice(&u16::MAX.to_be_bytes());
            assert_eq!(parse(&packet[..n]), Err(PacketError::IpChecksum));
        }
    }
}

#[test]
fn endpoint_delivers_zero_checksum_data_in_both_ip_families() {
    use support::*;
    for v6 in [false, true] {
        let mut ep = endpoint(4);
        let (handle, syn, iss) = established(&mut ep, t(0), v6);
        let mut seg = Segment {
            src: syn.dst,
            dst: syn.src,
            seq: SeqNum(iss + 1),
            ack: SeqNum(syn.seq.0.wrapping_add(1)),
            flags: TcpFlags::ACK,
            wnd: 65535,
            options: &[],
            payload: &[0, 0],
        };
        let mut packet = [0u8; 100];
        let ip_len = if v6 { 40 } else { 20 };
        build(&seg, 0, &mut packet).unwrap();
        let payload = [packet[ip_len + 16], packet[ip_len + 17]];
        seg.payload = &payload;
        let n = build(&seg, 0, &mut packet).unwrap();
        assert_eq!(&packet[ip_len + 16..ip_len + 18], &[0, 0]);
        packet[ip_len + 16..ip_len + 18].copy_from_slice(&u16::MAX.to_be_bytes());
        ep.handle_packet(ms(t(0), 1), &packet[..n]);
        let mut received = [0u8; 2];
        assert_eq!(
            ep.connection(handle).unwrap().read(&mut received).unwrap(),
            2
        );
        assert_eq!(received, payload);
    }
}
