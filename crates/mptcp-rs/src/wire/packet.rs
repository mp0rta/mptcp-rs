//! IPv4/IPv6 + TCP segment parse and build (spec §6: malformed input is `Err`, never a panic).

use std::net::{IpAddr, SocketAddr};

use etherparse::{
    IpNumber, Ipv4Header, Ipv4HeaderSlice, Ipv6FlowLabel, Ipv6Header, Ipv6HeaderSlice, TcpHeader,
    TcpHeaderSlice,
};

use crate::seq::SeqNum;

/// TCP control bits we use (RFC 9293 §3.1 layout: URG=0x20 ... FIN=0x01).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TcpFlags(pub u8);

impl TcpFlags {
    pub const FIN: TcpFlags = TcpFlags(0x01);
    pub const SYN: TcpFlags = TcpFlags(0x02);
    pub const RST: TcpFlags = TcpFlags(0x04);
    pub const PSH: TcpFlags = TcpFlags(0x08);
    pub const ACK: TcpFlags = TcpFlags(0x10);
    pub const URG: TcpFlags = TcpFlags(0x20);

    /// True if every bit of `other` is set.
    pub fn contains(self, other: TcpFlags) -> bool {
        self.0 & other.0 == other.0
    }
}

impl std::ops::BitOr for TcpFlags {
    type Output = TcpFlags;
    fn bitor(self, o: TcpFlags) -> TcpFlags {
        TcpFlags(self.0 | o.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PacketError {
    /// Not a well-formed IPv4/IPv6 + TCP packet (version, lengths, offsets).
    Malformed,
    /// Not TCP, or an IPv6 extension header is present.
    NotTcp,
    /// IPv4 fragment (MF set or offset != 0).
    Fragment,
    /// IPv4 header checksum mismatch.
    IpChecksum,
    /// TCP checksum mismatch.
    Checksum,
    OptionsTooLong,
    /// `src` and `dst` are of different IP families.
    FamilyMismatch,
    /// Packet does not fit the IP length field.
    TooLong,
    /// Output buffer too small.
    NoSpace,
}

impl std::fmt::Display for PacketError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for PacketError {}

/// One TCP segment with its addressing; parse output and build input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Segment<'a> {
    pub src: SocketAddr,
    pub dst: SocketAddr,
    pub seq: SeqNum,
    pub ack: SeqNum,
    pub flags: TcpFlags,
    pub wnd: u16,
    /// Raw TCP options. On parse: exactly as on the wire (padding included).
    pub options: &'a [u8],
    pub payload: &'a [u8],
}

// RFC 1071 / RFC 1624 section 5: verification includes the received checksum
// in the one's-complement sum. A zero computed checksum also admits 0xffff.
pub(crate) fn valid_checksum(computed: u16, received: u16) -> bool {
    let sum = u32::from(!computed) + u32::from(received);
    (sum & 0xffff) + (sum >> 16) == u32::from(u16::MAX)
}

/// Parse an IPv4 or IPv6 packet carrying TCP. Verifies the IPv4 header and TCP checksums.
pub fn parse(pkt: &[u8]) -> Result<Segment<'_>, PacketError> {
    let (src_ip, dst_ip, l4) = match pkt.first().map(|b| b >> 4) {
        Some(4) => {
            let h = Ipv4HeaderSlice::from_slice(pkt).map_err(|_| PacketError::Malformed)?;
            let hl = h.slice().len();
            let total = usize::from(h.total_len());
            if total < hl || total > pkt.len() {
                return Err(PacketError::Malformed);
            }
            if !valid_checksum(h.to_header().calc_header_checksum(), h.header_checksum()) {
                return Err(PacketError::IpChecksum);
            }
            if h.is_fragmenting_payload() {
                return Err(PacketError::Fragment);
            }
            if h.protocol() != IpNumber::TCP {
                return Err(PacketError::NotTcp);
            }
            (
                IpAddr::V4(h.source_addr()),
                IpAddr::V4(h.destination_addr()),
                &pkt[hl..total],
            )
        }
        Some(6) => {
            let h = Ipv6HeaderSlice::from_slice(pkt).map_err(|_| PacketError::Malformed)?;
            let end = Ipv6Header::LEN + usize::from(h.payload_length());
            if end > pkt.len() {
                return Err(PacketError::Malformed);
            }
            if h.next_header() != IpNumber::TCP {
                return Err(PacketError::NotTcp);
            }
            (
                IpAddr::V6(h.source_addr()),
                IpAddr::V6(h.destination_addr()),
                &pkt[Ipv6Header::LEN..end],
            )
        }
        _ => return Err(PacketError::Malformed),
    };
    let t = TcpHeaderSlice::from_slice(l4).map_err(|_| PacketError::Malformed)?;
    let payload = &l4[t.slice().len()..];
    let sum = match (src_ip, dst_ip) {
        (IpAddr::V4(s), IpAddr::V4(d)) => t.calc_checksum_ipv4_raw(s.octets(), d.octets(), payload),
        (IpAddr::V6(s), IpAddr::V6(d)) => t.calc_checksum_ipv6_raw(s.octets(), d.octets(), payload),
        _ => unreachable!("families come from one IP header"),
    }
    .map_err(|_| PacketError::Malformed)?;
    if !valid_checksum(sum, t.checksum()) {
        return Err(PacketError::Checksum);
    }
    let bit = |set: bool, f: TcpFlags| if set { f } else { TcpFlags(0) };
    let flags = bit(t.fin(), TcpFlags::FIN)
        | bit(t.syn(), TcpFlags::SYN)
        | bit(t.rst(), TcpFlags::RST)
        | bit(t.psh(), TcpFlags::PSH)
        | bit(t.ack(), TcpFlags::ACK)
        | bit(t.urg(), TcpFlags::URG);
    Ok(Segment {
        src: SocketAddr::new(src_ip, t.source_port()),
        dst: SocketAddr::new(dst_ip, t.destination_port()),
        seq: SeqNum(t.sequence_number()),
        ack: SeqNum(t.acknowledgment_number()),
        flags,
        wnd: t.window_size(),
        options: &t.slice()[TcpHeader::MIN_LEN..],
        payload,
    })
}

/// Build a complete IP packet into `buf`; returns its length.
pub fn build(seg: &Segment, ip_id: u16, buf: &mut [u8]) -> Result<usize, PacketError> {
    if seg.options.len() > 40 {
        return Err(PacketError::OptionsTooLong);
    }
    let mut opts = [1u8; 40]; // NOP padding
    opts[..seg.options.len()].copy_from_slice(seg.options);
    let opts = &opts[..seg.options.len().div_ceil(4) * 4];

    let mut t = TcpHeader::new(seg.src.port(), seg.dst.port(), seg.seq.0, seg.wnd);
    t.acknowledgment_number = seg.ack.0;
    t.fin = seg.flags.contains(TcpFlags::FIN);
    t.syn = seg.flags.contains(TcpFlags::SYN);
    t.rst = seg.flags.contains(TcpFlags::RST);
    t.psh = seg.flags.contains(TcpFlags::PSH);
    t.ack = seg.flags.contains(TcpFlags::ACK);
    t.urg = seg.flags.contains(TcpFlags::URG);
    t.set_options_raw(opts)
        .map_err(|_| PacketError::OptionsTooLong)?;
    let tcp_len = t.header_len() + seg.payload.len();

    let (ip_len, ip_bytes, sum) = match (seg.src.ip(), seg.dst.ip()) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            let mut h = Ipv4Header::new(
                u16::try_from(tcp_len).map_err(|_| PacketError::TooLong)?,
                64,
                IpNumber::TCP,
                s.octets(),
                d.octets(),
            )
            .map_err(|_| PacketError::TooLong)?;
            h.identification = ip_id;
            h.dont_fragment = true;
            h.header_checksum = h.calc_header_checksum();
            let sum = t
                .calc_checksum_ipv4_raw(s.octets(), d.octets(), seg.payload)
                .map_err(|_| PacketError::TooLong)?;
            (Ipv4Header::MIN_LEN, h.to_bytes().to_vec(), sum)
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            let h = Ipv6Header {
                traffic_class: 0,
                flow_label: Ipv6FlowLabel::ZERO,
                payload_length: u16::try_from(tcp_len).map_err(|_| PacketError::TooLong)?,
                next_header: IpNumber::TCP,
                hop_limit: 64,
                source: s.octets(),
                destination: d.octets(),
            };
            let sum = t
                .calc_checksum_ipv6_raw(s.octets(), d.octets(), seg.payload)
                .map_err(|_| PacketError::TooLong)?;
            (Ipv6Header::LEN, h.to_bytes().to_vec(), sum)
        }
        _ => return Err(PacketError::FamilyMismatch),
    };
    t.checksum = sum;
    let total = ip_len + tcp_len;
    if buf.len() < total {
        return Err(PacketError::NoSpace);
    }
    buf[..ip_len].copy_from_slice(&ip_bytes);
    let th = t.to_bytes();
    buf[ip_len..ip_len + th.len()].copy_from_slice(&th);
    buf[ip_len + th.len()..total].copy_from_slice(seg.payload);
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn v4(sp: u16, dp: u16) -> (SocketAddr, SocketAddr) {
        (
            SocketAddr::new(Ipv4Addr::new(10, 0, 0, 1).into(), sp),
            SocketAddr::new(Ipv4Addr::new(10, 0, 0, 2).into(), dp),
        )
    }

    // MSS 1460, NOP, WS 7 (8 bytes, already aligned)
    const SYN_OPTS: [u8; 8] = [2, 4, 5, 0xb4, 1, 3, 3, 7];

    fn syn<'a>() -> Segment<'a> {
        let (src, dst) = v4(40000, 80);
        Segment {
            src,
            dst,
            seq: SeqNum(0xFFFF_FF00),
            ack: SeqNum(0),
            flags: TcpFlags::SYN,
            wnd: 65535,
            options: &SYN_OPTS,
            payload: &[],
        }
    }

    #[test]
    fn v4_build_parse_roundtrip() {
        let s = syn();
        let mut buf = [0u8; 100];
        let n = build(&s, 0x1234, &mut buf).unwrap();
        assert_eq!(n, 20 + 20 + 8);
        assert_eq!(buf[8], 64); // TTL
        assert_eq!(buf[6] & 0x40, 0x40); // DF
        assert_eq!(u16::from_be_bytes([buf[4], buf[5]]), 0x1234);
        assert_eq!(parse(&buf[..n]).unwrap(), s);
    }

    #[test]
    fn v6_build_parse_roundtrip() {
        let payload = [0xabu8; 1000];
        let s = Segment {
            src: SocketAddr::new(Ipv6Addr::LOCALHOST.into(), 1),
            dst: SocketAddr::new(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2).into(), 2),
            seq: SeqNum(5),
            ack: SeqNum(9),
            flags: TcpFlags::ACK | TcpFlags::PSH,
            wnd: 100,
            options: &[],
            payload: &payload,
        };
        let mut buf = [0u8; 2000];
        let n = build(&s, 0, &mut buf).unwrap();
        assert_eq!(n, 40 + 20 + 1000);
        assert_eq!(buf[7], 64); // hop limit
        assert_eq!(parse(&buf[..n]).unwrap(), s);
        // bytes beyond the IPv6 payload length are ignored
        assert_eq!(parse(&buf[..]).unwrap(), s);
    }

    #[test]
    fn options_padded_with_nop() {
        let mut s = syn();
        s.options = &[3, 3, 7]; // 3 bytes
        let mut buf = [0u8; 100];
        let n = build(&s, 1, &mut buf).unwrap();
        let p = parse(&buf[..n]).unwrap();
        assert_eq!(p.options, &[3, 3, 7, 1]);
    }

    #[test]
    fn bad_checksum_rejected() {
        let payload = [1u8, 2, 3, 4];
        let mut s = syn();
        s.flags = TcpFlags::ACK;
        s.options = &[];
        s.payload = &payload;
        let mut buf = [0u8; 100];
        let n = build(&s, 1, &mut buf).unwrap();
        buf[n - 1] ^= 1;
        assert_eq!(parse(&buf[..n]), Err(PacketError::Checksum));
    }

    #[test]
    fn bad_ip_header_checksum_rejected() {
        let mut buf = [0u8; 100];
        let n = build(&syn(), 1, &mut buf).unwrap();
        buf[8] ^= 1; // TTL
        assert_eq!(parse(&buf[..n]), Err(PacketError::IpChecksum));
    }

    #[test]
    fn truncated_rejected() {
        let mut buf = [0u8; 100];
        let n = build(&syn(), 1, &mut buf).unwrap();
        assert!(parse(&buf[..10]).is_err());
        for l in 0..n {
            assert!(parse(&buf[..l]).is_err(), "len {l}");
        }
        assert!(parse(&[]).is_err());
    }

    #[test]
    fn ipv4_fragment_rejected() {
        let mut buf = [0u8; 100];
        let n = build(&syn(), 1, &mut buf).unwrap();
        buf[6] |= 0x20; // MF
        let h = Ipv4Header::from_slice(&buf[..n]).unwrap().0;
        let c = h.calc_header_checksum().to_be_bytes();
        buf[10..12].copy_from_slice(&c);
        assert_eq!(parse(&buf[..n]), Err(PacketError::Fragment));
    }

    #[test]
    fn non_tcp_rejected() {
        let mut buf = [0u8; 100];
        let n = build(&syn(), 1, &mut buf).unwrap();
        buf[9] = 17;
        let h = Ipv4Header::from_slice(&buf[..n]).unwrap().0;
        let c = h.calc_header_checksum().to_be_bytes();
        buf[10..12].copy_from_slice(&c);
        assert_eq!(parse(&buf[..n]), Err(PacketError::NotTcp));
    }

    #[test]
    fn ipv4_options_ignored_and_trailing_bytes_ignored() {
        let mut buf = [0u8; 100];
        let n = build(&syn(), 1, &mut buf).unwrap();
        // splice a 4-byte IPv4 option (NOPs) after the fixed header: IHL 6
        let mut p = Vec::new();
        p.extend_from_slice(&buf[..20]);
        p.extend_from_slice(&[1, 1, 1, 0]);
        p.extend_from_slice(&buf[20..n]);
        p[0] = 0x46;
        p[2..4].copy_from_slice(&((n + 4) as u16).to_be_bytes());
        let h = Ipv4Header::from_slice(&p).unwrap().0;
        let c = h.calc_header_checksum().to_be_bytes();
        p[10..12].copy_from_slice(&c);
        p.extend_from_slice(&[9, 9, 9]); // trailing garbage
        assert_eq!(parse(&p).unwrap(), syn());
        // length field claims more than present
        let l = p.len();
        assert!(parse(&p[..l - 5]).is_err());
    }

    #[test]
    fn options_over_40_rejected() {
        let o = [1u8; 41];
        let mut s = syn();
        s.options = &o;
        let mut buf = [0u8; 200];
        assert_eq!(build(&s, 1, &mut buf), Err(PacketError::OptionsTooLong));
    }

    #[test]
    fn build_into_small_buffer_errors() {
        let mut buf = [0u8; 47];
        assert_eq!(build(&syn(), 1, &mut buf), Err(PacketError::NoSpace));
    }

    #[test]
    fn family_mismatch_rejected() {
        let mut s = syn();
        s.dst = SocketAddr::new(Ipv6Addr::LOCALHOST.into(), 80);
        let mut buf = [0u8; 100];
        assert_eq!(build(&s, 1, &mut buf), Err(PacketError::FamilyMismatch));
    }
}
