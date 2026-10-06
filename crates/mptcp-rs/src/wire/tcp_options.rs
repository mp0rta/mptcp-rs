//! Generic TCP option walker (RFC 9293 §3.1) and writers for MSS, window scale and SACK.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OptError {
    Truncated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpOpt<'a> {
    Mss(u16),
    WindowScale(u8),
    SackPermitted,
    /// Network-order pairs of left/right sequence edges (RFC 2018).
    Sack(&'a [u8]),
    Timestamps {
        val: u32,
        ecr: u32,
    },
    /// Whole MPTCP option including kind and length bytes.
    Mptcp(&'a [u8]),
    Unknown {
        kind: u8,
        data: &'a [u8],
    },
}

pub struct TcpOptions<'a> {
    rest: &'a [u8],
}

pub fn walk(raw: &[u8]) -> TcpOptions<'_> {
    TcpOptions { rest: raw }
}

impl<'a> Iterator for TcpOptions<'a> {
    type Item = Result<TcpOpt<'a>, OptError>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let kind = *self.rest.first()?;
            match kind {
                0 => {
                    self.rest = &[];
                    return None;
                }
                1 => {
                    self.rest = &self.rest[1..];
                    continue;
                }
                _ => {}
            }
            let len = self.rest.get(1).copied().map(usize::from).unwrap_or(0);
            let Some(opt) = self.rest.get(..len).filter(|_| len >= 2) else {
                self.rest = &[];
                return Some(Err(OptError::Truncated));
            };
            self.rest = &self.rest[len..];
            let d = &opt[2..];
            // Known kinds with a wrong length are reported as Unknown, not guessed at.
            return Some(Ok(match (kind, d.len()) {
                (2, 2) => TcpOpt::Mss(u16::from_be_bytes([d[0], d[1]])),
                (3, 1) => TcpOpt::WindowScale(d[0]),
                (4, 0) => TcpOpt::SackPermitted,
                (5, n) if n >= 8 && n % 8 == 0 => TcpOpt::Sack(d),
                (8, 8) => TcpOpt::Timestamps {
                    val: u32::from_be_bytes([d[0], d[1], d[2], d[3]]),
                    ecr: u32::from_be_bytes([d[4], d[5], d[6], d[7]]),
                },
                (super::mptcp::KIND_MPTCP, _) => TcpOpt::Mptcp(opt),
                _ => TcpOpt::Unknown { kind, data: d },
            }));
        }
    }
}

/// Writes MSS (4 bytes). `out` must hold at least 4 bytes.
pub fn write_mss(out: &mut [u8], mss: u16) -> usize {
    out[..2].copy_from_slice(&[2, 4]);
    out[2..4].copy_from_slice(&mss.to_be_bytes());
    4
}

/// Writes window scale followed by a NOP (4 bytes). `out` must hold at least 4 bytes.
pub fn write_ws(out: &mut [u8], shift: u8) -> usize {
    out[..4].copy_from_slice(&[3, 3, shift, 1]);
    4
}

/// Writes SACK-Permitted and two NOPs (4 bytes), for a SYN only.
pub fn write_sack_permitted(out: &mut [u8]) -> usize {
    out[..4].copy_from_slice(&[4, 2, 1, 1]);
    4
}

/// Writes as many blocks as fit, at most four, padded to a TCP header word boundary.
pub fn write_sack(out: &mut [u8], blocks: &[(u32, u32)]) -> usize {
    let count = blocks.len().min(4).min(out.len().saturating_sub(4) / 8);
    if count == 0 {
        return 0;
    }
    out[..2].copy_from_slice(&[5, (2 + 8 * count) as u8]);
    for (dst, &(left, right)) in out[2..2 + 8 * count].chunks_exact_mut(8).zip(blocks) {
        dst[..4].copy_from_slice(&left.to_be_bytes());
        dst[4..].copy_from_slice(&right.to_be_bytes());
    }
    let len = 4 + 8 * count;
    out[len - 2..len].fill(0);
    len
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn walk_mss_nop_ws_eol() {
        let raw = [2, 4, 0x05, 0xb4, 1, 3, 3, 7, 0, 0xff];
        let v: Vec<_> = walk(&raw).collect();
        assert_eq!(v, vec![Ok(TcpOpt::Mss(1460)), Ok(TcpOpt::WindowScale(7))]);
    }
    #[test]
    fn walk_truncated_length_errors_once() {
        let v: Vec<_> = walk(&[2, 4, 0x05]).collect();
        assert_eq!(v, vec![Err(OptError::Truncated)]);
    }
    #[test]
    fn walk_zero_length_errors() {
        assert_eq!(walk(&[30, 0, 0, 0]).next(), Some(Err(OptError::Truncated)));
    }
    #[test]
    fn walk_kind_without_length_byte_errors() {
        assert_eq!(
            walk(&[30]).collect::<Vec<_>>(),
            vec![Err(OptError::Truncated)]
        );
    }
    #[test]
    fn walk_sack_ts_mptcp_unknown() {
        let raw = [
            4, 2, 8, 10, 0, 0, 0, 1, 0, 0, 0, 2, 30, 4, 0x01, 0x01, 99, 3, 5,
        ];
        let v: Vec<_> = walk(&raw).collect();
        assert_eq!(
            v,
            vec![
                Ok(TcpOpt::SackPermitted),
                Ok(TcpOpt::Timestamps { val: 1, ecr: 2 }),
                Ok(TcpOpt::Mptcp(&[30, 4, 0x01, 0x01])),
                Ok(TcpOpt::Unknown {
                    kind: 99,
                    data: &[5]
                }),
            ]
        );
    }
    #[test]
    fn writers() {
        let mut b = [0u8; 4];
        assert_eq!(write_mss(&mut b, 1460), 4);
        assert_eq!(b, [2, 4, 0x05, 0xb4]);
        assert_eq!(write_ws(&mut b, 7), 4);
        assert_eq!(b, [3, 3, 7, 1]);
    }

    #[test]
    fn sack_writer_bounds_padding_and_wrapping_edges() {
        let blocks = [(u32::MAX - 5, 10), (20, 30), (40, 50), (60, 70), (80, 90)];
        for size in 0..=40 {
            let mut out = [0xcc; 40];
            let n = write_sack(&mut out[..size], &blocks);
            let count = size.saturating_sub(4) / 8;
            if count == 0 {
                assert_eq!(n, 0);
            } else {
                assert_eq!(n, 4 + 8 * count.min(4));
                assert_eq!(
                    walk(&out[..n]).next(),
                    Some(Ok(TcpOpt::Sack(&out[2..n - 2])))
                );
                assert_eq!(&out[2..6], &(u32::MAX - 5).to_be_bytes());
                assert_eq!(&out[6..10], &10u32.to_be_bytes());
                assert_eq!(&out[n - 2..n], &[0, 0]);
            }
            assert!(out[n..].iter().all(|&byte| byte == 0xcc));
        }
        let mut out = [0; 40];
        assert_eq!(write_sack(&mut out, &[]), 0);
        assert!(matches!(
            walk(&[5, 3, 1]).next(),
            Some(Ok(TcpOpt::Unknown { kind: 5, .. }))
        ));
        assert_eq!(walk(&[5, 10, 1]).next(), Some(Err(OptError::Truncated)));
    }
}
