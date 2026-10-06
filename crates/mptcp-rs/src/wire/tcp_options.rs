//! Generic TCP option walker (RFC 9293 §3.1) and writers for MSS / window scale.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OptError {
    Truncated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpOpt<'a> {
    Mss(u16),
    WindowScale(u8),
    SackPermitted,
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
}
