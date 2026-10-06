//! MPTCP option codec (RFC 8684 §3.1, §3.2, §3.5, §7.2). DSS is added by a later task.

pub const KIND_MPTCP: u8 = 30;
pub const CAP_A: u8 = 0x80;
pub const CAP_B: u8 = 0x40;
pub const CAP_C: u8 = 0x20;
pub const CAP_H: u8 = 0x01;

const ST_CAPABLE: u8 = 0x0;
const ST_JOIN: u8 = 0x1;
const ST_FASTCLOSE: u8 = 0x7;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MptcpError {
    /// Option length or kind is not valid for its subtype.
    BadLength,
    /// Output buffer too small.
    NoSpace,
    /// Field combination or value has no defined wire form.
    InvalidFields,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MpCapable {
    pub version: u8,
    pub flags: u8,
    pub sender_key: Option<u64>,
    pub receiver_key: Option<u64>,
    pub data_len: Option<u16>,
    pub checksum: Option<u16>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MpJoin {
    Syn {
        backup: bool,
        addr_id: u8,
        token: u32,
        nonce: u32,
    },
    SynAck {
        backup: bool,
        addr_id: u8,
        hmac64: u64,
        nonce: u32,
    },
    Ack {
        hmac160: [u8; 20],
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MptcpOption {
    Capable(MpCapable),
    Join(MpJoin),
    FastClose { receiver_key: u64 },
    Unknown { subtype: u8 },
}

fn u64_at(b: &[u8], i: usize) -> Result<u64, MptcpError> {
    let s = b.get(i..i + 8).ok_or(MptcpError::BadLength)?;
    Ok(u64::from_be_bytes(s.try_into().unwrap()))
}
fn u32_at(b: &[u8], i: usize) -> Result<u32, MptcpError> {
    let s = b.get(i..i + 4).ok_or(MptcpError::BadLength)?;
    Ok(u32::from_be_bytes(s.try_into().unwrap()))
}
fn u16_at(b: &[u8], i: usize) -> Result<u16, MptcpError> {
    let s = b.get(i..i + 2).ok_or(MptcpError::BadLength)?;
    Ok(u16::from_be_bytes(s.try_into().unwrap()))
}

pub fn parse(opt: &[u8]) -> Result<MptcpOption, MptcpError> {
    let (&kind, &len, &b2) = match opt {
        [k, l, b, ..] => (k, l, b),
        _ => return Err(MptcpError::BadLength),
    };
    let len = usize::from(len);
    if kind != KIND_MPTCP || len != opt.len() || len < 4 {
        return Err(MptcpError::BadLength);
    }
    match b2 >> 4 {
        ST_CAPABLE => {
            let mut c = MpCapable {
                version: b2 & 0x0f,
                flags: opt[3],
                sender_key: None,
                receiver_key: None,
                data_len: None,
                checksum: None,
            };
            match len {
                4 => {}
                12 | 20 | 22 | 24 => {
                    c.sender_key = Some(u64_at(opt, 4)?);
                    if len >= 20 {
                        c.receiver_key = Some(u64_at(opt, 12)?);
                    }
                    if len >= 22 {
                        c.data_len = Some(u16_at(opt, 20)?);
                    }
                    if len == 24 {
                        c.checksum = Some(u16_at(opt, 22)?);
                    }
                }
                _ => return Err(MptcpError::BadLength),
            }
            Ok(MptcpOption::Capable(c))
        }
        ST_JOIN => {
            let backup = b2 & 1 != 0;
            let addr_id = opt[3];
            Ok(MptcpOption::Join(match len {
                12 => MpJoin::Syn {
                    backup,
                    addr_id,
                    token: u32_at(opt, 4)?,
                    nonce: u32_at(opt, 8)?,
                },
                16 => MpJoin::SynAck {
                    backup,
                    addr_id,
                    hmac64: u64_at(opt, 4)?,
                    nonce: u32_at(opt, 12)?,
                },
                24 => MpJoin::Ack {
                    hmac160: opt[4..24].try_into().unwrap(),
                },
                _ => return Err(MptcpError::BadLength),
            }))
        }
        ST_FASTCLOSE => {
            if len != 12 {
                return Err(MptcpError::BadLength);
            }
            Ok(MptcpOption::FastClose {
                receiver_key: u64_at(opt, 4)?,
            })
        }
        subtype => Ok(MptcpOption::Unknown { subtype }),
    }
}

pub fn encode(o: &MptcpOption, out: &mut [u8]) -> Result<usize, MptcpError> {
    let mut buf = [0u8; 24];
    let len = match o {
        MptcpOption::Capable(c) => {
            if c.version > 0x0f {
                return Err(MptcpError::InvalidFields);
            }
            let len = match (c.sender_key, c.receiver_key, c.data_len, c.checksum) {
                (None, None, None, None) => 4,
                (Some(_), None, None, None) => 12,
                (Some(_), Some(_), None, None) => 20,
                (Some(_), Some(_), Some(_), None) => 22,
                (Some(_), Some(_), Some(_), Some(_)) => 24,
                _ => return Err(MptcpError::InvalidFields),
            };
            buf[2] = (ST_CAPABLE << 4) | c.version;
            buf[3] = c.flags;
            if let Some(k) = c.sender_key {
                buf[4..12].copy_from_slice(&k.to_be_bytes());
            }
            if let Some(k) = c.receiver_key {
                buf[12..20].copy_from_slice(&k.to_be_bytes());
            }
            if let Some(d) = c.data_len {
                buf[20..22].copy_from_slice(&d.to_be_bytes());
            }
            if let Some(s) = c.checksum {
                buf[22..24].copy_from_slice(&s.to_be_bytes());
            }
            len
        }
        MptcpOption::Join(MpJoin::Syn {
            backup,
            addr_id,
            token,
            nonce,
        }) => {
            buf[2] = (ST_JOIN << 4) | u8::from(*backup);
            buf[3] = *addr_id;
            buf[4..8].copy_from_slice(&token.to_be_bytes());
            buf[8..12].copy_from_slice(&nonce.to_be_bytes());
            12
        }
        MptcpOption::Join(MpJoin::SynAck {
            backup,
            addr_id,
            hmac64,
            nonce,
        }) => {
            buf[2] = (ST_JOIN << 4) | u8::from(*backup);
            buf[3] = *addr_id;
            buf[4..12].copy_from_slice(&hmac64.to_be_bytes());
            buf[12..16].copy_from_slice(&nonce.to_be_bytes());
            16
        }
        MptcpOption::Join(MpJoin::Ack { hmac160 }) => {
            buf[2] = ST_JOIN << 4;
            buf[4..24].copy_from_slice(hmac160);
            24
        }
        MptcpOption::FastClose { receiver_key } => {
            buf[2] = ST_FASTCLOSE << 4;
            buf[4..12].copy_from_slice(&receiver_key.to_be_bytes());
            12
        }
        // Unknown carries no payload, so there is nothing defined to write.
        MptcpOption::Unknown { .. } => return Err(MptcpError::InvalidFields),
    };
    let dst = out.get_mut(..len).ok_or(MptcpError::NoSpace)?;
    buf[0] = KIND_MPTCP;
    buf[1] = len as u8;
    dst.copy_from_slice(&buf[..len]);
    Ok(len)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KA: u64 = 0x0102030405060708;
    const KB: u64 = 0x1112131415161718;

    fn cap(sk: Option<u64>, rk: Option<u64>, dl: Option<u16>, ck: Option<u16>) -> MptcpOption {
        MptcpOption::Capable(MpCapable {
            version: 1,
            flags: CAP_A | CAP_H,
            sender_key: sk,
            receiver_key: rk,
            data_len: dl,
            checksum: ck,
        })
    }
    fn fastclose(k: u64) -> MptcpOption {
        MptcpOption::FastClose { receiver_key: k }
    }
    fn roundtrip(o: MptcpOption) -> Vec<u8> {
        let mut b = [0u8; 40];
        let n = encode(&o, &mut b).unwrap();
        assert_eq!(usize::from(b[1]), n);
        assert_eq!(parse(&b[..n]).unwrap(), o);
        b[..n].to_vec()
    }

    #[test]
    fn capable_syn_roundtrip() {
        let o = MptcpOption::Capable(MpCapable {
            version: 1,
            flags: CAP_H,
            sender_key: None,
            receiver_key: None,
            data_len: None,
            checksum: None,
        });
        let mut b = [0u8; 40];
        let n = encode(&o, &mut b).unwrap();
        assert_eq!(&b[..n], &[30, 4, 0x01, 0x01]);
        assert_eq!(parse(&b[..n]).unwrap(), o);
    }
    #[test]
    fn capable_lengths_12_20_22_24_roundtrip() {
        let cases = [
            (cap(Some(KA), None, None, None), 12),
            (cap(Some(KA), Some(KB), None, None), 20),
            (cap(Some(KA), Some(KB), Some(1400), None), 22),
            (cap(Some(KA), Some(KB), Some(1400), Some(0xabcd)), 24),
        ];
        for (o, len) in cases {
            let w = roundtrip(o);
            assert_eq!(w.len(), len);
            assert_eq!(&w[..4], &[30, len as u8, 0x01, CAP_A | CAP_H]);
        }
        let w = roundtrip(cap(Some(KA), Some(KB), Some(1400), Some(0xabcd)));
        assert_eq!(&w[4..12], &KA.to_be_bytes());
        assert_eq!(&w[12..20], &KB.to_be_bytes());
        assert_eq!(&w[20..], &[0x05, 0x78, 0xab, 0xcd]);
    }
    #[test]
    fn capable_rejects_undefined_field_combinations() {
        for o in [
            cap(None, Some(KB), None, None),
            cap(Some(KA), None, Some(1), None),
            cap(Some(KA), Some(KB), None, Some(1)),
            cap(None, None, Some(1), None),
        ] {
            assert_eq!(encode(&o, &mut [0u8; 40]), Err(MptcpError::InvalidFields));
        }
        let o = MptcpOption::Capable(MpCapable {
            version: 16,
            flags: 0,
            sender_key: None,
            receiver_key: None,
            data_len: None,
            checksum: None,
        });
        assert_eq!(encode(&o, &mut [0u8; 40]), Err(MptcpError::InvalidFields));
    }
    #[test]
    fn join_syn_synack_ack_roundtrip() {
        let w = roundtrip(MptcpOption::Join(MpJoin::Syn {
            backup: true,
            addr_id: 5,
            token: 0xdeadbeef,
            nonce: 0x01020304,
        }));
        assert_eq!(w.len(), 12);
        assert_eq!(&w[..4], &[30, 12, 0x11, 5]);
        assert_eq!(&w[4..], &[0xde, 0xad, 0xbe, 0xef, 1, 2, 3, 4]);

        let w = roundtrip(MptcpOption::Join(MpJoin::SynAck {
            backup: false,
            addr_id: 6,
            hmac64: KA,
            nonce: 0x0a0b0c0d,
        }));
        assert_eq!(w.len(), 16);
        assert_eq!(&w[..4], &[30, 16, 0x10, 6]);
        assert_eq!(&w[4..12], &KA.to_be_bytes());
        assert_eq!(&w[12..], &[0x0a, 0x0b, 0x0c, 0x0d]);

        let mut h = [0u8; 20];
        for (i, x) in h.iter_mut().enumerate() {
            *x = i as u8 + 1;
        }
        let w = roundtrip(MptcpOption::Join(MpJoin::Ack { hmac160: h }));
        assert_eq!(w.len(), 24);
        assert_eq!(&w[..4], &[30, 24, 0x10, 0]);
        assert_eq!(&w[4..], &h);
    }
    #[test]
    fn fastclose_roundtrip() {
        let w = roundtrip(fastclose(KB));
        assert_eq!(w.len(), 12);
        assert_eq!(&w[..4], &[30, 12, 0x70, 0]);
        assert_eq!(&w[4..], &KB.to_be_bytes());
    }
    #[test]
    fn unknown_subtype_is_not_error() {
        assert_eq!(
            parse(&[30, 4, 0x50, 0]).unwrap(),
            MptcpOption::Unknown { subtype: 5 }
        );
        // DSS is parsed by a later task; until then it is Unknown.
        assert_eq!(
            parse(&[30, 4, 0x20, 0]).unwrap(),
            MptcpOption::Unknown { subtype: 2 }
        );
    }
    #[test]
    fn bad_lengths_are_errors() {
        for b in [
            &[30u8, 3, 0][..],
            &[30, 5, 0x01, 0x01, 0],
            &[30, 13, 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            &[],
            &[30],
            &[31, 4, 0x50, 0],
            &[30, 12, 0x70, 0, 0, 0, 0, 0, 0, 0, 0],
            &[30, 8, 0x70, 0, 0, 0, 0, 0],
        ] {
            assert!(parse(b).is_err(), "{b:?}");
        }
    }
    #[test]
    fn encode_no_space() {
        assert_eq!(
            encode(&fastclose(1), &mut [0u8; 11]),
            Err(MptcpError::NoSpace)
        );
        assert_eq!(encode(&fastclose(1), &mut [0u8; 12]), Ok(12));
    }
}
