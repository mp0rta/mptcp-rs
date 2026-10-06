//! MPTCP option codec (RFC 8684 §3.1, §3.2, §3.3, §3.5, §7.2).

pub const KIND_MPTCP: u8 = 30;
pub const CAP_A: u8 = 0x80;
pub const CAP_B: u8 = 0x40;
pub const CAP_C: u8 = 0x20;
pub const CAP_H: u8 = 0x01;

const DSS_F: u8 = 0x10;
const DSS_M64: u8 = 0x08;
const DSS_M: u8 = 0x04;
const DSS_A64: u8 = 0x02;
const DSS_A: u8 = 0x01;

const ST_CAPABLE: u8 = 0x0;
const ST_JOIN: u8 = 0x1;
const ST_DSS: u8 = 0x2;
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
pub enum DataAck {
    Ack32(u32),
    Ack64(u64),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dsn {
    Dsn32(u32),
    Dsn64(u64),
}

/// Data Sequence Mapping. `data_len == 0` is an infinite mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mapping {
    pub dsn: Dsn,
    pub ssn: u32,
    pub data_len: u16,
    /// Present on the wire only if checksums were negotiated.
    pub checksum: Option<u16>,
}

/// DSS option. The M/m/A/a/F wire flags are derived from these fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Dss {
    pub data_fin: bool,
    pub data_ack: Option<DataAck>,
    pub mapping: Option<Mapping>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MptcpOption {
    Dss(Dss),
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

fn parse_dss(opt: &[u8]) -> Result<Dss, MptcpError> {
    let f = opt[3];
    let ack_len = match (f & DSS_A != 0, f & DSS_A64 != 0) {
        (false, _) => 0,
        (true, false) => 4,
        (true, true) => 8,
    };
    let dsn_len = if f & DSS_M64 != 0 { 8 } else { 4 };
    let base = 4 + ack_len;
    // Reserved bits are ignored; `a`/`m` are ignored without A/M.
    let has_map = f & DSS_M != 0;
    let has_ck = match (has_map, opt.len()) {
        (false, l) if l == base => false,
        (true, l) if l == base + dsn_len + 6 => false,
        (true, l) if l == base + dsn_len + 8 => true,
        _ => return Err(MptcpError::BadLength),
    };
    let data_ack = match ack_len {
        4 => Some(DataAck::Ack32(u32_at(opt, 4)?)),
        8 => Some(DataAck::Ack64(u64_at(opt, 4)?)),
        _ => None,
    };
    let mapping = if has_map {
        let o = base;
        let dsn = if dsn_len == 8 {
            Dsn::Dsn64(u64_at(opt, o)?)
        } else {
            Dsn::Dsn32(u32_at(opt, o)?)
        };
        let o = o + dsn_len;
        Some(Mapping {
            dsn,
            ssn: u32_at(opt, o)?,
            data_len: u16_at(opt, o + 4)?,
            checksum: if has_ck {
                Some(u16_at(opt, o + 6)?)
            } else {
                None
            },
        })
    } else {
        None
    };
    Ok(Dss {
        data_fin: f & DSS_F != 0,
        data_ack,
        mapping,
    })
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
        ST_DSS => parse_dss(opt).map(MptcpOption::Dss),
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
    let mut buf = [0u8; 28];
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
        MptcpOption::Dss(d) => {
            // RFC 8684 §3.3.3: DATA_FIN always rides on a mapping.
            if d.data_fin && d.mapping.is_none() {
                return Err(MptcpError::InvalidFields);
            }
            let mut f = if d.data_fin { DSS_F } else { 0 };
            let mut n = 4;
            match d.data_ack {
                Some(DataAck::Ack32(a)) => {
                    f |= DSS_A;
                    buf[n..n + 4].copy_from_slice(&a.to_be_bytes());
                    n += 4;
                }
                Some(DataAck::Ack64(a)) => {
                    f |= DSS_A | DSS_A64;
                    buf[n..n + 8].copy_from_slice(&a.to_be_bytes());
                    n += 8;
                }
                None => {}
            }
            if let Some(m) = &d.mapping {
                f |= DSS_M;
                match m.dsn {
                    Dsn::Dsn32(v) => {
                        buf[n..n + 4].copy_from_slice(&v.to_be_bytes());
                        n += 4;
                    }
                    Dsn::Dsn64(v) => {
                        f |= DSS_M64;
                        buf[n..n + 8].copy_from_slice(&v.to_be_bytes());
                        n += 8;
                    }
                }
                buf[n..n + 4].copy_from_slice(&m.ssn.to_be_bytes());
                buf[n + 4..n + 6].copy_from_slice(&m.data_len.to_be_bytes());
                n += 6;
                if let Some(c) = m.checksum {
                    buf[n..n + 2].copy_from_slice(&c.to_be_bytes());
                    n += 2;
                }
            }
            buf[2] = ST_DSS << 4;
            buf[3] = f;
            n
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

    fn dss(m: Option<Mapping>, a: Option<DataAck>, fin: bool) -> MptcpOption {
        MptcpOption::Dss(Dss {
            data_fin: fin,
            data_ack: a,
            mapping: m,
        })
    }
    fn map(dsn: Dsn, ck: Option<u16>) -> Mapping {
        Mapping {
            dsn,
            ssn: 0x0a0b0c0d,
            data_len: 1400,
            checksum: ck,
        }
    }
    #[test]
    fn dss_ack64_only_is_12() {
        let d = dss(None, Some(DataAck::Ack64(7)), false);
        let mut b = [0u8; 40];
        assert_eq!(encode(&d, &mut b).unwrap(), 12);
        assert_eq!(&b[..4], &[30, 12, 0x20, 0x03]);
        assert_eq!(&b[4..12], &7u64.to_be_bytes());
        assert_eq!(parse(&b[..12]).unwrap(), d);
    }
    #[test]
    fn dss_ack64_map64_is_26() {
        let d = dss(
            Some(map(Dsn::Dsn64(KA), None)),
            Some(DataAck::Ack64(KB)),
            false,
        );
        let w = roundtrip(d);
        assert_eq!(w.len(), 26);
        assert_eq!(&w[..4], &[30, 26, 0x20, 0x0f]);
        assert_eq!(&w[4..12], &KB.to_be_bytes());
        assert_eq!(&w[12..20], &KA.to_be_bytes());
        assert_eq!(&w[20..24], &[0x0a, 0x0b, 0x0c, 0x0d]);
        assert_eq!(&w[24..], &1400u16.to_be_bytes());
    }
    #[test]
    fn dss_full_with_checksum_is_28() {
        let d = dss(
            Some(map(Dsn::Dsn64(KA), Some(0xbeef))),
            Some(DataAck::Ack64(KB)),
            false,
        );
        let w = roundtrip(d);
        assert_eq!(w.len(), 28);
        assert_eq!(&w[..4], &[30, 28, 0x20, 0x0f]);
        assert_eq!(&w[26..], &[0xbe, 0xef]);
    }
    #[test]
    fn dss_32bit_fields_roundtrip() {
        let d = dss(
            Some(map(Dsn::Dsn32(0x11223344), Some(0x1234))),
            Some(DataAck::Ack32(0x55667788)),
            false,
        );
        let w = roundtrip(d);
        assert_eq!(w.len(), 4 + 4 + 4 + 4 + 2 + 2);
        assert_eq!(&w[..4], &[30, 20, 0x20, 0x05]);
        assert_eq!(&w[4..8], &[0x55, 0x66, 0x77, 0x88]);
        assert_eq!(&w[8..12], &[0x11, 0x22, 0x33, 0x44]);
        // Without checksum: 4+4+4+4+2 = 18.
        let w = roundtrip(dss(
            Some(map(Dsn::Dsn32(1), None)),
            Some(DataAck::Ack32(2)),
            false,
        ));
        assert_eq!(w.len(), 18);
    }
    #[test]
    fn dss_data_fin_flag() {
        let d = dss(Some(map(Dsn::Dsn64(KA), None)), None, true);
        let w = roundtrip(d);
        assert_eq!(w[3], 0x10 | 0x08 | 0x04);
        match parse(&w).unwrap() {
            MptcpOption::Dss(x) => assert!(x.data_fin),
            _ => panic!(),
        }
    }
    #[test]
    fn dss_data_fin_without_mapping_is_invalid() {
        // RFC 8684 s3.3.3: a bare DATA_FIN still carries a mapping (len 1).
        for a in [None, Some(DataAck::Ack32(1))] {
            assert_eq!(
                encode(&dss(None, a, true), &mut [0u8; 40]),
                Err(MptcpError::InvalidFields)
            );
        }
    }
    #[test]
    fn dss_infinite_mapping_parses() {
        let mut m = map(Dsn::Dsn64(KA), None);
        m.data_len = 0;
        roundtrip(dss(Some(m), None, false));
    }
    #[test]
    fn dss_length_flag_mismatch_is_error() {
        // A|a set (needs 12) but length 8.
        assert_eq!(
            parse(&[30, 8, 0x20, 0x03, 0, 0, 0, 0]),
            Err(MptcpError::BadLength)
        );
        // A only, 4-byte ack, but length 12.
        assert_eq!(
            parse(&[30, 12, 0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0]),
            Err(MptcpError::BadLength)
        );
        // M|m needs 20 or 22; 21 is wrong.
        let mut b = [0u8; 21];
        b[..4].copy_from_slice(&[30, 21, 0x20, 0x0c]);
        assert_eq!(parse(&b), Err(MptcpError::BadLength));
        // No A, no M: only the bare 4-byte form is valid.
        assert_eq!(parse(&[30, 4, 0x20, 0x00]).map(|_| ()), Ok(()));
        assert_eq!(
            parse(&[30, 8, 0x20, 0x00, 0, 0, 0, 0]),
            Err(MptcpError::BadLength)
        );
    }
    #[test]
    fn dss_reserved_bits_ignored() {
        let mut w = [30u8, 8, 0x20, 0xe3, 0, 0, 0, 9];
        // 0xe3 = reserved bits + a + A; a without room is a length error, so use 12.
        assert_eq!(parse(&w), Err(MptcpError::BadLength));
        let mut b = [0u8; 12];
        b[..4].copy_from_slice(&[30, 12, 0x20, 0xe3]);
        b[11] = 7;
        assert_eq!(
            parse(&b).unwrap(),
            dss(None, Some(DataAck::Ack64(7)), false)
        );
        w[3] = 0xe1;
        assert_eq!(parse(&w[..4]), Err(MptcpError::BadLength));
    }
}
