//! MPTCP option codec (RFC 8684 §3.1, §3.2, §3.3, §3.4, §3.5, §3.6, §7.2).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

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
const ST_ADD_ADDR: u8 = 0x3;
const ST_REMOVE_ADDR: u8 = 0x4;
const ST_PRIO: u8 = 0x5;
const ST_FASTCLOSE: u8 = 0x7;
const ST_TCPRST: u8 = 0x8;

const ADD_ADDR_E: u8 = 0x01;
const PRIO_B: u8 = 0x01;
const TCPRST_T: u8 = 0x01;
const MAX_REMOVE_IDS: usize = 37;

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

/// The address ids of a REMOVE_ADDR: 1 to 37 (40 option bytes minus 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RemoveIds {
    ids: [u8; MAX_REMOVE_IDS],
    len: u8,
}

impl RemoveIds {
    /// `None` if `ids` is empty or longer than 37.
    pub fn new(ids: &[u8]) -> Option<Self> {
        if ids.is_empty() || ids.len() > MAX_REMOVE_IDS {
            return None;
        }
        let mut r = Self {
            ids: [0; MAX_REMOVE_IDS],
            len: ids.len() as u8,
        };
        r.ids[..ids.len()].copy_from_slice(ids);
        Some(r)
    }
    pub fn len(&self) -> usize {
        usize::from(self.len)
    }
    pub fn is_empty(&self) -> bool {
        false
    }
    pub fn iter(&self) -> impl Iterator<Item = u8> + '_ {
        self.ids[..self.len()].iter().copied()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum MptcpOption {
    Dss(Dss),
    Capable(MpCapable),
    Join(MpJoin),
    FastClose {
        receiver_key: u64,
    },
    /// `hmac` is `Some` exactly when `echo` is false.
    AddAddr {
        echo: bool,
        id: u8,
        addr: IpAddr,
        port: Option<u16>,
        hmac: Option<u64>,
    },
    RemoveAddr {
        ids: RemoveIds,
    },
    Prio {
        backup: bool,
    },
    TcpRst {
        transient: bool,
        reason: u8,
    },
    Unknown {
        subtype: u8,
    },
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
    // RFC 8684 §3.3/§3.3.3: F has no meaning without a mapping (matches encode).
    if f & DSS_F != 0 && !has_map {
        return Err(MptcpError::InvalidFields);
    }
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
    // Only MP_PRIO and REMOVE_ADDR (which then fails below) may be 3 bytes long.
    let short_ok = matches!(b2 >> 4, ST_PRIO | ST_REMOVE_ADDR);
    if kind != KIND_MPTCP || len != opt.len() || len < 3 || (len == 3 && !short_ok) {
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
        ST_ADD_ADDR => {
            let (v6, port, hmac) = match len {
                8 | 10 | 16 | 18 => (false, len & 2 != 0 || len == 18, len >= 16),
                20 | 22 | 28 | 30 => (true, len == 22 || len == 30, len >= 28),
                _ => return Err(MptcpError::BadLength),
            };
            // E=0 carries the HMAC and E=1 does not; reserved flag bits are ignored.
            if (b2 & ADD_ADDR_E == 0) != hmac {
                return Err(MptcpError::BadLength);
            }
            let alen = if v6 { 16 } else { 4 };
            let a = &opt[4..4 + alen];
            let addr = if v6 {
                IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(a).unwrap()))
            } else {
                IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(a).unwrap()))
            };
            let mut o = 4 + alen;
            let port = if port {
                o += 2;
                Some(u16_at(opt, o - 2)?)
            } else {
                None
            };
            Ok(MptcpOption::AddAddr {
                echo: !hmac,
                id: opt[3],
                addr,
                port,
                hmac: if hmac { Some(u64_at(opt, o)?) } else { None },
            })
        }
        ST_REMOVE_ADDR => Ok(MptcpOption::RemoveAddr {
            ids: RemoveIds::new(&opt[3..]).ok_or(MptcpError::BadLength)?,
        }),
        ST_PRIO => {
            if len != 3 {
                return Err(MptcpError::BadLength);
            }
            Ok(MptcpOption::Prio {
                backup: b2 & PRIO_B != 0,
            })
        }
        ST_TCPRST => {
            if len != 4 {
                return Err(MptcpError::BadLength);
            }
            Ok(MptcpOption::TcpRst {
                transient: b2 & TCPRST_T != 0,
                reason: opt[3],
            })
        }
        subtype => Ok(MptcpOption::Unknown { subtype }),
    }
}

pub fn encode(o: &MptcpOption, out: &mut [u8]) -> Result<usize, MptcpError> {
    let mut buf = [0u8; 40];
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
        MptcpOption::AddAddr {
            echo,
            id,
            addr,
            port,
            hmac,
        } => {
            if *echo == hmac.is_some() {
                return Err(MptcpError::InvalidFields);
            }
            buf[2] = (ST_ADD_ADDR << 4) | if *echo { ADD_ADDR_E } else { 0 };
            buf[3] = *id;
            let mut n = 4;
            match addr {
                IpAddr::V4(a) => {
                    buf[n..n + 4].copy_from_slice(&a.octets());
                    n += 4;
                }
                IpAddr::V6(a) => {
                    buf[n..n + 16].copy_from_slice(&a.octets());
                    n += 16;
                }
            }
            if let Some(p) = port {
                buf[n..n + 2].copy_from_slice(&p.to_be_bytes());
                n += 2;
            }
            if let Some(h) = hmac {
                buf[n..n + 8].copy_from_slice(&h.to_be_bytes());
                n += 8;
            }
            n
        }
        MptcpOption::RemoveAddr { ids } => {
            buf[2] = ST_REMOVE_ADDR << 4;
            for (i, id) in ids.iter().enumerate() {
                buf[3 + i] = id;
            }
            3 + ids.len()
        }
        MptcpOption::Prio { backup } => {
            buf[2] = (ST_PRIO << 4) | if *backup { PRIO_B } else { 0 };
            3
        }
        MptcpOption::TcpRst { transient, reason } => {
            buf[2] = (ST_TCPRST << 4) | if *transient { TCPRST_T } else { 0 };
            buf[3] = *reason;
            4
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
            parse(&[30, 4, 0x90, 0]).unwrap(),
            MptcpOption::Unknown { subtype: 9 }
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
        let mut b = [0u8; 12];
        b[..4].copy_from_slice(&[30, 12, 0x20, 0xe3]);
        b[11] = 7;
        assert_eq!(
            parse(&b).unwrap(),
            dss(None, Some(DataAck::Ack64(7)), false)
        );
        // Reserved bits with M|m set parse like 0x0C.
        let mut m = [0u8; 18];
        m[..4].copy_from_slice(&[30, 18, 0x20, 0x0c]);
        let plain = parse(&m).unwrap();
        m[3] = 0xec;
        assert_eq!(parse(&m).unwrap(), plain);
    }
    #[test]
    fn dss_data_fin_without_mapping_rejected_on_parse() {
        assert_eq!(parse(&[30, 4, 0x20, 0x10]), Err(MptcpError::InvalidFields));
        assert_eq!(
            parse(&[30, 8, 0x20, 0x11, 0, 0, 0, 0]),
            Err(MptcpError::InvalidFields)
        );
    }

    fn add_addr(echo: bool, addr: IpAddr, port: Option<u16>) -> MptcpOption {
        MptcpOption::AddAddr {
            echo,
            id: 7,
            addr,
            port,
            hmac: (!echo).then_some(KA),
        }
    }
    #[test]
    fn add_addr_lengths_v4_v6() {
        let v4 = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let v6 = IpAddr::V6("2001:db8::1".parse().unwrap());
        let mut ok = Vec::new();
        for (addr, base) in [(v4, 8), (v6, 20)] {
            for (echo, port, len) in [
                (true, None, base),
                (true, Some(4321), base + 2),
                (false, None, base + 8),
                (false, Some(4321), base + 10),
            ] {
                let w = roundtrip(add_addr(echo, addr, port));
                assert_eq!(w.len(), len);
                assert_eq!(w[2], 0x30 | u8::from(echo));
                assert_eq!(w[3], 7);
                ok.push(len);
            }
        }
        assert_eq!(ok, [8, 10, 16, 18, 20, 22, 28, 30]);
        for len in 0..=40usize {
            if ok.contains(&len) || len < 4 {
                continue;
            }
            let mut b = vec![0u8; len];
            b[..4].copy_from_slice(&[30, len as u8, 0x31, 0]);
            assert_eq!(parse(&b), Err(MptcpError::BadLength), "{len}");
            b[2] = 0x30;
            assert_eq!(parse(&b), Err(MptcpError::BadLength), "{len}");
        }
        // The E flag must agree with the length.
        for (len, flags) in [(8, 0x30), (16, 0x31), (20, 0x30), (28, 0x31)] {
            let mut b = vec![0u8; len];
            b[..4].copy_from_slice(&[30, len as u8, flags, 0]);
            assert_eq!(parse(&b), Err(MptcpError::BadLength), "{len}");
        }
        // Option bytes after the 4-byte header: address, then port, then HMAC.
        let w = roundtrip(add_addr(false, v4, Some(0x1234)));
        assert_eq!(&w[4..8], &[192, 0, 2, 1]);
        assert_eq!(&w[8..10], &[0x12, 0x34]);
        assert_eq!(&w[10..], &KA.to_be_bytes());
        // E and HMAC must agree on encode.
        let bad = MptcpOption::AddAddr {
            echo: true,
            id: 1,
            addr: v4,
            port: None,
            hmac: Some(1),
        };
        assert_eq!(encode(&bad, &mut [0u8; 40]), Err(MptcpError::InvalidFields));
        let bad = MptcpOption::AddAddr {
            echo: false,
            id: 1,
            addr: v4,
            port: None,
            hmac: None,
        };
        assert_eq!(encode(&bad, &mut [0u8; 40]), Err(MptcpError::InvalidFields));
    }
    #[test]
    fn add_addr_reserved_flags_ignored() {
        let v4 = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let w = roundtrip(add_addr(true, v4, None));
        assert_eq!(w[2] & 0x0e, 0);
        let mut b = w.clone();
        b[2] = 0x3f;
        assert_eq!(parse(&b), parse(&w));
        let w = roundtrip(add_addr(false, v4, None));
        assert_eq!(w[2], 0x30);
        let mut b = w.clone();
        b[2] = 0x3e;
        assert_eq!(parse(&b), parse(&w));
    }
    #[test]
    fn remove_addr_one_and_many() {
        for ids in [&[1u8][..], &[1, 25]] {
            let o = MptcpOption::RemoveAddr {
                ids: RemoveIds::new(ids).unwrap(),
            };
            let w = roundtrip(o);
            assert_eq!(&w[..3], &[30, 3 + ids.len() as u8, 0x40]);
            assert_eq!(&w[3..], ids);
            match parse(&w).unwrap() {
                MptcpOption::RemoveAddr { ids: r } => {
                    assert_eq!(r.len(), ids.len());
                    assert_eq!(r.iter().collect::<Vec<_>>(), ids);
                }
                _ => panic!(),
            }
        }
        assert_eq!(parse(&[30, 3, 0x40]), Err(MptcpError::BadLength));
        let max = [9u8; 37];
        roundtrip(MptcpOption::RemoveAddr {
            ids: RemoveIds::new(&max).unwrap(),
        });
        assert!(RemoveIds::new(&[]).is_none());
        assert!(RemoveIds::new(&[0; 38]).is_none());
        // Reserved nibble bits are ignored.
        assert_eq!(parse(&[30, 4, 0x4f, 2]), parse(&[30, 4, 0x40, 2]));
    }
    #[test]
    fn mp_prio_b_bit_reserved_ignored() {
        assert_eq!(roundtrip(MptcpOption::Prio { backup: true }), [30, 3, 0x51]);
        assert_eq!(
            roundtrip(MptcpOption::Prio { backup: false }),
            [30, 3, 0x50]
        );
        assert_eq!(
            parse(&[30, 3, 0x5f]),
            Ok(MptcpOption::Prio { backup: true })
        );
        assert_eq!(
            parse(&[30, 3, 0x5e]),
            Ok(MptcpOption::Prio { backup: false })
        );
        assert_eq!(parse(&[30, 4, 0x51, 0]), Err(MptcpError::BadLength));
    }
    #[test]
    fn tcprst_flags_uvw_ignored_on_parse_zero_on_encode() {
        let o = MptcpOption::TcpRst {
            transient: true,
            reason: 2,
        };
        assert_eq!(roundtrip(o), [30, 4, 0x81, 2]);
        let o = MptcpOption::TcpRst {
            transient: false,
            reason: 6,
        };
        assert_eq!(roundtrip(o), [30, 4, 0x80, 6]);
        assert_eq!(
            parse(&[30, 4, 0x8e, 6]),
            Ok(MptcpOption::TcpRst {
                transient: false,
                reason: 6
            })
        );
        assert_eq!(parse(&[30, 5, 0x80, 6, 0]), Err(MptcpError::BadLength));
    }
    #[test]
    fn mp_fail_stays_unknown() {
        assert_eq!(
            parse(&[30, 12, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
            Ok(MptcpOption::Unknown { subtype: 6 })
        );
    }
}
