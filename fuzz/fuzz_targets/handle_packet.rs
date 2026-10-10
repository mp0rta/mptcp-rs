#![no_main]
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use libfuzzer_sys::fuzz_target;
use mptcp_rs::wire::packet::{Segment, TcpFlags, build, parse};
use mptcp_rs::{ConnectConfig, Endpoint, Event, Instant};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

fn drain(ep: &mut Endpoint<ChaCha20Rng>, now: Instant) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut buf = [0u8; 65535];
    while let Some(n) = ep.poll_transmit(now, &mut buf) {
        out.push(buf[..n].to_vec());
    }
    out
}

/// A well-formed-header option of one of the new subtypes (ADD_ADDR, REMOVE_ADDR, MP_PRIO,
/// MP_TCPRST): `sel` picks subtype and length, `b` fills the rest.
fn synth(sel: u8, b: &[u8]) -> Vec<u8> {
    let n = usize::from(sel / 4);
    let (st, len) = match sel % 4 {
        0 => (3, [8, 10, 16, 18, 20, 22, 28, 30][n % 8]),
        1 => (4, 4 + n % 37),
        2 => (5, 3),
        _ => (8, 4),
    };
    let mut o = vec![0; len];
    for (i, x) in o[2..].iter_mut().enumerate() {
        *x = b.get(i).copied().unwrap_or(0);
    }
    o[0] = 30;
    o[1] = len as u8;
    // E=1 exactly for the lengths without an HMAC.
    let low = if st == 3 {
        o[2] & 0x0e | u8::from(matches!(len, 8 | 10 | 20 | 22))
    } else {
        o[2] & 0x0f
    };
    o[2] = st << 4 | low;
    o
}

fuzz_target!(|data: &[u8]| {
    let now = Instant::from_nanos(1_000_000_000);
    let mut ep = Endpoint::new(ChaCha20Rng::seed_from_u64(1));
    let local = IpAddr::V4(Ipv4Addr::new(10, 0, 9, 2));
    let remote = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 1, 2)), 5201);
    let mptcp = data.first().is_some_and(|b| b & 2 != 0);
    let connect = if mptcp {
        Endpoint::connect_mptcp
    } else {
        Endpoint::connect
    };
    let h = connect(&mut ep, now, local, remote, ConnectConfig::default()).unwrap();

    // Inline handshake: SYN/ACK with MSS 1200 + NOP + WS 7.
    let pkts = drain(&mut ep, now);
    assert_eq!(pkts.len(), 1);
    let syn = parse(&pkts[0]).unwrap();
    let mut opts = vec![2, 4, 0x04, 0xb0, 1, 3, 3, 7];
    if mptcp {
        opts.extend_from_slice(&[30, 12, 1, 1, 1, 2, 3, 4, 5, 6, 7, 8]);
    }
    let synack = Segment {
        src: syn.dst,
        dst: syn.src,
        seq: mptcp_rs::SeqNum(5000),
        ack: syn.seq.wrapping_add(1),
        flags: TcpFlags::SYN | TcpFlags::ACK,
        wnd: 65535,
        options: &opts,
        payload: &[],
    };
    let mut buf = [0u8; 1500];
    let n = build(&synack, 0, &mut buf).unwrap();
    ep.handle_packet(now, &buf[..n]);
    let third = drain(&mut ep, now);
    assert_eq!(ep.poll_event(), Some((h, Event::Connected { mptcp })));
    // The joined subflow's (ISS, local, remote) when mode bit 2 asks for a join (MPTCP only).
    let mut join = None;
    if mptcp {
        use mptcp_rs::wire::{
            mptcp::{self, DataAck, Dss, MpJoin, MptcpOption},
            tcp_options::{self, TcpOpt, walk},
        };
        let ack = parse(&third[0]).unwrap();
        let key = walk(ack.options)
            .find_map(|o| match o {
                Ok(TcpOpt::Mptcp(raw)) => match mptcp::parse(raw).ok()? {
                    MptcpOption::Capable(c) => c.sender_key,
                    _ => None,
                },
                _ => None,
            })
            .unwrap();
        let (_, idsn) = mptcp_rs::crypto::key_token_idsn(key);
        let mut options = [0; 40];
        let len = mptcp::encode(
            &MptcpOption::Dss(Dss {
                data_ack: Some(DataAck::Ack64(idsn.wrapping_add(1))),
                mapping: None,
                data_fin: false,
            }),
            &mut options,
        )
        .unwrap();
        let confirmed = Segment {
            seq: mptcp_rs::SeqNum(5001),
            flags: TcpFlags::ACK,
            options: &options[..len],
            ..synack
        };
        let n = build(&confirmed, 0, &mut buf).unwrap();
        ep.handle_packet(now, &buf[..n]);
        drain(&mut ep, now);
        if data.first().is_some_and(|b| b & 4 != 0) {
            // Join prefix: MP_JOIN SYN from 10.0.8.2, the peer's SYN/ACK (HMAC-B, MSS 1200,
            // WS 7), our third ACK (HMAC-A) and the peer's fourth ACK -> SubflowUp.
            const PEER_NONCE: u32 = 0xb1b2_b3b4;
            let peer_key = 0x0102_0304_0506_0708;
            let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 8, 2));
            let id = ep.add_subflow(now, h, ip, remote, 1500, false).unwrap();
            let pkts = drain(&mut ep, now);
            let mut segs = pkts.iter().map(|p| parse(p).unwrap());
            let jsyn = segs.find(|s| s.src.ip() == ip).expect("join SYN");
            let nonce = walk(jsyn.options)
                .find_map(|o| match o {
                    Ok(TcpOpt::Mptcp(raw)) => match mptcp::parse(raw).ok()? {
                        MptcpOption::Join(MpJoin::Syn { nonce, .. }) => Some(nonce),
                        _ => None,
                    },
                    _ => None,
                })
                .unwrap();
            let mac = mptcp_rs::crypto::join_hmac(peer_key, key, PEER_NONCE, nonce);
            let mut o = [0; 40];
            let mut n = mptcp::encode(
                &MptcpOption::Join(MpJoin::SynAck {
                    backup: false,
                    addr_id: 5,
                    hmac64: u64::from_be_bytes(mac[..8].try_into().unwrap()),
                    nonce: PEER_NONCE,
                }),
                &mut o,
            )
            .unwrap();
            n += tcp_options::write_mss(&mut o[n..], 1200);
            n += tcp_options::write_ws(&mut o[n..], 7);
            let jsynack = Segment {
                src: jsyn.dst,
                dst: jsyn.src,
                seq: mptcp_rs::SeqNum(5000),
                ack: jsyn.seq.wrapping_add(1),
                flags: TcpFlags::SYN | TcpFlags::ACK,
                wnd: 65535,
                options: &o[..n],
                payload: &[],
            };
            let n = build(&jsynack, 0, &mut buf).unwrap();
            ep.handle_packet(now, &buf[..n]);
            drain(&mut ep, now);
            let fourth = Segment {
                seq: mptcp_rs::SeqNum(5001),
                flags: TcpFlags::ACK,
                options: &options[..len],
                ..jsynack
            };
            let n = build(&fourth, 0, &mut buf).unwrap();
            ep.handle_packet(now, &buf[..n]);
            drain(&mut ep, now);
            assert_eq!(ep.poll_event(), Some((h, Event::SubflowUp { subflow: id })));
            join = Some((jsyn.seq, jsyn.src, jsyn.dst));
        }
    }

    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    let mut t = now;
    if mode & 1 == 0 {
        // Raw mode: the input is one IP packet.
        ep.handle_packet(t, rest);
        drain(&mut ep, t);
    } else {
        // Structured mode: the input is a list of segments for the established
        // 4-tuple, built with valid checksums and sequence numbers near the
        // connection's, with data in flight.
        // Bit 7 of the flags byte picks the joined subflow's 4-tuple when there is one.
        let initial = (syn.seq, syn.src, syn.dst);
        ep.connection(h).unwrap().write(&[0xab; 4000]).unwrap();
        drain(&mut ep, t);
        let mut rest = rest;
        while rest.len() >= 9 {
            let (d, r) = rest.split_at(9);
            let sd = i16::from_be_bytes([d[0], d[1]]);
            let ad = i16::from_be_bytes([d[2], d[3]]);
            let olen = usize::from(d[6] % 41);
            let plen = usize::from(d[7]);
            let olen = olen.min(r.len());
            let plen = plen.min(r.len() - olen);
            let (opts, r) = r.split_at(olen);
            // Flag bit 7 of the length byte swaps the options for a synthesized new-subtype one,
            // NOP-padded to 4 bytes.
            let synthed = match opts.split_first() {
                Some((&sel, body)) if d[6] & 0x80 != 0 => {
                    let mut o = synth(sel, body);
                    o.resize(o.len().next_multiple_of(4), 1);
                    Some(o)
                }
                _ => None,
            };
            let opts = synthed.as_deref().unwrap_or(opts);
            let (payload, r) = r.split_at(plen);
            rest = r;
            let on_join = d[4] & 0x80 != 0;
            let (iss, dst, src) = join.filter(|_| on_join).unwrap_or(initial);
            let (rcv0, snd0) = (5001u32, iss.0.wrapping_add(1));
            let seg = Segment {
                src,
                dst,
                seq: mptcp_rs::SeqNum(rcv0.wrapping_add_signed(i32::from(sd))),
                ack: mptcp_rs::SeqNum(snd0.wrapping_add_signed(i32::from(ad))),
                flags: TcpFlags(d[4] & 0x3f),
                wnd: u16::from(d[5]) << 8,
                options: opts,
                payload,
            };
            let mut b = [0u8; 1500];
            // Options longer than 40 bytes or not 4-aligned make build fail; skip those.
            if let Ok(n) = build(&seg, 0, &mut b) {
                ep.handle_packet(t, &b[..n]);
            }
            drain(&mut ep, t);
            if let Some(c) = ep.connection(h) {
                let _ = c.read(&mut [0u8; 4096]);
            }
            t = t + Duration::from_millis(u64::from(d[8]));
            ep.handle_timeout(t);
            drain(&mut ep, t);
        }
    }
    if let Some(c) = ep.connection(h) {
        c.close();
    }
    drain(&mut ep, t);
    let later = t + Duration::from_secs(1);
    ep.handle_timeout(later);
    drain(&mut ep, later);
    ep.handle_timeout(later + Duration::from_secs(180));
    drain(&mut ep, later + Duration::from_secs(180));
});
