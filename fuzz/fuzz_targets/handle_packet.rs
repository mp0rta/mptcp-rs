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

fuzz_target!(|data: &[u8]| {
    let now = Instant::from_nanos(1_000_000_000);
    let mut ep = Endpoint::new(ChaCha20Rng::seed_from_u64(1));
    let local = IpAddr::V4(Ipv4Addr::new(10, 0, 9, 2));
    let remote = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 1, 2)), 5201);
    let h = ep
        .connect(now, local, remote, ConnectConfig::default())
        .unwrap();

    // Inline handshake: SYN/ACK with MSS 1200 + NOP + WS 7.
    let pkts = drain(&mut ep, now);
    assert_eq!(pkts.len(), 1);
    let syn = parse(&pkts[0]).unwrap();
    let opts = [2, 4, 0x04, 0xb0, 1, 3, 3, 7];
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
    assert_eq!(
        ep.poll_event(),
        Some((h, Event::Connected { mptcp: false }))
    );
    drain(&mut ep, now);

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
        let (rcv0, snd0) = (5000u32.wrapping_add(1), syn.seq.0.wrapping_add(1));
        let (src, dst) = (syn.dst, syn.src);
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
            let (payload, r) = r.split_at(plen);
            rest = r;
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
    let later = t + Duration::from_secs(1);
    ep.handle_timeout(later);
    drain(&mut ep, later);
});
