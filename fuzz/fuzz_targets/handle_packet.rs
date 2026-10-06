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

    ep.handle_packet(now, data);
    drain(&mut ep, now);
    let later = now + Duration::from_secs(1);
    ep.handle_timeout(later);
    drain(&mut ep, later);
});
