mod support;

use mptcp_rs::wire::packet::{TcpFlags, parse};
use mptcp_rs::{CloseReason, ConnectConfig, Event, ReadError};
use std::time::Duration;
use support::*;

struct Outcome {
    elapsed: Duration,
    rst_from_client: bool,
    closed: Vec<CloseReason>,
}

/// Client writes `up` bytes then closes; the peer sends `down` bytes and FINs right after them
/// (`peer.close()` is called up front). Virtual clock jumps to the next timer or packet arrival.
fn run(v6: bool, len: usize, seed: u64, loss: u32, reorder: u32) -> Outcome {
    let (up, down) = (pattern(len, 0), pattern(len, 13));
    let mut ep = endpoint(seed);
    let mut peer = ScriptedPeer::new(peer_addr(v6), down.clone());
    peer.close();
    let (mut c2p, mut p2c) = (
        Link::new(seed ^ 1, loss, reorder),
        Link::new(seed ^ 2, loss, reorder),
    );
    let t0 = t(1);
    let mut now = t0;
    let h = ep
        .connect(now, local_ip(v6), peer_addr(v6), ConnectConfig::default())
        .unwrap();
    let (mut written, mut got, mut eof) = (0usize, Vec::new(), false);
    let (mut closed_app, mut closed, mut rst, mut connected) = (false, Vec::new(), false, false);
    let mut buf = vec![0u8; MTU];
    let mut rbuf = vec![0u8; 65536];
    let deadline = t0 + Duration::from_secs(300);
    loop {
        while let Some(p) = p2c.recv(now) {
            ep.handle_packet(now, &p);
        }
        while let Some(p) = c2p.recv(now) {
            peer.rx(now, &p);
        }
        if ep.poll_timeout().is_some_and(|x| x <= now) {
            ep.handle_timeout(now);
        }
        while let Some((_, e)) = ep.poll_event() {
            match e {
                Event::FellBack => panic!("plain connection fell back"),
                Event::Connected { .. } => connected = true,
                Event::Closed { reason } => closed.push(reason),
                Event::SubflowUp { .. }
                | Event::SubflowDown { .. }
                | Event::SubflowStale { .. }
                | Event::SubflowRecovered { .. } => panic!("plain TCP has no subflow events"),
            }
        }
        if let Some(c) = ep.connection(h) {
            while written < up.len() {
                let n = c
                    .write(&up[written..(written + 65536).min(up.len())])
                    .unwrap();
                if n == 0 {
                    break;
                }
                written += n;
            }
            // `close` in SYN-SENT would abort the connection, so wait for Connected.
            if written == up.len() && connected && !closed_app {
                c.close();
                closed_app = true;
            }
            loop {
                match c.read(&mut rbuf) {
                    Ok(0) => {
                        eof = true;
                        break;
                    }
                    Ok(n) => got.extend_from_slice(&rbuf[..n]),
                    Err(ReadError::WouldBlock) => break,
                    Err(e) => panic!("{e:?}"),
                }
            }
        }
        while let Some(n) = ep.poll_transmit(now, &mut buf) {
            rst |= parse(&buf[..n]).unwrap().flags.contains(TcpFlags::RST);
            c2p.send(now, buf[..n].to_vec());
        }
        while let Some(p) = peer.poll_tx(now) {
            p2c.send(now, p);
        }
        if eof && peer.fin_acked && !closed.is_empty() && peer.fin_received {
            break;
        }
        let next = [ep.poll_timeout(), peer.next_timer(), c2p.next_due(), p2c.next_due()]
            .into_iter()
            .flatten()
            .min()
            .unwrap_or_else(|| panic!("nothing pending: written {written} got {} peer got {} eof {eof} fin_acked {} closed {closed:?} peer_fin {}", got.len(), peer.received.len(), peer.fin_acked, peer.fin_received));
        now = next.max(now + Duration::from_micros(1));
        assert!(
            now < deadline,
            "stuck: written {written} got {} peer got {}",
            got.len(),
            peer.received.len()
        );
    }
    assert!(got == down, "client received data differs");
    assert!(peer.received == up, "peer received data differs");
    Outcome {
        elapsed: now - t0,
        rst_from_client: rst || peer.rst_seen,
        closed,
    }
}

#[test]
fn transfer_1mib_each_way_byte_exact() {
    for v6 in [false, true] {
        let o = run(v6, 1 << 20, 42, 10, 50);
        assert!(o.elapsed < Duration::from_secs(60), "{:?}", o.elapsed);
        assert_eq!(o.closed, vec![CloseReason::Normal]);
        assert!(!o.rst_from_client);
    }
}

#[test]
fn clean_close_has_no_rst() {
    for v6 in [false, true] {
        let o = run(v6, 20_000, 7, 0, 0);
        assert!(!o.rst_from_client);
        assert_eq!(o.closed, vec![CloseReason::Normal]);
        assert!(o.elapsed < Duration::from_secs(10), "{:?}", o.elapsed);
    }
}
