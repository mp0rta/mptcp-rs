//! Test client: one TCP connection through a TUN device, pattern in both directions.
#![deny(unsafe_code)]

#[allow(unsafe_code)]
mod tun;

use std::io::{self, Read};
use std::net::{IpAddr, SocketAddr};
use std::process::ExitCode;
use std::time::Duration;

use mptcp_rs::{CloseReason, ConnectConfig, Endpoint, Event, Instant, ReadError};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use tun::Tun;

const USAGE: &str =
    "usage: mptcp-rs-tun --tun NAME --local IP --remote IP:PORT --send BYTES --expect BYTES";
const CAP: Duration = Duration::from_millis(100);

fn pattern_byte(i: u64) -> u8 {
    ((i * 31 + 7) % 251) as u8
}

/// True when `data` equals the pattern starting at global byte offset `offset`.
fn verify_pattern(offset: u64, data: &[u8]) -> bool {
    data.iter()
        .zip(offset..)
        .all(|(b, i)| *b == pattern_byte(i))
}

struct Args {
    tun: String,
    local: IpAddr,
    remote: SocketAddr,
    send: u64,
    expect: u64,
}

fn parse_args(mut it: impl Iterator<Item = String>) -> Option<Args> {
    let (mut tun, mut local, mut remote, mut send, mut expect) = (None, None, None, None, None);
    while let Some(flag) = it.next() {
        let v = it.next()?;
        match flag.as_str() {
            "--tun" => tun = Some(v),
            "--local" => local = v.parse().ok(),
            "--remote" => remote = v.parse().ok(),
            "--send" => send = v.parse().ok(),
            "--expect" => expect = v.parse().ok(),
            _ => return None,
        }
    }
    Some(Args {
        tun: tun?,
        local: local?,
        remote: remote?,
        send: send?,
        expect: expect?,
    })
}

fn now(start: std::time::Instant) -> Instant {
    Instant::from_nanos(start.elapsed().as_nanos() as u64)
}

fn run(a: Args) -> Result<String, String> {
    let io_err = |what: &'static str| move |e: io::Error| format!("{what}: {e}");
    let tun = Tun::open(&a.tun).map_err(io_err("open tun"))?;
    let mut seed = [0u8; 32];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut seed))
        .map_err(io_err("read /dev/urandom"))?;
    let mut ep = Endpoint::new(ChaCha20Rng::from_seed(seed));
    let start = std::time::Instant::now();
    let h = ep
        .connect(now(start), a.local, a.remote, ConnectConfig::default())
        .map_err(|e| format!("connect: {e:?}"))?;

    let mut pkt = vec![0u8; 65535];
    let mut chunk = vec![0u8; 65536];
    let (mut sent, mut verified) = (0u64, 0u64);
    let (mut connected, mut closing, mut eof) = (false, false, false);
    loop {
        let t = now(start);
        let wait = ep.poll_timeout().map_or(CAP, |d| {
            Duration::from_nanos(d.as_nanos().saturating_sub(t.as_nanos())).min(CAP)
        });
        tun.wait_readable(Some(wait)).map_err(io_err("poll"))?;
        loop {
            match tun.read(&mut pkt) {
                Ok(n) => ep.handle_packet(now(start), &pkt[..n]),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(format!("tun read: {e}")),
            }
        }
        let t = now(start);
        if ep.poll_timeout().is_some_and(|d| d <= t) {
            ep.handle_timeout(t);
        }

        if connected && !closing {
            let conn = ep.connection(h).ok_or("connection gone")?;
            while sent < a.send {
                let n = ((a.send - sent).min(chunk.len() as u64)) as usize;
                for (b, i) in chunk[..n].iter_mut().zip(sent..) {
                    *b = pattern_byte(i);
                }
                match conn.write(&chunk[..n]) {
                    Ok(0) => break,
                    Ok(w) => sent += w as u64,
                    Err(e) => return Err(format!("write: {e:?}")),
                }
            }
            while !eof {
                match conn.read(&mut chunk) {
                    Ok(0) => eof = true,
                    Ok(n) => {
                        if verified + n as u64 > a.expect || !verify_pattern(verified, &chunk[..n])
                        {
                            return Err(format!("verification mismatch at byte {verified}"));
                        }
                        verified += n as u64;
                    }
                    Err(ReadError::WouldBlock) => break,
                    Err(ReadError::Reset) => return Err("connection reset by peer".into()),
                }
            }
            if eof && verified < a.expect {
                return Err(format!(
                    "premature EOF after {verified} of {} bytes",
                    a.expect
                ));
            }
            if sent == a.send && verified == a.expect {
                conn.close();
                closing = true;
            }
        }

        while let Some((_, ev)) = ep.poll_event() {
            match ev {
                Event::Connected { .. } => connected = true,
                Event::Closed {
                    reason: CloseReason::Normal,
                } if closing && sent == a.send && verified == a.expect => {
                    return Ok(format!("ok: sent {sent} bytes, verified {verified} bytes"));
                }
                Event::Closed { reason } => {
                    return Err(format!(
                        "connection closed: {reason:?} (sent {sent}, verified {verified})"
                    ));
                }
            }
        }

        while let Some(n) = ep.poll_transmit(now(start), &mut pkt) {
            tun.write(&pkt[..n]).map_err(io_err("tun write"))?;
        }
    }
}

fn main() -> ExitCode {
    let Some(args) = parse_args(std::env::args().skip(1)) else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    match run(args) {
        Ok(s) => {
            println!("{s}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("mptcp-rs-tun: {e}");
            ExitCode::from(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pattern_verifies_at_any_offset() {
        let data: Vec<u8> = (1000..1600u64).map(pattern_byte).collect();
        assert!(verify_pattern(1000, &data)); // 1000 % 251 != 0
        assert!(verify_pattern(1250, &data[250..]));
        assert!(!verify_pattern(1001, &data));
        let mut bad = data.clone();
        bad[300] ^= 1;
        assert!(!verify_pattern(1000, &bad));
        assert_eq!(pattern_byte(0), 7);
    }

    #[test]
    fn args() {
        let v = |s: &str| {
            s.split(' ')
                .map(String::from)
                .collect::<Vec<_>>()
                .into_iter()
        };
        let ok = "--tun t0 --local 10.0.0.2 --remote 10.0.1.1:80 --send 5 --expect 6";
        assert!(parse_args(v(ok)).is_some());
        assert!(parse_args(v("--tun t0")).is_none());
        assert!(parse_args(v("--bogus 1")).is_none());
    }
}
