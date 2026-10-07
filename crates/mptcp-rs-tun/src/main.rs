//! Test client: one TCP connection through a TUN device, pattern in both directions.
#![deny(unsafe_code)]

#[allow(unsafe_code)]
mod tun;

#[cfg(test)]
mod ack_tests;

use std::io::{self, Read};
use std::net::{IpAddr, SocketAddr};
use std::process::ExitCode;
use std::time::Duration;

use mptcp_rs::{CloseReason, ConnectConfig, Endpoint, Event, Instant, ReadError};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use tun::Tun;

const USAGE: &str = "usage: mptcp-rs-tun --mode tcp|mptcp --tun NAME --local IP --remote IP:PORT --send BYTES --expect BYTES [--pause-read-ms MS]";
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
    mptcp: bool,
    pause_read: Duration,
    tun: String,
    local: IpAddr,
    remote: SocketAddr,
    send: u64,
    expect: u64,
}

fn parse_args(mut it: impl Iterator<Item = String>) -> Option<Args> {
    let (mut tun, mut local, mut remote, mut send, mut expect) = (None, None, None, None, None);
    let mut mode = None;
    let mut pause_read = Duration::ZERO;
    while let Some(flag) = it.next() {
        let v = it.next()?;
        match flag.as_str() {
            "--mode" => {
                mode = Some(match v.as_str() {
                    "tcp" => false,
                    "mptcp" => true,
                    _ => return None,
                })
            }
            "--pause-read-ms" => pause_read = Duration::from_millis(v.parse().ok()?),
            "--tun" => tun = Some(v),
            "--local" => local = v.parse().ok(),
            "--remote" => remote = v.parse().ok(),
            "--send" => send = v.parse().ok(),
            "--expect" => expect = v.parse().ok(),
            _ => return None,
        }
    }
    Some(Args {
        mptcp: mode?,
        pause_read,
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
    let connect = if a.mptcp {
        Endpoint::connect_mptcp
    } else {
        Endpoint::connect
    };
    let cfg = ConnectConfig {
        recv_buffer: if a.pause_read.is_zero() {
            ConnectConfig::default().recv_buffer
        } else {
            16384
        },
        ..ConnectConfig::default()
    };
    let h = connect(&mut ep, now(start), a.local, a.remote, cfg)
        .map_err(|e| format!("connect: {e:?}"))?;

    let mut pkt = vec![0u8; 65535];
    let mut rbuf = vec![0u8; 65536];
    // One period of the pattern repeats every 251 bytes: slice at `sent % 251`.
    let pat: Vec<u8> = (0..65536 + 251u64).map(pattern_byte).collect();
    let mut st = State::default();
    let mut resume_read = None;
    loop {
        if start.elapsed() > Duration::from_secs(900) {
            return Err("connection timed out".into());
        }
        let t = now(start);
        let wait = ep.poll_timeout().map_or(CAP, |d| {
            Duration::from_nanos(d.as_nanos().saturating_sub(t.as_nanos())).min(CAP)
        });
        tun.wait_readable(Some(wait)).map_err(io_err("poll"))?;
        loop {
            match tun.read(&mut pkt) {
                Ok(n) => {
                    if let Some(n) = receive_and_poll(&mut ep, now(start), &mut pkt, n) {
                        write_packet(&tun, &pkt[..n])?;
                    }
                    // Start the test pause before a continuously readable TUN fills the buffer.
                    if !a.pause_read.is_zero() && st.verified == 0 {
                        break;
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(format!("tun read: {e}")),
            }
        }
        let t = now(start);
        if ep.poll_timeout().is_some_and(|d| d <= t) {
            ep.handle_timeout(t);
        }
        // Events first: a reset or R2 timeout frees the TCB in the same iteration.
        st.events(&mut ep, &a)?;

        // After a normal close the connection is gone unless data is still unread.
        if st.drives(ep.connection(h).is_some()) {
            let conn = ep.connection(h).ok_or("connection gone")?;
            while !st.closing && st.sent < a.send {
                let n = (a.send - st.sent).min(65536) as usize;
                match conn.write(&pat[(st.sent % 251) as usize..][..n]) {
                    Ok(0) => break,
                    Ok(w) => st.sent += w as u64,
                    Err(e) => return Err(format!("write: {e:?}")),
                }
            }
            // Keep verifying after close(): extra bytes from the peer are a mismatch.
            while !st.eof && resume_read.is_none_or(|deadline| start.elapsed() >= deadline) {
                match conn.read(&mut rbuf) {
                    Ok(0) => st.eof = true,
                    Ok(n) => {
                        if st.verified + n as u64 > a.expect
                            || !verify_pattern(st.verified, &rbuf[..n])
                        {
                            return Err(format!("verification mismatch at byte {}", st.verified));
                        }
                        st.verified += n as u64;
                        if resume_read.is_none() && !a.pause_read.is_zero() {
                            resume_read = Some(start.elapsed() + a.pause_read);
                            eprintln!("read paused at {} bytes", st.verified);
                            break;
                        }
                    }
                    Err(ReadError::WouldBlock) => break,
                    Err(ReadError::Reset) => return Err("connection reset by peer".into()),
                }
            }
            if st.eof && st.verified < a.expect {
                return Err(format!(
                    "premature EOF after {} of {} bytes",
                    st.verified, a.expect
                ));
            }
            if !st.closing && st.sent == a.send && st.verified == a.expect {
                conn.close();
                st.closing = true;
            }
        }
        st.events(&mut ep, &a)?;

        // Drain before returning: the final ACK of the active close must go out.
        while let Some(n) = ep.poll_transmit(now(start), &mut pkt) {
            write_packet(&tun, &pkt[..n])?;
        }
        if st.done {
            if !st.eof {
                return Err("closed before EOF".into());
            }
            return Ok(format!(
                "ok: sent {} bytes, verified {} bytes, eof=true",
                st.sent, st.verified
            ));
        }
    }
}

/// Service the single connection's current ACK before another input can coalesce it.
/// One output can carry the ACK on data; remaining data is drained after application reads.
fn receive_and_poll(
    ep: &mut Endpoint<ChaCha20Rng>,
    t: Instant,
    pkt: &mut [u8],
    n: usize,
) -> Option<usize> {
    ep.handle_packet(t, &pkt[..n]);
    ep.poll_transmit(t, pkt)
}

fn write_packet(tun: &Tun, pkt: &[u8]) -> Result<(), String> {
    match tun.write(pkt) {
        Ok(_) => Ok(()),
        // Link not up yet (EIO) or queue full: a dropped packet, TCP recovers.
        Err(e)
            if e.kind() == io::ErrorKind::WouldBlock
                || matches!(e.raw_os_error(), Some(libc::EIO | libc::ENOBUFS)) =>
        {
            Ok(())
        }
        Err(e) => Err(format!("tun write: {e}")),
    }
}

#[derive(Default)]
struct State {
    sent: u64,
    verified: u64,
    connected: bool,
    closing: bool,
    eof: bool,
    done: bool,
}

impl State {
    /// Whether this iteration writes, reads and closes. After a normal close the connection is
    /// gone unless data is still unread. EOF only stops the read loop, never the writes.
    fn drives(&self, conn_present: bool) -> bool {
        self.connected && (!self.done || conn_present)
    }

    fn events(&mut self, ep: &mut Endpoint<ChaCha20Rng>, a: &Args) -> Result<(), String> {
        while let Some((_, ev)) = ep.poll_event() {
            match ev {
                Event::FellBack => eprintln!("event: FellBack"),
                Event::Connected { mptcp } => {
                    eprintln!("event: Connected mptcp={mptcp}");
                    self.connected = true;
                }
                Event::Closed {
                    reason: CloseReason::Normal,
                } if self.closing && self.sent == a.send && self.verified == a.expect => {
                    eprintln!("event: Closed Normal");
                    self.done = true;
                }
                Event::Closed { reason } => {
                    return Err(format!(
                        "connection closed: {reason:?} (sent {}, verified {})",
                        self.sent, self.verified
                    ));
                }
            }
        }
        Ok(())
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
        assert!(parse_args(v(ok)).is_none());
        assert!(parse_args(v(&format!("{ok} --mode tcp"))).is_some());
        assert!(parse_args(v(&format!("{ok} --mode mptcp"))).is_some());
        assert!(parse_args(v(&format!("{ok} --mode other"))).is_none());
        assert!(parse_args(v("--tun t0")).is_none());
        assert!(parse_args(v("--bogus 1")).is_none());
    }

    #[test]
    fn peer_eof_does_not_stop_writes_and_close() {
        let st = State {
            connected: true,
            eof: true,
            ..State::default()
        };
        assert!(st.drives(true));
        let st = State { done: true, ..st };
        assert!(!st.drives(false));
        assert!(!State::default().drives(true), "not connected yet");
    }
}
