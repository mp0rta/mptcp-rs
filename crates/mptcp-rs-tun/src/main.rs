//! Test client: one TCP connection through a TUN device, pattern in both directions.
#![deny(unsafe_code)]

#[allow(unsafe_code)]
mod tun;

#[cfg(test)]
mod ack_tests;
mod script;

use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr};
use std::process::ExitCode;
use std::time::{Duration, SystemTime};

use mptcp_rs::{
    CloseReason, CongestionControlKind, ConnectConfig, ConnectionHandle, DebugStats, Endpoint,
    Event, Instant, ReadError, SubflowId,
};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use script::{Action, Ev, Script};
use tun::Tun;

const USAGE: &str = "usage: mptcp-rs-tun --mode tcp|mptcp --tun NAME --local IP --remote IP:PORT --send BYTES|--send-secs S --expect BYTES|any [--pause-read-ms MS] [--script FILE] [--join IP [--join-mtu N]]... [--abort-after-ms MS] [--send-rate MBIT] [--event-log FILE] [--cc cubic|bbr3]";
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
    /// Timed sending: write the pattern for this long after `Connected`, then close.
    send_secs: Option<Duration>,
    /// `None` = `--expect any`: verify the pattern until EOF.
    expect: Option<u64>,
    /// `--join IP [--join-mtu N]`: extra subflows from these local addresses, with that MTU.
    joins: Vec<(IpAddr, u16)>,
    /// `--abort-after-ms`: `Connection::abort` this long after `Connected`, instead of a close.
    abort_after: Option<Duration>,
    /// `--script`: the scenario file (`script.rs`); `--join` and `--abort-after-ms` add to it.
    script: Option<String>,
    /// `--send-rate`: the writer's rate in Mbit/s from `Connected`; unlimited without it.
    send_rate: Option<f64>,
    /// `--event-log`: a JSON line per event and action, with a clock pair at start and end.
    event_log: Option<String>,
    /// `--cc`: the congestion controller; CUBIC without it.
    cc: CongestionControlKind,
}

impl Args {
    /// The scenario: the script file, then the `--join` and `--abort-after-ms` shorthands.
    fn scenario(&self) -> Result<String, String> {
        let mut text = match &self.script {
            Some(path) => std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?,
            None => String::new(),
        };
        for (ip, mtu) in &self.joins {
            text += &format!("\nat Connected +0 join {ip} {} mtu {mtu}", self.remote);
        }
        if let Some(d) = self.abort_after {
            text += &format!("\nat Connected +{} abort", d.as_millis());
        }
        Ok(text)
    }
}

fn parse_args(mut it: impl Iterator<Item = String>) -> Option<Args> {
    let (mut tun, mut local, mut remote, mut send, mut expect) = (None, None, None, None, None);
    let mut send_secs = None;
    let mut mode = None;
    let mut pause_read = Duration::ZERO;
    let mut joins = Vec::new();
    let mut abort_after = None;
    let (mut script, mut send_rate, mut event_log) = (None, None, None);
    let mut cc = CongestionControlKind::Cubic;
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
            // The TUN device's MTU, which the initial subflow also uses.
            "--join" => joins.push((v.parse().ok()?, ConnectConfig::default().mtu)),
            "--join-mtu" => joins.last_mut()?.1 = v.parse().ok()?,
            "--abort-after-ms" => abort_after = Some(Duration::from_millis(v.parse().ok()?)),
            "--script" => script = Some(v),
            "--send-rate" => send_rate = Some(v.parse().ok().filter(|r: &f64| *r > 0.0)?),
            "--event-log" => event_log = Some(v),
            "--cc" => {
                cc = match v.as_str() {
                    "cubic" => CongestionControlKind::Cubic,
                    "bbr3" => CongestionControlKind::BbrV3,
                    _ => return None,
                }
            }
            "--send-secs" => {
                send_secs = Some(Duration::from_secs(v.parse().ok().filter(|s| *s > 0)?))
            }
            "--expect" => {
                expect = Some(if v == "any" {
                    None
                } else {
                    Some(v.parse().ok()?)
                })
            }
            _ => return None,
        }
    }
    Some(Args {
        mptcp: mode?,
        pause_read,
        tun: tun?,
        local: local?,
        remote: remote?,
        send: match (send, send_secs) {
            (Some(n), None) => n,
            (None, Some(_)) => 0,
            _ => return None,
        },
        send_secs,
        expect: expect?,
        joins,
        abort_after,
        script,
        send_rate,
        event_log,
        cc,
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
    let mut cfg = ConnectConfig::default();
    cfg.congestion_control = a.cc;
    if !a.pause_read.is_zero() {
        cfg.recv_buffer = 16384;
    }
    let mtu = cfg.mtu;
    let h = connect(&mut ep, now(start), a.local, a.remote, cfg)
        .map_err(|e| format!("connect: {e:?}"))?;
    let mut drv = Driver {
        script: Script::parse(&a.scenario()?)?,
        subs: vec![(SubflowId::INITIAL, a.local, a.remote, mtu, false)],
        down: Vec::new(),
        log: match &a.event_log {
            Some(path) => Some(EventLog::create(path, start).map_err(io_err("event log"))?),
            None => None,
        },
        complete: false,
    };
    drv.clock("start");
    // The suite stops an active closer in TIME-WAIT with SIGTERM: it still reports an unmet
    // directive and ends the event log.
    tun::catch_sigterm();

    let mut pkt = vec![0u8; 65535];
    let mut rbuf = vec![0u8; 65536];
    // One period of the pattern repeats every 251 bytes: slice at `sent % 251`.
    let pat: Vec<u8> = (0..65536 + 251u64).map(pattern_byte).collect();
    let mut st = State::default();
    let mut resume_read = None;
    loop {
        if tun::sigterm() {
            if let Some(d) = drv.script.unmet() {
                eprintln!("script: unmet {d}");
            }
            drop(drv); // the event log's end clock
            tun::die_of_sigterm();
        }
        if start.elapsed() > Duration::from_secs(900) {
            return Err("connection timed out".into());
        }
        let t = now(start);
        let wait = ep.poll_timeout().map_or(CAP, |d| {
            Duration::from_nanos(d.as_nanos().saturating_sub(t.as_nanos())).min(CAP)
        });
        // Scenario deadlines wake the loop too.
        let wait = (drv.script.next_deadline())
            .map_or(wait, |d| wait.min(d.saturating_sub(start.elapsed())));
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
        st.events(&mut ep, &a, start.elapsed(), &mut drv)?;
        // Then the scenario's due actions.
        let elapsed = start.elapsed();
        for action in drv.script.due(elapsed) {
            drv.act(&mut ep, h, now(start), &action, &mut st)?;
        }
        // Every directive has run: the suite requires this line (M3 spec §5.3).
        if !drv.complete && drv.script.unmet().is_none() {
            drv.complete = true;
            println!("script: complete");
            drv.log("script", "complete");
        }
        // After a normal close the connection is gone unless data is still unread.
        if st.drives(ep.connection(h).is_some()) {
            let conn = ep.connection(h).ok_or("connection gone")?;
            st.stats = conn.debug_stats();
            while !st.closing && !st.send_done(&a, start.elapsed()) {
                let n = if a.send_secs.is_some() {
                    65536
                } else {
                    (a.send - st.sent).min(65536) as usize
                };
                // `--send-rate`: what the rate allows since `Connected`, in pieces of 16 KiB or
                // more (or the rest): writing every octet as it accrues would keep this loop
                // spinning, with nothing sent or received, until the store is full.
                let n = match (a.send_rate, st.connected_at) {
                    (Some(r), Some(c)) => {
                        let due = (start.elapsed() - c).as_secs_f64() * r * 1e6 / 8.0;
                        let allowed = (due as u64).saturating_sub(st.sent) as usize;
                        if allowed < n.min(16384) {
                            0
                        } else {
                            n.min(allowed)
                        }
                    }
                    _ => n,
                };
                if n == 0 {
                    break;
                }
                match conn.write(&pat[(st.sent % 251) as usize..][..n]) {
                    Ok(0) => {
                        st.blocked_since.get_or_insert(start.elapsed());
                        break;
                    }
                    Ok(w) => {
                        st.unblock(start.elapsed());
                        st.sent += w as u64;
                    }
                    Err(e) => return Err(format!("write: {e:?}")),
                }
            }
            // The application has nothing more to write: it is no longer blocked.
            if st.send_done(&a, start.elapsed()) {
                st.unblock(start.elapsed());
            }
            // Keep verifying after close(): extra bytes from the peer are a mismatch.
            while !st.eof && resume_read.is_none_or(|deadline| start.elapsed() >= deadline) {
                match conn.read(&mut rbuf) {
                    Ok(0) => st.eof = true,
                    Ok(n) => {
                        if a.expect.is_some_and(|e| st.verified + n as u64 > e)
                            || !verify_pattern(st.verified, &rbuf[..n])
                        {
                            return Err(format!("verification mismatch at byte {}", st.verified));
                        }
                        st.verified += n as u64;
                        let t = start.elapsed();
                        st.first_rx.get_or_insert(t);
                        st.last_rx = t;
                        if resume_read.is_none() && !a.pause_read.is_zero() {
                            resume_read = Some(start.elapsed() + a.pause_read);
                            eprintln!("read paused at {} bytes", st.verified);
                            break;
                        }
                    }
                    Err(ReadError::WouldBlock) => break,
                    Err(ReadError::Reset) => return Err("connection reset by peer".into()),
                    Err(e) => return Err(format!("read: {e:?}")),
                }
            }
            if let Some(e) = a.expect.filter(|e| st.eof && st.verified < *e) {
                return Err(format!("premature EOF after {} of {e} bytes", st.verified));
            }
            if !st.closing && st.send_done(&a, start.elapsed()) && st.recv_done(&a) {
                // The suite may stop an active closer in TIME-WAIT, before the `ok:` line.
                println!(
                    "closing: sent {} bytes, verified {} bytes",
                    st.sent, st.verified
                );
                conn.close();
                st.closing = true;
                drv.script.on_event(Ev::Stop, start.elapsed());
            }
        }
        st.events(&mut ep, &a, start.elapsed(), &mut drv)?;

        // Drain before returning: the final ACK of the active close must go out.
        while let Some(n) = ep.poll_transmit(now(start), &mut pkt) {
            write_packet(&tun, &pkt[..n])?;
        }
        if st.done {
            if let Some(d) = drv.script.unmet() {
                return Err(format!("script: unmet {d}"));
            }
        }
        if st.done && st.aborted {
            return Ok(format!(
                "aborted: sent {} bytes, verified {} bytes",
                st.sent, st.verified
            ));
        }
        if st.done {
            if !st.eof {
                return Err("closed before EOF".into());
            }
            st.unblock(start.elapsed());
            let s = st.stats;
            println!(
                "stats: opp_triggers={} opp_episodes={} penalties={} opp_bytes={} app_blocked_ms={}",
                s.opp_triggers,
                s.opp_episodes,
                s.penalties,
                s.opp_bytes,
                st.app_blocked.as_millis()
            );
            if let Some(f) = st.first_rx {
                // Receiver-side goodput: first to last received byte.
                let secs = (st.last_rx - f).as_secs_f64();
                let mbps = st.verified as f64 * 8.0 / secs.max(1e-9) / 1e6;
                println!(
                    "goodput: {} bytes in {secs:.3} s = {mbps:.1} Mbit/s",
                    st.verified
                );
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
    connected_at: Option<Duration>,
    send_stop: bool,
    first_rx: Option<Duration>,
    last_rx: Duration,
    closing: bool,
    /// `Connection::abort` was called.
    aborted: bool,
    eof: bool,
    done: bool,
    /// The connection's counters, as last seen while it existed.
    stats: DebugStats,
    /// Since when `write` accepts nothing while the application has data; the longest such
    /// interval so far.
    blocked_since: Option<Duration>,
    app_blocked: Duration,
}

impl State {
    /// A write-blocked interval, if one is open, ends at `now`.
    fn unblock(&mut self, now: Duration) {
        if let Some(since) = self.blocked_since.take() {
            self.app_blocked = self.app_blocked.max(now - since);
        }
    }

    /// Whether this iteration writes, reads and closes. After a normal close the connection is
    /// gone unless data is still unread. EOF only stops the read loop, never the writes.
    fn drives(&self, conn_present: bool) -> bool {
        self.connected && !self.aborted && (!self.done || conn_present)
    }

    /// All bytes are written: the fixed count, or the `--send-secs` deadline has passed.
    fn send_done(&mut self, a: &Args, now: Duration) -> bool {
        if let (Some(d), Some(c)) = (a.send_secs, self.connected_at) {
            self.send_stop |= now >= c + d;
        }
        match a.send_secs {
            Some(_) => self.send_stop,
            None => self.sent == a.send,
        }
    }

    /// Everything expected has arrived: the fixed count, or EOF for `--expect any`.
    fn recv_done(&self, a: &Args) -> bool {
        a.expect.map_or(self.eof, |e| self.verified == e)
    }

    fn events(
        &mut self,
        ep: &mut Endpoint<ChaCha20Rng>,
        a: &Args,
        now: Duration,
        drv: &mut Driver,
    ) -> Result<(), String> {
        // Subflow events carry the time since `Connected` (the harness's blackhole clock).
        let at = |c: Option<Duration>| c.map_or(0.0, |c| (now - c).as_secs_f64());
        while let Some((_, ev)) = ep.poll_event() {
            let t = at(self.connected_at);
            let text = match ev {
                Event::FellBack => "FellBack".into(),
                Event::SubflowUp { subflow } => format!("SubflowUp {subflow:?} +{t:.3}s"),
                Event::SubflowDown {
                    subflow,
                    reason,
                    rst,
                    ..
                } => {
                    let rst = rst.map_or("none".into(), |r| {
                        format!("0x{:02x}/T{}", r.reason, u8::from(r.transient))
                    });
                    format!("SubflowDown {subflow:?} {reason:?} rst={rst} +{t:.3}s")
                }
                Event::SubflowStale { subflow } => format!("SubflowStale {subflow:?} +{t:.3}s"),
                Event::SubflowRecovered { subflow } => {
                    format!("SubflowRecovered {subflow:?} +{t:.3}s")
                }
                Event::Connected { mptcp } => {
                    self.connected = true;
                    self.connected_at = Some(now);
                    format!("Connected mptcp={mptcp}")
                }
                Event::Closed { reason } => format!("Closed {reason:?}"),
                other => format!("{other:?}"),
            };
            eprintln!("event: {text}");
            drv.log("event", &text);
            drv.on_event(&ev, now);
            match ev {
                Event::Closed {
                    reason: CloseReason::Normal,
                } if self.closing
                    && self.recv_done(a)
                    && (a.send_secs.is_some() || self.sent == a.send) =>
                {
                    self.done = true
                }
                Event::Closed {
                    reason: CloseReason::Aborted,
                } if self.aborted => self.done = true,
                Event::Closed { reason } => {
                    return Err(format!(
                        "connection closed: {reason:?} (sent {}, verified {})",
                        self.sent, self.verified
                    ));
                }
                _ => {}
            }
        }
        Ok(())
    }
}

/// The scenario driver's side effects: the subflows it knows by number (`SubflowId(n)`: the
/// initial one, then each join in order), with how each was opened (local IP, remote, MTU,
/// B bit), and the event log.
struct Driver {
    script: Script,
    subs: Vec<(SubflowId, IpAddr, SocketAddr, u16, bool)>,
    /// The subflows that ended (`SubflowDown`).
    down: Vec<SubflowId>,
    log: Option<EventLog>,
    /// `script: complete` was printed.
    complete: bool,
}

impl Driver {
    fn sub(&self, n: usize) -> Result<SubflowId, String> {
        Ok(self.subs.get(n).ok_or(format!("script: no subflow {n}"))?.0)
    }

    fn on_event(&mut self, ev: &Event, now: Duration) {
        if let Event::SubflowDown { subflow, .. } = ev {
            self.down.push(*subflow);
        }
        let n = |id: &SubflowId| self.subs.iter().position(|s| s.0 == *id);
        let ev = match ev {
            Event::Connected { .. } => Some(Ev::Connected),
            Event::SubflowUp { subflow } => n(subflow).map(Ev::Up),
            Event::SubflowDown { subflow, rst, .. } => n(subflow).map(|sub| Ev::Down {
                sub,
                transient: rst.is_some_and(|r| r.transient),
            }),
            &Event::AddressAnnounced { id, addr } => Some(Ev::Announced { id, addr }),
            Event::FellBack | Event::Closed { .. } => Some(Ev::Stop),
            _ => None,
        };
        if let Some(ev) = ev {
            self.script.on_event(ev, now);
        }
    }

    /// Runs one scenario action; a failed call fails the run.
    fn act(
        &mut self,
        ep: &mut Endpoint<ChaCha20Rng>,
        h: ConnectionHandle,
        now: Instant,
        action: &Action,
        st: &mut State,
    ) -> Result<(), String> {
        self.log("action", &format!("{action:?}"));
        let fail = |e: &dyn std::fmt::Debug| format!("script: {action:?}: {e:?}");
        let (local, remote, mtu, backup) = match *action {
            Action::Join {
                local,
                remote,
                backup,
                mtu,
            } => (
                local,
                remote,
                mtu.unwrap_or(ConnectConfig::default().mtu),
                backup,
            ),
            Action::JoinAnnounced(local, remote) => {
                let open = |s: &&(SubflowId, IpAddr, SocketAddr, u16, bool)| {
                    (s.1, s.2) == (local, remote) && !self.down.contains(&s.0)
                };
                if let Some(s) = self.subs.iter().find(open) {
                    eprintln!("join: {remote} from {local} already open as {:?}", s.0);
                    return Ok(());
                }
                (local, remote, ConnectConfig::default().mtu, false)
            }
            Action::Rejoin(n) => {
                self.sub(n)?;
                let (_, local, remote, mtu, backup) = self.subs[n];
                (local, remote, mtu, backup)
            }
            Action::SetBackup(n, on) => {
                return (ep.set_backup(now, h, self.sub(n)?, on)).map_err(|e| fail(&e));
            }
            Action::SetLocalBackup(n, on) => {
                return (ep.set_local_backup(h, self.sub(n)?, on)).map_err(|e| fail(&e));
            }
            Action::CloseSubflow(n) => {
                return (ep.close_subflow(now, h, self.sub(n)?)).map_err(|e| fail(&e));
            }
            Action::RemoveAddress(ip) => {
                return (ep.remove_address(now, h, ip)).map_err(|e| fail(&e));
            }
            Action::Abort => {
                // A close already begun wins.
                if !st.aborted && !st.closing {
                    ep.connection(h).ok_or("connection gone")?.abort();
                    st.aborted = true;
                    self.script.on_event(Ev::Stop, Duration::ZERO);
                }
                return Ok(());
            }
        };
        let id = (ep.add_subflow(now, h, local, remote, mtu, backup))
            .map_err(|e| format!("add_subflow {local}: {e:?}"))?;
        eprintln!("join: {id:?} local {local} mtu {mtu}");
        self.subs.push((id, local, remote, mtu, backup));
        Ok(())
    }

    fn log(&mut self, kind: &str, text: &str) {
        if let Some(l) = &mut self.log {
            l.line(&format!("\"{kind}\": {text:?}"));
        }
    }

    fn clock(&mut self, which: &str) {
        if let Some(l) = &mut self.log {
            l.line(&format!("\"clock\": {which:?}"));
        }
    }
}

/// `--event-log`: JSON lines, each with CLOCK_REALTIME epoch time (`realtime`) and the
/// monotonic time since the client started (`rel`); the start and end lines pair the two
/// clocks, so a drift between them shows (M3 spec §5.3). The end line is written on drop, so
/// every exit has one.
struct EventLog {
    file: std::fs::File,
    start: std::time::Instant,
}

impl EventLog {
    fn create(path: &str, start: std::time::Instant) -> io::Result<Self> {
        let file = std::fs::File::create(path)?;
        Ok(Self { file, start })
    }

    fn line(&mut self, fields: &str) {
        let realtime = (SystemTime::now().duration_since(SystemTime::UNIX_EPOCH))
            .map_or(0.0, |d| d.as_secs_f64());
        let rel = self.start.elapsed().as_secs_f64();
        // A full disk only loses log lines; the run goes on.
        let _ = writeln!(
            self.file,
            "{{\"realtime\": {realtime:.6}, \"rel\": {rel:.6}, {fields}}}"
        );
    }
}

impl Drop for EventLog {
    fn drop(&mut self) {
        self.line("\"clock\": \"end\"");
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
        let timed = "--mode mptcp --tun t0 --local 10.0.0.2 --remote 10.0.1.1:80 --expect any";
        let a = parse_args(v(&format!("{timed} --send-secs 30"))).unwrap();
        assert_eq!(
            (a.send, a.send_secs, a.expect),
            (0, Some(Duration::from_secs(30)), None)
        );
        assert!(parse_args(v(&format!("{timed} --send-secs 0"))).is_none());
        assert!(parse_args(v(&format!("{timed} --send 5"))).is_some());
        assert!(parse_args(v(&format!("{timed} --send 5 --send-secs 3"))).is_none());
        let a = parse_args(v(&format!(
            "{timed} --send 5 --join 10.0.8.2 --join-mtu 1280 --join 10.0.7.2"
        )))
        .unwrap();
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        assert_eq!(a.joins, [(ip("10.0.8.2"), 1280), (ip("10.0.7.2"), 1500)]);
        assert!(parse_args(v(&format!("{timed} --send 5 --join-mtu 1280"))).is_none());
        assert!(parse_args(v(&format!("{timed} --send 5 --join x"))).is_none());
        let a = parse_args(v(&format!("{timed} --send 5 --abort-after-ms 2000"))).unwrap();
        assert_eq!(a.abort_after, Some(Duration::from_millis(2000)));
        // The shorthands become scenario directives.
        let a = parse_args(v(&format!(
            "{timed} --send 5 --join 10.0.8.2 --join-mtu 1280 --abort-after-ms 2000 --send-rate 8.5 --event-log e.jsonl"
        )))
        .unwrap();
        assert_eq!(
            (a.send_rate, a.event_log.as_deref()),
            (Some(8.5), Some("e.jsonl"))
        );
        let text = a.scenario().unwrap();
        assert_eq!(
            text,
            "\nat Connected +0 join 10.0.8.2 10.0.1.1:80 mtu 1280\nat Connected +2000 abort"
        );
        assert!(Script::parse(&text).is_ok());
        for bad in ["--send-rate 0", "--send-rate x", "--script"] {
            assert!(
                parse_args(v(&format!("{timed} --send 5 {bad}"))).is_none(),
                "{bad}"
            );
        }
        // IPv6 local, remote and join addresses (M3 spec §5.3).
        let v6 =
            "--mode mptcp --tun t0 --local fd00:91::2 --remote [dead:beef:1::2]:5201 --expect 0";
        let a = parse_args(v(&format!("{v6} --send 5 --join fd00:92::2"))).unwrap();
        let text = a.scenario().unwrap();
        assert_eq!(
            text,
            "\nat Connected +0 join fd00:92::2 [dead:beef:1::2]:5201 mtu 1500"
        );
        assert!(Script::parse(&text).is_ok());
        let a = parse_args(v(&format!("{timed} --send 5 --script /nonexistent"))).unwrap();
        assert!(a.scenario().is_err());
        assert!(parse_args(v(&format!("{timed} --send 5 --abort-after-ms x"))).is_none());
        assert!(
            parse_args(v(
                "--mode tcp --tun t0 --local 10.0.0.2 --remote 10.0.1.1:80 --send 1"
            ))
            .is_none()
        );
    }

    #[test]
    fn cc_arg() {
        let base =
            "--mode mptcp --tun t0 --local 10.0.0.2 --remote 10.0.1.1:80 --send 5 --expect 5";
        let cc = |extra: &str| {
            let s = format!("{base}{extra}");
            parse_args(s.split(' ').map(String::from)).map(|a| a.cc)
        };
        assert_eq!(cc(""), Some(CongestionControlKind::Cubic));
        assert_eq!(cc(" --cc cubic"), Some(CongestionControlKind::Cubic));
        assert_eq!(cc(" --cc bbr3"), Some(CongestionControlKind::BbrV3));
        assert_eq!(cc(" --cc bbr"), None);
        assert_eq!(cc(" --cc"), None);
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
