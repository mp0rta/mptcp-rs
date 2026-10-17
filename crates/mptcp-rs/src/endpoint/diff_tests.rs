//! Differential test (issue #12): randomized two-endpoint scenarios run once with the full
//! scan (`Endpoint::full_scan`, the test-only oracle) and once without. Every packet, in order,
//! and every event, `poll_timeout` value, read and API result must be the same.
use super::*;
use crate::tcp::CongestionControlKind;
use crate::wire::packet::{build, parse};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use std::net::Ipv6Addr;
use std::time::Duration;

/// splitmix64: the scenario's randomness, apart from the endpoints'.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: u64) -> u64 {
        if n == 0 { 0 } else { self.next() % n }
    }

    /// True with probability `pm` per mille.
    fn pm(&mut self, pm: u64) -> bool {
        self.below(1000) < pm
    }
}

/// What a driver observes, in order.
#[derive(Debug, PartialEq)]
enum Rec {
    Packet(usize, u64, Vec<u8>),
    Event(usize, u64, String),
    Timeout(usize, u64, Option<Instant>),
    Read(usize, u64, String),
    Call(usize, u64, String),
}

struct Params {
    conns: u64,
    open_spread_ms: u64,
    mptcp_pm: u64,
    server_mptcp: bool,
    joins: bool,
    loss_pm: u64,
    reorder_pm: u64,
    delay_ms: u64,
    path2_extra_ms: u64,
    /// 0: a well-behaved driver; 1: spurious and late `handle_timeout`; 2: partial drains,
    /// small buffers and shuffled inputs; 3: `unlisten` too.
    adversarial: u64,
    duration_ms: u64,
    max_write: u64,
    /// CUBIC, BBRv3 or either, per connection.
    cc: u64,
    /// Off, on or either, per connection.
    checksums: u64,
    small_bufs: bool,
    max_half_open: usize,
    v6: bool,
    lazy_reads: bool,
    /// The application looks at every connection at each of its turns, or at some.
    poll_all: bool,
    /// (path, from ms, length ms); path 0 is both.
    blackholes: Vec<(u8, u64, u64)>,
    /// MPTCP options stripped: never, on path 2, or now and then.
    strip: u8,
    corrupt_pm: u64,
}

impl Params {
    /// Scenario `seed`; `big` ones run longer, with more connections and data.
    fn new(seed: u64, big: bool) -> Self {
        let mut r = Rng(seed ^ 0x6d70_7463_7072_7321);
        let many = r.pm(150);
        let p = Params {
            conns: 1 + r.below(match (big, many) {
                (false, false) => 4,
                (false, true) => 16,
                (true, false) => 8,
                (true, true) => 60,
            }),
            open_spread_ms: r.below(2000),
            mptcp_pm: [0, 500, 1000, 1000][r.below(4) as usize],
            server_mptcp: r.pm(900),
            joins: r.pm(700),
            loss_pm: [0, 0, 5, 20, 50][r.below(5) as usize],
            reorder_pm: [0, 0, 20, 100][r.below(4) as usize],
            delay_ms: 1 + r.below(30),
            path2_extra_ms: r.below(40),
            adversarial: r.below(4),
            duration_ms: [2_000, 5_000, 15_000, 60_000][r.below(if big { 4 } else { 3 }) as usize],
            max_write: [1_000, 20_000, 200_000, 2_000_000]
                [r.below(if big { 4 } else { 3 }) as usize],
            cc: r.below(3),
            checksums: r.below(3),
            small_bufs: r.pm(200),
            max_half_open: if r.pm(150) {
                1 + r.below(3) as usize
            } else {
                256
            },
            v6: r.pm(200),
            lazy_reads: r.pm(300),
            poll_all: r.pm(500),
            blackholes: Vec::new(),
            strip: if r.pm(100) { 1 + r.below(2) as u8 } else { 0 },
            corrupt_pm: if r.pm(100) { 1 + r.below(10) } else { 0 },
        };
        let blackholes = if r.pm(250) {
            let n = 1 + r.below(3);
            (0..n)
                .map(|_| {
                    (
                        r.below(3) as u8,
                        r.below(p.duration_ms),
                        200 + r.below(5_000),
                    )
                })
                .collect()
        } else {
            Vec::new()
        };
        Params { blackholes, ..p }
    }
}

/// One side's view of a connection.
struct App {
    ep: usize,
    h: ConnectionHandle,
    to_write: u64,
    written: u64,
    up: bool,
    mptcp: bool,
    lazy: bool,
    closed: bool,
    done: bool,
    subflows: Vec<SubflowId>,
}

struct Sim {
    p: Params,
    r: Rng,
    eps: [Endpoint<ChaCha20Rng>; 2],
    /// Packets in flight from each endpoint: (arrival, sequence) → packet.
    links: [BTreeMap<(u64, u64), Vec<u8>>; 2],
    sent: u64,
    now: u64,
    trace: Vec<Rec>,
    apps: Vec<App>,
    /// Client paths 1 and 2, then the server.
    ips: [IpAddr; 3],
    server: SocketAddr,
}

impl Sim {
    fn t(&self) -> Instant {
        Instant::from_nanos(self.now)
    }

    fn call(&mut self, ep: usize, s: String) {
        self.trace.push(Rec::Call(ep, self.now, s));
    }

    fn send(&mut self, from: usize, pkt: Vec<u8>) {
        self.trace.push(Rec::Packet(from, self.now, pkt.clone()));
        if self.r.pm(self.p.loss_pm) {
            return;
        }
        let Ok(seg) = parse(&pkt) else {
            return;
        };
        let client_ip = if from == 0 {
            seg.src.ip()
        } else {
            seg.dst.ip()
        };
        let path = if client_ip == self.ips[1] { 2 } else { 1 };
        let ms = self.now / 1_000_000;
        let holes = &self.p.blackholes;
        if holes
            .iter()
            .any(|&(p, at, len)| (p == 0 || p == path) && ms >= at && ms < at + len)
        {
            return;
        }
        let pkt = self.mangle(pkt, path == 2);
        let mut d = self.p.delay_ms * 1_000_000;
        if path == 2 {
            d += self.p.path2_extra_ms * 1_000_000;
        }
        if self.r.pm(self.p.reorder_pm) {
            d += 1_000_000 + self.r.below(20_000_000);
        }
        self.sent += 1;
        self.links[from].insert((self.now + d, self.sent), pkt);
    }

    /// A middlebox: strips MPTCP options (NOPs in their place) or corrupts a payload octet,
    /// with fresh checksums.
    fn mangle(&mut self, pkt: Vec<u8>, path2: bool) -> Vec<u8> {
        let strip = match self.p.strip {
            1 => path2,
            2 => self.r.pm(20),
            _ => false,
        };
        let corrupt = self.r.pm(self.p.corrupt_pm);
        if !strip && !corrupt {
            return pkt;
        }
        let Ok(seg) = parse(&pkt) else {
            return pkt;
        };
        let mut options = seg.options.to_vec();
        let mut i = 0;
        while strip && i < options.len() {
            match options[i] {
                0 => break,
                1 => i += 1,
                kind => {
                    let len = usize::from(*options.get(i + 1).unwrap_or(&2)).max(2);
                    let end = (i + len).min(options.len());
                    if kind == 30 {
                        options[i..end].fill(1);
                    }
                    i = end;
                }
            }
        }
        let mut payload = seg.payload.to_vec();
        if corrupt && !payload.is_empty() {
            let k = self.r.below(payload.len() as u64) as usize;
            payload[k] ^= 0x5a;
        }
        let seg = Segment {
            options: &options,
            payload: &payload,
            ..seg
        };
        let mut buf = vec![0; pkt.len() + 64];
        match build(&seg, 0, &mut buf) {
            Ok(n) => {
                buf.truncate(n);
                buf
            }
            Err(_) => pkt,
        }
    }

    /// Everything `ep` has to send, or at most `limit` packets.
    fn drain(&mut self, ep: usize, limit: Option<usize>) {
        let mut k = 0;
        while limit.is_none_or(|l| k < l) {
            // Now and then a buffer smaller than the MTU, which must hold nothing back.
            let small = self.p.adversarial >= 2 && self.r.pm(30);
            let mut buf = vec![0; if small { 1400 } else { 1500 }];
            let mut n = self.eps[ep].poll_transmit(self.t(), &mut buf);
            if n.is_none() && small {
                buf = vec![0; 1500];
                n = self.eps[ep].poll_transmit(self.t(), &mut buf);
            }
            let Some(n) = n else {
                return;
            };
            buf.truncate(n);
            self.send(ep, buf);
            k += 1;
        }
    }

    /// After an input: the driver contract's full drain, or less from a careless driver.
    fn after_input(&mut self, ep: usize) {
        if self.p.adversarial < 2 || self.r.pm(600) {
            self.drain(ep, None);
        } else if self.r.pm(500) {
            let k = self.r.below(3) as usize;
            self.drain(ep, Some(k));
        }
    }

    fn deliver(&mut self) {
        loop {
            let first = |l: &BTreeMap<(u64, u64), Vec<u8>>| l.first_key_value().map(|(k, _)| *k);
            let next = [0, 1]
                .into_iter()
                .filter_map(|from| first(&self.links[from]).map(|k| (k, from)))
                .filter(|&((at, _), _)| at <= self.now)
                .min();
            let Some((key, from)) = next else {
                return;
            };
            let pkt = self.links[from].remove(&key).unwrap();
            let to = 1 - from;
            self.eps[to].handle_packet(self.t(), &pkt);
            self.after_input(to);
        }
    }

    fn timeouts(&mut self) {
        for ep in 0..2 {
            let due = self.eps[ep].poll_timeout().is_some_and(|t| t <= self.t());
            if due || (self.p.adversarial >= 1 && self.r.pm(50)) {
                self.call(ep, format!("handle_timeout due={due}"));
                self.eps[ep].handle_timeout(self.t());
                self.after_input(ep);
            }
        }
    }

    fn events(&mut self) {
        for ep in 0..2 {
            while let Some((h, e)) = self.eps[ep].poll_event() {
                self.trace
                    .push(Rec::Event(ep, self.now, format!("{h:?} {e:?}")));
                if let Event::Accepted { mptcp } = e {
                    let to_write = self.r.below(self.p.max_write + 1);
                    let lazy = self.p.lazy_reads && self.r.pm(500);
                    self.apps.push(App {
                        ep,
                        h,
                        to_write,
                        written: 0,
                        up: true,
                        mptcp,
                        lazy,
                        closed: false,
                        done: false,
                        subflows: Vec::new(),
                    });
                    continue;
                }
                for a in self.apps.iter_mut().filter(|a| a.ep == ep && a.h == h) {
                    match e {
                        Event::Connected { mptcp } => (a.up, a.mptcp) = (true, mptcp),
                        Event::Closed { .. } => a.done = true,
                        Event::SubflowUp { subflow } => a.subflows.push(subflow),
                        Event::SubflowDown { subflow, .. } => a.subflows.retain(|&s| s != subflow),
                        Event::FellBack => a.mptcp = false,
                        _ => {}
                    }
                }
            }
        }
    }

    fn config(&mut self) -> ConnectConfig {
        let mut cfg = ConnectConfig::default();
        if self.p.cc == 1 || (self.p.cc == 2 && self.r.pm(500)) {
            cfg.congestion_control = CongestionControlKind::BbrV3;
        }
        cfg.checksums = self.p.checksums == 1 || (self.p.checksums == 2 && self.r.pm(500));
        if self.p.small_bufs {
            cfg.recv_buffer = 4096 + self.r.below(60_000) as u32;
            cfg.send_buffer = 4096 + self.r.below(60_000) as u32;
        }
        if self.r.pm(100) {
            cfg.r2_data = Duration::from_secs(2 + self.r.below(10));
        }
        cfg
    }

    fn open(&mut self) {
        let cfg = self.config();
        let mptcp = self.r.pm(self.p.mptcp_pm);
        let (t, local, server) = (self.t(), self.ips[0], self.server);
        let r = if mptcp {
            self.eps[0].connect_mptcp(t, local, server, cfg)
        } else {
            self.eps[0].connect(t, local, server, cfg)
        };
        self.call(0, format!("connect mptcp={mptcp} {r:?}"));
        if let Ok(h) = r {
            let to_write = self.r.below(self.p.max_write + 1);
            let lazy = self.p.lazy_reads && self.r.pm(500);
            self.apps.push(App {
                ep: 0,
                h,
                to_write,
                written: 0,
                up: false,
                mptcp,
                lazy,
                closed: false,
                done: false,
                subflows: Vec::new(),
            });
        }
        self.after_input(0);
    }

    /// The application's turn: reads, writes, close and abort, `set_nodelay`, and the
    /// client's path calls.
    fn app_tick(&mut self) {
        for i in 0..self.apps.len() {
            if !self.p.poll_all && !self.r.pm(300) {
                continue;
            }
            let (ep, h, now) = (self.apps[i].ep, self.apps[i].h, self.now);
            let read = !self.apps[i].lazy || self.r.pm(100);
            let mut buf = vec![0; 1 + self.r.below(70_000) as usize];
            let Some(c) = self.eps[ep].connection(h) else {
                continue;
            };
            let mut more = read;
            while more {
                let r = c.read(&mut buf);
                let s = match r {
                    Ok(k) => format!("{h:?} {k} {:?}", &buf[..k.min(8)]),
                    Err(e) => format!("{h:?} {e:?}"),
                };
                self.trace.push(Rec::Read(ep, now, s));
                more = matches!(r, Ok(k) if k > 0) && !self.r.pm(300);
            }
            if !self.apps[i].up {
                continue;
            }
            let a = &mut self.apps[i];
            if a.to_write > 0 && !a.closed {
                let k = (1 + self.r.below(65_536)).min(a.to_write) as usize;
                let data: Vec<u8> = (0..k)
                    .map(|j| ((a.written as usize + j) % 251) as u8)
                    .collect();
                let r = c.write(&data);
                if let Ok(w) = r {
                    a.to_write -= w as u64;
                    a.written += w as u64;
                }
                self.trace
                    .push(Rec::Call(ep, now, format!("{h:?} write {k} {r:?}")));
            }
            let a = &mut self.apps[i];
            if a.to_write == 0 && !a.closed && self.r.pm(200) {
                c.close();
                a.closed = true;
                self.trace.push(Rec::Call(ep, now, format!("{h:?} close")));
            }
            if self.r.pm(2) {
                c.abort();
                self.apps[i].closed = true;
                self.trace.push(Rec::Call(ep, now, format!("{h:?} abort")));
            }
            if self.r.pm(5) {
                let v = self.r.pm(500);
                c.set_nodelay(v);
                self.trace
                    .push(Rec::Call(ep, now, format!("{h:?} nodelay {v}")));
            }
            let a = &self.apps[i];
            if ep != 0 || !a.mptcp || !self.p.joins || a.done {
                continue;
            }
            let (t, ip, server) = (self.t(), self.ips[1], self.server);
            if a.subflows.len() < 2 && self.r.pm(30) {
                let backup = self.r.pm(200);
                let mtu = if self.r.pm(100) { 1400 } else { 1500 };
                let r = self.eps[0].add_subflow(t, h, ip, server, mtu, backup);
                self.call(0, format!("{h:?} add_subflow {r:?}"));
            }
            if let Some(&s) = self.apps[i].subflows.first() {
                if self.r.pm(5) {
                    let r = self.eps[0].close_subflow(t, h, s);
                    self.call(0, format!("{h:?} close_subflow {s:?} {r:?}"));
                }
                if self.r.pm(5) {
                    let v = self.r.pm(500);
                    let r = self.eps[0].set_backup(t, h, s, v);
                    self.call(0, format!("{h:?} set_backup {s:?} {v} {r:?}"));
                }
                if self.r.pm(5) {
                    let v = self.r.pm(500);
                    let r = self.eps[0].set_local_backup(h, s, v);
                    self.call(0, format!("{h:?} set_local_backup {s:?} {v} {r:?}"));
                }
            }
            if self.r.pm(2) {
                let r = self.eps[0].remove_address(t, h, ip);
                self.call(0, format!("{h:?} remove_address {r:?}"));
            }
        }
        for ep in 0..2 {
            self.after_input(ep);
        }
    }
}

/// Runs scenario `seed`, with the full scan or not, and returns what a driver observed.
fn run(seed: u64, big: bool, full_scan: bool) -> Vec<Rec> {
    let p = Params::new(seed, big);
    let ips: [IpAddr; 3] = if p.v6 {
        let v6 = |s: &str| IpAddr::V6(s.parse::<Ipv6Addr>().unwrap());
        [v6("fd00:1::1"), v6("fd00:2::1"), v6("fd00::2")]
    } else {
        [
            "10.0.1.1".parse().unwrap(),
            "10.0.2.1".parse().unwrap(),
            "10.0.0.2".parse().unwrap(),
        ]
    };
    let mut eps = [
        Endpoint::new(ChaCha20Rng::seed_from_u64(seed.wrapping_mul(3))),
        Endpoint::new(ChaCha20Rng::seed_from_u64(seed.wrapping_mul(3) + 1)),
    ];
    for ep in &mut eps {
        ep.full_scan = full_scan;
    }
    let mut sim = Sim {
        r: Rng(seed),
        eps,
        links: Default::default(),
        sent: 0,
        now: 0,
        trace: Vec::new(),
        apps: Vec::new(),
        ips,
        server: SocketAddr::new(ips[2], 80),
        p,
    };
    let cfg = ListenConfig {
        connection: sim.config(),
        mptcp: sim.p.server_mptcp,
        max_half_open: sim.p.max_half_open,
    };
    let r = sim.eps[1].listen(sim.server, cfg);
    sim.call(1, format!("listen {r:?}"));
    let mut opens: Vec<u64> = (0..sim.p.conns)
        .map(|_| sim.r.below(sim.p.open_spread_ms * 1_000_000 + 1))
        .collect();
    opens.sort_unstable();
    let mut opens = VecDeque::from(opens);
    let end = sim.p.duration_ms * 1_000_000;
    let (mut tick, mut unlistened) = (0, false);
    for _ in 0..1_000_000 {
        let (now, adversarial) = (sim.now, sim.p.adversarial);
        let timeouts = [sim.eps[0].poll_timeout(), sim.eps[1].poll_timeout()];
        for (ep, t) in timeouts.into_iter().enumerate() {
            sim.trace.push(Rec::Timeout(ep, now, t));
        }
        let arrival = (sim.links.iter())
            .filter_map(|l| l.first_key_value().map(|(k, _)| k.0))
            .min();
        let active = sim.apps.iter().any(|a| !a.done) || !opens.is_empty();
        let next = (timeouts.into_iter().flatten().map(|t| t.as_nanos()))
            .chain(arrival)
            .chain(opens.front().copied())
            .chain(active.then_some(tick))
            .min();
        let Some(next) = next.filter(|&t| t <= end) else {
            break;
        };
        sim.now = next.max(now);
        if adversarial >= 1 && sim.r.pm(50) {
            // Late: deadlines pass before the driver gets to them.
            sim.now += sim.r.below(5_000_000);
        }
        let order = if adversarial >= 2 { sim.r.below(6) } else { 0 };
        let order = [
            [0, 1, 2],
            [0, 2, 1],
            [1, 0, 2],
            [1, 2, 0],
            [2, 0, 1],
            [2, 1, 0],
        ][order as usize];
        for step in order {
            match step {
                0 => sim.deliver(),
                1 => sim.timeouts(),
                _ => {
                    while opens.front().is_some_and(|&t| t <= sim.now) {
                        opens.pop_front();
                        sim.open();
                    }
                    if sim.now >= tick {
                        sim.app_tick();
                        tick = sim.now + 1_000_000 + sim.r.below(50_000_000);
                    }
                }
            }
        }
        if adversarial >= 3 && !unlistened && sim.now > end / 2 && sim.r.pm(20) {
            unlistened = true;
            let r = sim.eps[1].unlisten(sim.server);
            sim.call(1, format!("unlisten {r}"));
        }
        for ep in 0..2 {
            if adversarial < 2 || sim.r.pm(800) {
                sim.drain(ep, None);
            }
        }
        sim.events();
    }
    sim.trace
}

/// Asserts that scenarios `seeds` run the same with the full scan and without.
fn check(seeds: impl IntoIterator<Item = u64>, big: bool) {
    for seed in seeds {
        let (oracle, fast) = (run(seed, big, true), run(seed, big, false));
        if let Some(i) = (0..oracle.len().max(fast.len())).find(|&i| oracle.get(i) != fast.get(i)) {
            let around = |v: &[Rec]| {
                format!(
                    "{:?}",
                    &v[i.saturating_sub(3).min(v.len())..(i + 2).min(v.len())]
                )
            };
            panic!(
                "seed {seed}: record {i} differs\nfull scan: {}\nfast:      {}",
                around(&oracle),
                around(&fast)
            );
        }
        assert!(
            oracle.iter().any(|r| matches!(r, Rec::Packet(..))),
            "seed {seed}: nothing sent"
        );
    }
}

#[test]
fn same_packets_and_timeouts_as_the_full_scan() {
    check(1..=40, false);
}

/// More and larger scenarios:
/// `DIFF_SEEDS=1..1000 cargo test --release -p mptcp-rs diff_tests -- --ignored`.
#[test]
#[ignore]
fn same_packets_and_timeouts_as_the_full_scan_many() {
    let seeds = std::env::var("DIFF_SEEDS").unwrap_or_else(|_| "1..1000".into());
    let (a, b) = seeds.split_once("..").expect("DIFF_SEEDS=first..last");
    check(a.parse().unwrap()..=b.parse().unwrap(), true);
}
