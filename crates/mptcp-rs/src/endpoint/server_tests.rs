use super::*;
use crate::crypto::key_token_idsn;
use crate::wire::mptcp::{self, CAP_H, DataAck, Dss, MpCapable, MptcpOption};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

/// Moves every packet `from` wants to send into `to`; returns how many.
fn shuttle(
    from: &mut Endpoint<ChaCha20Rng>,
    to: &mut Endpoint<ChaCha20Rng>,
    now: Instant,
) -> usize {
    let mut buf = [0u8; 1500];
    let mut n = 0;
    while let Some(len) = from.poll_transmit(now, &mut buf) {
        to.handle_packet(now, &buf[..len]);
        n += 1;
    }
    n
}

#[test]
fn half_open_hidden_until_established() {
    let now = Instant::from_nanos(0);
    let mut a = Endpoint::new(ChaCha20Rng::seed_from_u64(1));
    let mut b = Endpoint::new(ChaCha20Rng::seed_from_u64(2));
    let key: SocketAddr = "10.0.0.2:80".parse().unwrap();
    let cfg = ListenConfig {
        mptcp: false,
        ..Default::default()
    };
    b.listen(key, cfg).unwrap();
    let remote = key;
    a.connect(
        now,
        "10.0.0.1".parse().unwrap(),
        remote,
        ConnectConfig::default(),
    )
    .unwrap();
    assert_eq!(shuttle(&mut a, &mut b, now), 1, "the SYN");
    assert_eq!(
        b.next_handle, 1,
        "the half-open connection exists internally"
    );
    assert_eq!(b.listeners[&key].half_open, 1);
    for h in (0..b.next_handle).map(ConnectionHandle) {
        assert!(b.connection(h).is_none());
        let add = b.add_subflow(now, h, "10.0.0.2".parse().unwrap(), remote, 1500, false);
        assert_eq!(add, Err(AddSubflowError::NoConnection));
    }
    assert_eq!(b.poll_event(), None);
    assert_eq!(shuttle(&mut b, &mut a, now), 1, "the SYN/ACK");
    assert_eq!(shuttle(&mut a, &mut b, now), 1, "the final ACK");
    let h = ConnectionHandle(0);
    assert_eq!(b.poll_event(), Some((h, Event::Accepted { mptcp: false })));
    assert_eq!(b.poll_event(), None);
    assert!(b.connection(h).is_some());
    assert_eq!(b.listeners[&key].half_open, 0);
}

fn open_mptcp(ep: &mut Endpoint<ChaCha20Rng>, now: Instant) -> ConnectionHandle {
    ep.connect_mptcp(
        now,
        "10.0.0.1".parse().unwrap(),
        "10.0.0.2:80".parse().unwrap(),
        ConnectConfig::default(),
    )
    .unwrap()
}

fn token_of(ep: &Endpoint<ChaCha20Rng>, h: ConnectionHandle) -> u32 {
    ep.conns[&h].hooks.negotiation.as_ref().unwrap().token
}

#[test]
fn token_collision_client_client() {
    let now = Instant::from_nanos(0);
    let mut ep = Endpoint::new(ChaCha20Rng::seed_from_u64(1));
    ep.keys.extend([7, 7, 8]);
    let a = open_mptcp(&mut ep, now);
    let b = open_mptcp(&mut ep, now);
    assert_eq!(
        ep.conns[&a].hooks.negotiation.as_ref().unwrap().local_key,
        7
    );
    assert_eq!(
        ep.conns[&b].hooks.negotiation.as_ref().unwrap().local_key,
        8
    );
    assert_eq!(ep.tokens.len(), 2);
    assert_eq!(ep.tokens[&token_of(&ep, b)], b);
}

#[test]
fn token_freed_with_connection() {
    let now = Instant::from_nanos(0);
    let mut ep = Endpoint::new(ChaCha20Rng::seed_from_u64(1));
    ep.keys.extend([7, 7, 8]);
    let a = open_mptcp(&mut ep, now);
    let t = token_of(&ep, a);
    assert_eq!(ep.tokens.get(&t), Some(&a));
    // Closed in SYN-SENT: freed at the next timeout.
    ep.connection(a).unwrap().close();
    ep.handle_timeout(now);
    assert!(!ep.conns.contains_key(&a));
    assert!(ep.tokens.is_empty());
    let b = open_mptcp(&mut ep, now);
    assert_eq!(
        ep.conns[&b].hooks.negotiation.as_ref().unwrap().local_key,
        7
    );
    assert_eq!(token_of(&ep, b), t);
}

// ---------------------------------------------------------------------------------------------
// Server MP_CAPABLE (M4a Task 5): a scripted client against a listener on `SERVER`.

pub(super) const CLIENT: &str = "10.0.0.1:40000";
pub(super) const SERVER: &str = "10.0.0.2:80";
pub(super) const CLIENT_KEY: u64 = 0x1122_3344_5566_7788;
pub(super) const SERVER_KEY: u64 = 0x0807_0605_0403_0201;
/// The scripted client's ISN.
pub(super) const C_ISN: u32 = 1000;

/// MP_CAPABLE `version`, `flags` with the given keys and data length.
pub(super) fn cap(
    version: u8,
    flags: u8,
    sender: Option<u64>,
    receiver: Option<u64>,
    data_len: Option<u16>,
) -> Vec<u8> {
    let c = MpCapable {
        version,
        flags,
        sender_key: sender,
        receiver_key: receiver,
        data_len,
        checksum: None,
    };
    let mut out = [0; 40];
    let n = mptcp::encode(&MptcpOption::Capable(c), &mut out).unwrap();
    out[..n].to_vec()
}

/// The client's MP_CAPABLE on its SYN.
pub(super) fn syn_cap(version: u8, flags: u8) -> Vec<u8> {
    cap(version, flags, None, None, None)
}

/// The confirming forms: length 20 (`data_len` `None`) or 22, both keys right.
pub(super) fn ack_cap(flags: u8, data_len: Option<u16>) -> Vec<u8> {
    cap(1, flags, Some(CLIENT_KEY), Some(SERVER_KEY), data_len)
}

pub(super) fn dss_ack(ack: u64) -> Vec<u8> {
    let o = MptcpOption::Dss(Dss {
        data_fin: false,
        data_ack: Some(DataAck::Ack64(ack)),
        mapping: None,
    });
    let mut out = [0; 40];
    let n = mptcp::encode(&o, &mut out).unwrap();
    out[..n].to_vec()
}

/// The MPTCP options of an IP packet, raw.
pub(super) fn mptcp_of(bytes: &[u8]) -> Vec<Vec<u8>> {
    let seg = packet::parse(bytes).unwrap();
    walk(seg.options)
        .filter_map(|o| match o.unwrap() {
            TcpOpt::Mptcp(raw) => Some(raw.to_vec()),
            _ => None,
        })
        .collect()
}

pub(super) fn client_idsn() -> u64 {
    key_token_idsn(CLIENT_KEY).1
}

pub(super) fn server_idsn() -> u64 {
    key_token_idsn(SERVER_KEY).1
}

/// A listener on `SERVER` whose next key is `SERVER_KEY`, and a scripted client.
pub(super) struct Script {
    pub ep: Endpoint<ChaCha20Rng>,
    pub now: Instant,
    /// The server's ISS, from its SYN/ACK.
    pub iss: u32,
    /// The client's next sequence number.
    pub seq: u32,
}

impl Script {
    pub fn new(mptcp: bool) -> Self {
        let mut ep = Endpoint::new(ChaCha20Rng::seed_from_u64(9));
        let cfg = ListenConfig {
            mptcp,
            ..Default::default()
        };
        ep.listen(SERVER.parse().unwrap(), cfg).unwrap();
        ep.keys.push_back(SERVER_KEY);
        let now = Instant::from_nanos(0);
        Script {
            ep,
            now,
            iss: 0,
            seq: C_ISN,
        }
    }

    /// One segment from the client.
    pub fn input(&mut self, flags: TcpFlags, seq: u32, wnd: u16, options: &[u8], payload: &[u8]) {
        let seg = Segment {
            src: CLIENT.parse().unwrap(),
            dst: SERVER.parse().unwrap(),
            seq: SeqNum(seq),
            ack: SeqNum(self.iss.wrapping_add(1)),
            flags,
            wnd,
            options,
            payload,
        };
        let mut out = [0; 1500];
        let n = packet::build(&seg, 0, &mut out).unwrap();
        self.ep.handle_packet(self.now, &out[..n]);
    }

    /// Everything the server sends now.
    pub fn output(&mut self) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        let mut buf = [0; 1500];
        while let Some(n) = self.ep.poll_transmit(self.now, &mut buf) {
            out.push(buf[..n].to_vec());
        }
        out
    }

    /// The client's SYN with `options`; returns the SYN/ACK.
    pub fn syn(&mut self, options: &[u8]) -> Vec<u8> {
        self.input(TcpFlags::SYN, C_ISN, 65535, options, &[]);
        let out = self.output();
        assert_eq!(out.len(), 1, "one SYN/ACK");
        let s = packet::parse(&out[0]).unwrap();
        assert_eq!(s.flags, TcpFlags::SYN | TcpFlags::ACK);
        self.iss = s.seq.0;
        self.seq = C_ISN + 1;
        out[0].clone()
    }

    /// A client segment with ACK at the client's next sequence number; advances it.
    pub fn send(&mut self, wnd: u16, options: &[u8], payload: &[u8]) -> Vec<Vec<u8>> {
        self.input(TcpFlags::ACK, self.seq, wnd, options, payload);
        self.seq += payload.len() as u32;
        self.output()
    }

    pub fn events(&mut self) -> Vec<Event> {
        std::iter::from_fn(|| self.ep.poll_event())
            .map(|(_, e)| e)
            .collect()
    }

    /// The accepted connection (the only one).
    pub fn conn(&mut self) -> &mut Connection {
        self.ep.connection(ConnectionHandle(0)).unwrap()
    }

    pub fn negotiation(&self) -> &crate::mptcp::Negotiation {
        let c = &self.ep.conns[&ConnectionHandle(0)];
        c.hooks.negotiation.as_ref().unwrap()
    }

    /// Reads everything readable.
    pub fn read_all(&mut self) -> Vec<u8> {
        let mut buf = [0; 4096];
        let n = self.conn().read(&mut buf).unwrap_or(0);
        buf[..n].to_vec()
    }

    /// The server writes, then the client sends a segment: no MPTCP option goes out.
    pub fn assert_plain_after(&mut self) {
        self.conn().write(b"server data").unwrap();
        let mut out = self.output();
        out.extend(self.send(65535, &[], b"more"));
        assert!(!out.is_empty());
        for p in &out {
            assert!(mptcp_of(p).is_empty(), "MPTCP option after fallback");
        }
    }
}

#[test]
fn token_collision_server_server() {
    let mut ep = Endpoint::new(ChaCha20Rng::seed_from_u64(1));
    ep.listen(SERVER.parse().unwrap(), ListenConfig::default())
        .unwrap();
    ep.keys.extend([7, 7, 8]);
    for port in [40000, 40001] {
        let seg = Segment {
            src: SocketAddr::new("10.0.0.1".parse().unwrap(), port),
            dst: SERVER.parse().unwrap(),
            seq: SeqNum(C_ISN),
            ack: SeqNum(0),
            flags: TcpFlags::SYN,
            wnd: 65535,
            options: &syn_cap(1, CAP_H),
            payload: &[],
        };
        let mut out = [0; 1500];
        let n = packet::build(&seg, 0, &mut out).unwrap();
        ep.handle_packet(Instant::from_nanos(0), &out[..n]);
    }
    let keys: Vec<_> = (0..2)
        .map(|h| ep.conns[&ConnectionHandle(h)].hooks.negotiation.as_ref())
        .map(|n| n.unwrap().local_key)
        .collect();
    assert_eq!(keys, [7, 8]);
    assert_eq!(ep.tokens.len(), 2);
    // Each SYN/ACK carries its connection's key.
    let mut buf = [0; 1500];
    for key in [7u64, 8] {
        let n = ep.poll_transmit(Instant::from_nanos(0), &mut buf).unwrap();
        assert_eq!(mptcp_of(&buf[..n]), [cap(1, CAP_H, Some(key), None, None)]);
    }
}

#[test]
fn token_collision_client_server() {
    let now = Instant::from_nanos(0);
    let mut ep = Endpoint::new(ChaCha20Rng::seed_from_u64(1));
    ep.listen(SERVER.parse().unwrap(), ListenConfig::default())
        .unwrap();
    ep.keys.extend([7, 7, 8]);
    let client = ep
        .connect_mptcp(
            now,
            "10.0.0.2".parse().unwrap(),
            "10.0.0.3:80".parse().unwrap(),
            ConnectConfig::default(),
        )
        .unwrap();
    let seg = Segment {
        src: CLIENT.parse().unwrap(),
        dst: SERVER.parse().unwrap(),
        seq: SeqNum(C_ISN),
        ack: SeqNum(0),
        flags: TcpFlags::SYN,
        wnd: 65535,
        options: &syn_cap(1, CAP_H),
        payload: &[],
    };
    let mut out = [0; 1500];
    let n = packet::build(&seg, 0, &mut out).unwrap();
    ep.handle_packet(now, &out[..n]);
    let server = ConnectionHandle(1);
    let key = |h| ep.conns[&h].hooks.negotiation.as_ref().unwrap().local_key;
    assert_eq!((key(client), key(server)), (7, 8));
    assert_eq!(ep.tokens.len(), 2);
    assert_eq!(ep.tokens[&key_token_idsn(8).0], server);
}

/// The client's SYN has WS 7: the MPTCP send edge is `DATA_ACK + (wnd << 7)`, from the
/// confirming segment and from a later DATA_ACK (RFC 7323 §2.2 scaling of non-SYN windows).
#[test]
fn server_mptcp_send_edge_scaled() {
    let mut s = Script::new(true);
    s.syn(&[syn_cap(1, CAP_H), vec![1, 3, 3, 7]].concat());
    s.send(100, &ack_cap(CAP_H, None), &[]);
    assert_eq!(
        s.events(),
        [Event::Accepted { mptcp: true }],
        "Accepted on the final ACK"
    );
    let edge = |s: &Script| s.negotiation().send_right_edge;
    let una = server_idsn().wrapping_add(1);
    assert_eq!(edge(&s), Some(una + (100 << 7)));
    s.send(300, &dss_ack(una), &[]);
    assert_eq!(edge(&s), Some(una + (300 << 7)));
}

/// A final ACK that confirms MPTCP (taking the client's key) and then fails, its data_len 0
/// mapping refused, resets the half-open connection. It is freed with its token and demux
/// entry once the RST is out, not kept for the no-subflow wait: repeated, these would bypass
/// `max_half_open` (spec G9) with nothing the application can abort (spec G10).
#[test]
fn half_open_failed_final_ack_freed() {
    let now = Instant::from_nanos(0);
    let mut ep = Endpoint::new(ChaCha20Rng::seed_from_u64(1));
    let cfg = ListenConfig {
        max_half_open: 1,
        ..Default::default()
    };
    let server: SocketAddr = SERVER.parse().unwrap();
    ep.listen(server, cfg).unwrap();
    let input = |ep: &mut Endpoint<ChaCha20Rng>, seg: Segment| {
        let mut out = [0; 1500];
        let n = packet::build(&seg, 0, &mut out).unwrap();
        ep.handle_packet(now, &out[..n]);
        let mut sent = Vec::new();
        while let Some(n) = ep.poll_transmit(now, &mut out) {
            sent.push(out[..n].to_vec());
        }
        sent
    };
    for round in 0..3u16 {
        let key = SERVER_KEY + u64::from(round);
        ep.keys.push_back(key);
        let syn = Segment {
            src: SocketAddr::new("10.0.0.1".parse().unwrap(), 40000 + round),
            dst: server,
            seq: SeqNum(C_ISN),
            ack: SeqNum(0),
            flags: TcpFlags::SYN,
            wnd: 65535,
            options: &syn_cap(1, CAP_H),
            payload: &[],
        };
        let out = input(&mut ep, syn.clone());
        assert_eq!(out.len(), 1, "round {round}: the SYN/ACK; the slot is free");
        let synack = packet::parse(&out[0]).unwrap();
        assert_eq!(synack.flags, TcpFlags::SYN | TcpFlags::ACK);
        let option = cap(1, CAP_H, Some(CLIENT_KEY), Some(key), Some(0));
        let ack = Segment {
            seq: SeqNum(C_ISN + 1),
            ack: synack.seq.wrapping_add(1),
            flags: TcpFlags::ACK,
            options: &option,
            payload: b"x",
            ..syn
        };
        let out = input(&mut ep, ack);
        let rst = |p: &Vec<u8>| packet::parse(p).unwrap().flags.contains(TcpFlags::RST);
        assert!(out.iter().any(rst), "round {round}: the final ACK is reset");
        ep.handle_timeout(now);
        assert_eq!(ep.poll_event(), None);
        assert_eq!(ep.listeners[&server].half_open, 0);
        let counts = (ep.conns.len(), ep.tokens.len(), ep.demux.len());
        assert_eq!(counts, (0, 0, 0), "round {round}: freed");
    }
}
