//! DSS checksums (M4b spec G1–G5): the A-bit negotiation in both roles, the checksum on every
//! mapping we send, and the presence check on every mapping we receive.
use super::super::server_tests::*;
use super::*;
use crate::crypto::key_token_idsn;
use crate::wire::mptcp::{CAP_A, Dss, Mapping, dss_checksum, dss_checksum_ok};

const BOTH: [(bool, bool); 4] = [(false, false), (false, true), (true, false), (true, true)];

fn a(on: bool) -> u8 {
    if on { CAP_A } else { 0 }
}

fn t(n: u64) -> Instant {
    Instant::from_nanos(n)
}

fn checksums_cfg(checksums: bool) -> ConnectConfig {
    ConnectConfig {
        checksums,
        ..ConnectConfig::default()
    }
}

fn negotiation(ep: &Endpoint<ChaCha20Rng>, h: ConnectionHandle) -> &crate::mptcp::Negotiation {
    ep.conns[&h].hooks.negotiation.as_ref().unwrap()
}

/// The DSS of an MPTCP option, if it is one.
fn dss(raw: &[u8]) -> Option<Dss> {
    match mptcp::parse(raw) {
        Ok(MptcpOption::Dss(d)) => Some(d),
        _ => None,
    }
}

fn encode(o: &MptcpOption) -> Vec<u8> {
    let mut out = [0; 40];
    let n = mptcp::encode(o, &mut out).unwrap();
    out[..n].to_vec()
}

fn dss_mapping(data_fin: bool, ssn: u32, dsn: u64, len: u16, checksum: Option<u16>) -> Vec<u8> {
    encode(&MptcpOption::Dss(Dss {
        data_fin,
        data_ack: None,
        mapping: Some(Mapping {
            dsn: mptcp::Dsn::Dsn64(dsn),
            ssn,
            data_len: len,
            checksum,
        }),
    }))
}

// ---------------------------------------------------------------------------------------------
// Client role, against a scripted server.

struct Client {
    ep: Endpoint<ChaCha20Rng>,
    h: ConnectionHandle,
    syn: Segment<'static>,
    /// The flags of our SYN's MP_CAPABLE.
    syn_flags: u8,
    /// Our third ACK's MP_CAPABLE.
    third: Vec<u8>,
}

/// A client with `checksums` (Reno, no pacing) against a SYN/ACK whose MP_CAPABLE has
/// A=`peer_a`, MSS 1460 and WS 7. The third ACK is sent.
fn client(checksums: bool, peer_a: bool) -> Client {
    let mut ep = Endpoint::new(ChaCha20Rng::seed_from_u64(41));
    ep.cc = Some(reno);
    let h = ep
        .connect_mptcp(
            t(0),
            "10.0.0.1".parse().unwrap(),
            "10.0.0.2:80".parse().unwrap(),
            checksums_cfg(checksums),
        )
        .unwrap();
    let syn = packet::parse(transmit(&mut ep, t(0)).leak()).unwrap();
    let syn_flags = mpc(syn.options)[0][3];
    let mut opts = capable(1, CAP_H | a(peer_a));
    let mut o = [0; 4];
    let n = crate::wire::tcp_options::write_mss(&mut o, 1460);
    opts.extend_from_slice(&o[..n]);
    let n = crate::wire::tcp_options::write_ws(&mut o, 7);
    opts.extend_from_slice(&o[..n]);
    reply(&mut ep, &syn, &opts, syn.seq.wrapping_add(1));
    let ack = transmit(&mut ep, t(1));
    let third = mpc(packet::parse(&ack).unwrap().options)[0].to_vec();
    Client {
        ep,
        h,
        syn,
        syn_flags,
        third,
    }
}

impl Client {
    /// Our IDSN + 1, from the key our third ACK carries.
    fn head(&self) -> u64 {
        let MptcpOption::Capable(c) = mptcp::parse(&self.third).unwrap() else {
            panic!()
        };
        key_token_idsn(c.sender_key.unwrap()).1.wrapping_add(1)
    }
    /// The peer's DATA_ACK at our send head opens 128,000 octets and confirms us.
    fn confirm(&mut self) {
        let head = una(&self.ep, self.h);
        let syn = self.syn.clone();
        peer_ack(
            &mut self.ep,
            &syn,
            t(2),
            syn.seq.wrapping_add(1),
            head,
            1000,
        );
        assert_eq!(negotiation(&self.ep, self.h).state, State::Confirmed);
    }
    /// The packets due at `now`, parsed.
    fn sent(&mut self, now: Instant) -> Vec<Segment<'static>> {
        let out = drain(&mut self.ep, now);
        out.into_iter()
            .map(|p| packet::parse(p.leak()).unwrap())
            .collect()
    }
    /// The peer's segment at its next sequence number with `options` and `payload`.
    fn peer(&mut self, options: &[u8], payload: &[u8]) -> Vec<Segment<'static>> {
        let syn = self.syn.clone();
        input(&mut self.ep, &peer_data(&syn, 5001, options, payload));
        self.sent(t(2))
    }
}

/// The mapping of the DSS a segment carries.
fn seg_mapping(seg: &Segment) -> Option<(Mapping, bool)> {
    let d = mpc(seg.options).into_iter().find_map(dss)?;
    d.mapping.map(|m| (m, d.data_fin))
}

fn dsn64(m: &Mapping) -> u64 {
    let mptcp::Dsn::Dsn64(dsn) = m.dsn else {
        panic!("64-bit DSNs only")
    };
    dsn
}

/// One client case of the matrix: SYN A = `checksums`; the third ACK and the first data's
/// MP_CAPABLE (length 24 with its checksum, else 22) carry A = `csum`; the DSS mapping after
/// confirmation carries its checksum exactly when `csum` (spec G1, G2, G4, G5).
fn client_case(checksums: bool, peer_a: bool) {
    let csum = checksums || peer_a;
    let mut c = client(checksums, peer_a);
    assert_eq!(c.syn_flags, CAP_H | a(checksums));
    assert_eq!(
        c.ep.poll_event(),
        Some((c.h, Event::Connected { mptcp: true }))
    );
    assert_eq!(negotiation(&c.ep, c.h).csum, csum);
    let MptcpOption::Capable(third) = mptcp::parse(&c.third).unwrap() else {
        panic!()
    };
    assert_eq!((c.third.len(), third.flags), (20, CAP_H | a(csum)));
    let head = c.head();
    c.ep.connection(c.h).unwrap().write(b"hello").unwrap();
    let sent = c.sent(t(2));
    let opt = mpc(sent[0].options)[0].to_vec();
    let MptcpOption::Capable(first) = mptcp::parse(&opt).unwrap() else {
        panic!("MP_CAPABLE with data")
    };
    assert_eq!(opt.len(), if csum { 24 } else { 22 });
    assert_eq!(first.flags, CAP_H | a(csum));
    let ck = dss_checksum(head, 1, 5, &[b"hello"]);
    assert_eq!(first.checksum, csum.then_some(ck));
    // The peer acknowledges "hello" at both levels, which confirms us.
    let syn = c.syn.clone();
    let ack = sent[0].seq.wrapping_add(5);
    peer_ack(&mut c.ep, &syn, t(2), ack, head + 5, 1000);
    assert_eq!(negotiation(&c.ep, c.h).state, State::Confirmed);
    c.ep.connection(c.h).unwrap().write(b"world").unwrap();
    let sent = c.sent(t(3));
    let seg = sent.iter().find(|s| s.payload == b"world").unwrap();
    let (m, _) = seg_mapping(seg).unwrap();
    assert_eq!((dsn64(&m), m.ssn, m.data_len), (head + 5, 6, 5));
    let ck = dss_checksum(head + 5, 6, 5, &[b"world"]);
    assert_eq!(m.checksum, csum.then_some(ck));
    assert_eq!(negotiation(&c.ep, c.h).state, State::Confirmed);
}

#[test]
fn client_negotiation_matrix() {
    for (checksums, peer_a) in BOTH {
        client_case(checksums, peer_a);
    }
}

#[test]
fn client_syn_a_bit_follows_config() {
    for checksums in [false, true] {
        assert_eq!(client(checksums, false).syn_flags, CAP_H | a(checksums));
    }
}

/// A server that requires checksums while we do not: we use them, and stay MPTCP (spec G1;
/// the old A=1 → fallback rule is gone).
#[test]
fn client_honours_synack_a() {
    client_case(false, true);
}

#[test]
fn client_off_off_no_checksum() {
    client_case(false, false);
}

// ---------------------------------------------------------------------------------------------
// Two endpoints: a client and a listener on `SERVER`.

struct Pair {
    c: Endpoint<ChaCha20Rng>,
    s: Endpoint<ChaCha20Rng>,
    h: ConnectionHandle,
    now: Instant,
    /// Every packet the client sent, parsed.
    client_sent: Vec<Segment<'static>>,
}

impl Pair {
    fn new(client_checksums: bool, server_checksums: bool) -> Self {
        let mut s = Endpoint::new(ChaCha20Rng::seed_from_u64(43));
        let cfg = ListenConfig {
            connection: checksums_cfg(server_checksums),
            ..Default::default()
        };
        s.listen(SERVER.parse().unwrap(), cfg).unwrap();
        let mut c = Endpoint::new(ChaCha20Rng::seed_from_u64(42));
        let h = c
            .connect_mptcp(
                t(0),
                "10.0.0.1".parse().unwrap(),
                SERVER.parse().unwrap(),
                checksums_cfg(client_checksums),
            )
            .unwrap();
        let mut p = Pair {
            c,
            s,
            h,
            now: t(0),
            client_sent: Vec::new(),
        };
        p.pump();
        assert_eq!(
            p.c.poll_event(),
            Some((h, Event::Connected { mptcp: true }))
        );
        assert_eq!(
            p.s.poll_event(),
            Some((ConnectionHandle(0), Event::Accepted { mptcp: true }))
        );
        p
    }
    /// Shuttles packets both ways, following timers, until nothing is due within 1 s.
    fn pump(&mut self) {
        let mut buf = [0; 1500];
        loop {
            let mut moved = false;
            while let Some(n) = self.c.poll_transmit(self.now, &mut buf) {
                self.client_sent
                    .push(packet::parse(buf[..n].to_vec().leak()).unwrap());
                self.s.handle_packet(self.now, &buf[..n]);
                moved = true;
            }
            while let Some(n) = self.s.poll_transmit(self.now, &mut buf) {
                self.c.handle_packet(self.now, &buf[..n]);
                moved = true;
            }
            if moved {
                continue;
            }
            let next = [self.c.poll_timeout(), self.s.poll_timeout()];
            let Some(at) = next.into_iter().flatten().min() else {
                return;
            };
            if at > self.now + Duration::from_secs(1) {
                return;
            }
            self.now = self.now.max(at);
            self.c.handle_timeout(self.now);
            self.s.handle_timeout(self.now);
        }
    }
    fn server_read(&mut self) -> Vec<u8> {
        let mut all = Vec::new();
        let mut buf = [0; 65536];
        let conn = self.s.connection(ConnectionHandle(0)).unwrap();
        while let Ok(n) = conn.read(&mut buf) {
            if n == 0 {
                break;
            }
            all.extend_from_slice(&buf[..n]);
        }
        all
    }
}

fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 7 + i / 251) as u8).collect()
}

/// Our checksums off, a server that requires them (as Linux with `checksum_enabled=1`, whose
/// SYN/ACK A follows its own setting): we use checksums and 10 kB arrive (Review Focus 4).
#[test]
fn client_off_linux_style_on_stays_mptcp() {
    let mut p = Pair::new(false, true);
    assert!(negotiation(&p.c, p.h).csum);
    assert!(negotiation(&p.s, ConnectionHandle(0)).csum);
    let data = pattern(10_000);
    let mut at = 0;
    while at < data.len() {
        at += p.c.connection(p.h).unwrap().write(&data[at..]).unwrap();
        p.pump();
    }
    assert_eq!(p.server_read(), data);
    assert_eq!(negotiation(&p.c, p.h).state, State::Confirmed);
}

/// Every DSS mapping on the wire verifies over the octets of the whole mapping, collected from
/// every segment that carries it; at least one mapping spans segments (spec G4, G5).
#[test]
fn tx_mapping_checksum_verifies() {
    let mut p = Pair::new(true, false);
    let iss = p.client_sent[0].seq;
    let data = pattern(3000);
    assert_eq!(p.c.connection(p.h).unwrap().write(&data), Ok(3000));
    p.pump();
    assert_eq!(p.server_read(), data);
    // Each mapping, its octets, and how many segments carried it.
    let mut maps: Vec<(Mapping, Vec<Option<u8>>, usize)> = Vec::new();
    for seg in p.client_sent.iter().filter(|s| !s.payload.is_empty()) {
        let Some((m, fin)) = seg_mapping(seg) else {
            continue;
        };
        let i = match maps.iter().position(|(k, ..)| *k == m) {
            Some(i) => i,
            None => {
                let len = usize::from(m.data_len) - usize::from(fin);
                maps.push((m, vec![None; len], 0));
                maps.len() - 1
            }
        };
        let off = seg.seq.0.wrapping_sub(iss.0).wrapping_sub(m.ssn) as usize;
        let (_, bytes, segs) = &mut maps[i];
        bytes[off..off + seg.payload.len()]
            .iter_mut()
            .zip(seg.payload)
            .for_each(|(b, v)| *b = Some(*v));
        *segs += 1;
    }
    assert!(!maps.is_empty());
    assert!(
        maps.iter().any(|(.., segs)| *segs > 1),
        "a mapping spans segments"
    );
    for (m, bytes, _) in &maps {
        let bytes: Vec<u8> = bytes.iter().map(|b| b.expect("whole mapping")).collect();
        let ck = m.checksum.expect("checksum present");
        assert!(dss_checksum_ok(dsn64(m), m.ssn, m.data_len, &[&bytes], ck));
    }
}

/// Half a mapping is TCP-acknowledged, then an RTO: the retransmission carries the original
/// mapping and checksum, unchanged (spec G5).
#[test]
fn tx_checksum_survives_partial_ack_and_retransmit() {
    let mut c = client(true, false);
    c.confirm();
    c.ep.connection(c.h).unwrap().set_nodelay(true);
    let data = pattern(8000);
    c.ep.connection(c.h).unwrap().write(&data).unwrap();
    let sent = c.sent(t(3));
    let with_data: Vec<_> = sent.iter().filter(|s| !s.payload.is_empty()).collect();
    assert!(with_data.len() >= 2);
    let (m, _) = seg_mapping(with_data[0]).unwrap();
    assert_eq!(
        seg_mapping(with_data[1]).unwrap().0,
        m,
        "one mapping, two segments"
    );
    assert!(m.checksum.is_some());
    // The peer acknowledges the first segment only.
    let ack = with_data[0]
        .seq
        .wrapping_add(with_data[0].payload.len() as u32);
    let (syn, head) = (c.syn.clone(), una(&c.ep, c.h));
    peer_ack(&mut c.ep, &syn, t(4), ack, head, 1000);
    let rto = c.ep.poll_timeout().unwrap();
    c.ep.handle_timeout(rto);
    let again = c.sent(rto);
    let again = again.iter().find(|s| !s.payload.is_empty()).unwrap();
    assert_eq!(again.seq, ack, "the retransmission");
    assert_eq!(seg_mapping(again).unwrap().0, m);
}

/// A DATA_FIN folded into the last mapping counts in its Data-Level Length, and the checksum
/// covers that length (spec G4).
#[test]
fn tx_data_fin_folded_checksum() {
    let mut c = client(true, false);
    c.confirm();
    let dsn = una(&c.ep, c.h);
    c.ep.connection(c.h).unwrap().write(b"hello").unwrap();
    c.ep.connection(c.h).unwrap().close();
    let sent = c.sent(t(3));
    let seg = sent.iter().find(|s| s.payload == b"hello").unwrap();
    let (m, fin) = seg_mapping(seg).unwrap();
    assert!(fin);
    assert_eq!((dsn64(&m), m.data_len), (dsn, 6));
    assert_eq!(m.checksum, Some(dss_checksum(dsn, m.ssn, 6, &[b"hello"])));
}

/// A DATA_FIN-only mapping covers the pseudo-header only; an infinite mapping carries
/// checksum 0, the field present (spec G4).
#[test]
fn tx_data_fin_only_and_infinite_checksum() {
    let mut c = client(true, false);
    c.confirm();
    let fin_dsn = una(&c.ep, c.h);
    c.ep.connection(c.h).unwrap().close();
    let sent = c.sent(t(3));
    let (m, fin) = sent.iter().find_map(seg_mapping).unwrap();
    assert!(fin);
    assert_eq!((dsn64(&m), m.ssn, m.data_len), (fin_dsn, 0, 1));
    assert_eq!(m.checksum, Some(dss_checksum(fin_dsn, 0, 1, &[])));

    // The peer strips options: its TCP ACK of our data without a DATA_ACK falls back.
    let mut c = client(true, false);
    c.ep.connection(c.h).unwrap().write(b"first").unwrap();
    let sent = c.sent(t(2));
    let mut ack = peer_data(&c.syn, 5001, &[], &[]);
    ack.ack = sent[0].seq.wrapping_add(5);
    ack.wnd = 65535;
    input(&mut c.ep, &ack);
    assert_eq!(negotiation(&c.ep, c.h).state, State::FellBack);
    let sent = c.sent(t(3));
    let (m, _) = sent
        .iter()
        .find_map(seg_mapping)
        .expect("the infinite mapping");
    assert_eq!((m.data_len, m.checksum), (0, Some(0)));
}

// ---------------------------------------------------------------------------------------------
// Presence check (spec G3).

/// The MP_TCPRST of an RST among `sent`, if any.
fn rst_reason(sent: &[Segment]) -> Option<Vec<u8>> {
    let rst = sent.iter().find(|s| s.flags.contains(TcpFlags::RST))?;
    Some(mpc(rst.options).concat())
}

/// A DSS mapping, data, DATA_FIN-only or infinite, whose checksum presence differs from the
/// decision resets the subflow with MP_TCPRST 0x01; one that matches, or a DSS with only a
/// DATA_ACK, does not.
#[test]
fn rx_checksum_presence_mismatch_resets() {
    let tcprst = vec![30, 4, 0x80, 0x01];
    for csum in [true, false] {
        for wrong in [true, false] {
            // Checksum present exactly when it should not be (`wrong`).
            let ck = (csum != wrong).then_some(0);
            let forms: [(bool, u32, u16, &[u8]); 3] = [
                (false, 1, 5, b"hello"),
                (true, 0, 1, b""),
                (false, 1, 0, b"hello"),
            ];
            for (fin, ssn, len, payload) in forms {
                let mut c = client(csum, false);
                let dsn = key_token_idsn(PEER_KEY).1.wrapping_add(1);
                let ck = if len == 5 {
                    ck.map(|_| dss_checksum(dsn, 1, 5, &[b"hello"]))
                } else if fin {
                    ck.map(|_| dss_checksum(dsn, 0, 1, &[]))
                } else {
                    ck
                };
                let opt = dss_mapping(fin, ssn, dsn, len, ck);
                let sent = c.peer(&opt, payload);
                let want = wrong.then(|| tcprst.clone());
                assert_eq!(rst_reason(&sent), want, "csum {csum} {opt:?}");
            }
        }
        // A DATA_ACK alone has no checksum field.
        let mut c = client(csum, false);
        let head = una(&c.ep, c.h);
        let sent = c.peer(&data_ack(head), &[]);
        assert_eq!(rst_reason(&sent), None);
    }
}

// ---------------------------------------------------------------------------------------------
// Server role, against a scripted client (`Script`).

/// A listener on `SERVER` with `checksums`.
fn server(checksums: bool) -> Script {
    let mut s = Script::new(true);
    let l = s.ep.listeners.get_mut(&SERVER.parse().unwrap()).unwrap();
    l.cfg.connection.checksums = checksums;
    s
}

/// The client's MP_CAPABLE with data `data` and its checksum (length 24).
fn cap_csum(flags: u8, data: &[u8]) -> Vec<u8> {
    let len = data.len() as u16;
    encode(&MptcpOption::Capable(MpCapable {
        version: 1,
        flags,
        sender_key: Some(CLIENT_KEY),
        receiver_key: Some(SERVER_KEY),
        data_len: Some(len),
        checksum: Some(dss_checksum(client_idsn().wrapping_add(1), 1, len, &[data])),
    }))
}

/// The SYN/ACK has A = `csum`; a confirming option with A = `csum` (and, with data, length 24
/// exactly when `csum`) confirms; our first DSS mapping has its checksum exactly when `csum`.
#[test]
fn server_negotiation_matrix() {
    for (checksums, peer_a) in BOTH {
        let csum = checksums || peer_a;
        for with_data in [false, true] {
            let mut s = server(checksums);
            let synack = s.syn(&syn_cap(1, CAP_H | a(peer_a)));
            let want = cap(1, CAP_H | a(csum), Some(SERVER_KEY), None, None);
            assert_eq!(mptcp_of(&synack), [want]);
            assert_eq!(s.negotiation().csum, csum);
            let flags = CAP_H | a(csum);
            if with_data {
                let opt = if csum {
                    cap_csum(flags, b"hello")
                } else {
                    ack_cap(flags, Some(5))
                };
                s.send(65535, &opt, b"hello");
                assert_eq!(s.read_all(), b"hello");
            } else {
                s.send(65535, &ack_cap(flags, None), &[]);
            }
            assert_eq!(s.events(), [Event::Accepted { mptcp: true }]);
            assert_eq!(s.negotiation().state, State::Confirmed);
            s.conn().write(b"srv").unwrap();
            let out = s.output();
            let p = out.iter().find(|p| !mptcp_of(p).is_empty()).unwrap();
            let m = mptcp_of(p).iter().find_map(|o| dss(o)?.mapping).unwrap();
            let head = server_idsn().wrapping_add(1);
            assert_eq!((dsn64(&m), m.ssn, m.data_len), (head, 1, 3));
            assert_eq!(
                m.checksum,
                csum.then(|| dss_checksum(head, 1, 3, &[b"srv"]))
            );
        }
    }
}

#[test]
fn server_csum_from_syn_a() {
    let mut s = server(false);
    let synack = s.syn(&syn_cap(1, CAP_H | CAP_A));
    let want = cap(1, CAP_H | CAP_A, Some(SERVER_KEY), None, None);
    assert_eq!(mptcp_of(&synack), [want]);
}

#[test]
fn server_csum_from_config() {
    let mut s = server(true);
    let synack = s.syn(&syn_cap(1, CAP_H));
    let want = cap(1, CAP_H | CAP_A, Some(SERVER_KEY), None, None);
    assert_eq!(mptcp_of(&synack), [want]);
}

/// A confirming option whose A differs from the decision, or MP_CAPABLE-with-data of length 22
/// when `csum` or 24 when not, is invalid: the G2b fallback of M4a.
#[test]
fn server_third_ack_a_mismatch_falls_back() {
    for (checksums, peer_a) in BOTH {
        let csum = checksums || peer_a;
        let wrong = CAP_H | a(!csum);
        let cases: [(Vec<u8>, &[u8]); 3] = [
            (ack_cap(wrong, None), b""),
            (ack_cap(wrong, Some(5)), b"hello"),
            if csum {
                (ack_cap(CAP_H | CAP_A, Some(5)), b"hello")
            } else {
                (cap_csum(CAP_H, b"hello"), b"hello")
            },
        ];
        for (option, payload) in cases {
            let mut s = server(checksums);
            s.syn(&syn_cap(1, CAP_H | a(peer_a)));
            let out = s.send(65535, &option, payload);
            assert_eq!(s.events(), [Event::Accepted { mptcp: false }], "{option:?}");
            assert_eq!(s.negotiation().state, State::FellBack);
            assert!(s.ep.conns[&ConnectionHandle(0)].hooks.data.is_none());
            assert!(out.iter().all(|p| mptcp_of(p).is_empty()));
            assert_eq!(s.read_all(), payload);
            s.assert_plain_after();
        }
    }
}
