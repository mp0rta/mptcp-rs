//! DSS checksums (M4b spec G1–G9): the A-bit negotiation in both roles, the checksum on every
//! mapping we send, the presence check on every mapping we receive, and the hold buffer that
//! keeps a mapping's octets until its checksum verifies.
use super::super::server_tests::*;
use super::join_tests::{JOIN_IP, joined};
use super::*;
use crate::crypto::key_token_idsn;
use crate::wire::mptcp::{CAP_A, Dss, Mapping, dss_checksum, dss_checksum_ok};

const BOTH: [(bool, bool); 4] = [(false, false), (false, true), (true, false), (true, true)];

fn a(on: bool) -> u8 {
    if on { CAP_A } else { 0 }
}

pub(super) fn t(n: u64) -> Instant {
    Instant::from_nanos(n)
}

pub(super) fn checksums_cfg(checksums: bool) -> ConnectConfig {
    ConnectConfig {
        checksums,
        ..ConnectConfig::default()
    }
}

pub(super) fn negotiation(
    ep: &Endpoint<ChaCha20Rng>,
    h: ConnectionHandle,
) -> &crate::mptcp::Negotiation {
    ep.conns[&h].hooks.negotiation.as_ref().unwrap()
}

/// The DSS of an MPTCP option, if it is one.
fn dss(raw: &[u8]) -> Option<Dss> {
    match mptcp::parse(raw) {
        Ok(MptcpOption::Dss(d)) => Some(d),
        _ => None,
    }
}

pub(super) fn encode(o: &MptcpOption) -> Vec<u8> {
    let mut out = [0; 40];
    let n = mptcp::encode(o, &mut out).unwrap();
    out[..n].to_vec()
}

pub(super) fn dss_mapping(
    data_fin: bool,
    ssn: u32,
    dsn: u64,
    len: u16,
    checksum: Option<u16>,
) -> Vec<u8> {
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

pub(super) struct Client {
    pub(super) ep: Endpoint<ChaCha20Rng>,
    pub(super) h: ConnectionHandle,
    pub(super) syn: Segment<'static>,
    /// The flags of our SYN's MP_CAPABLE.
    syn_flags: u8,
    /// Our third ACK's MP_CAPABLE.
    third: Vec<u8>,
}

/// A client with `checksums` (Reno, no pacing) against a SYN/ACK whose MP_CAPABLE has
/// A=`peer_a`, MSS 1460 and WS 7. The third ACK is sent.
pub(super) fn client(checksums: bool, peer_a: bool) -> Client {
    client_cfg(checksums_cfg(checksums), peer_a)
}

/// `client` with the whole `ConnectConfig`.
fn client_cfg(cfg: ConnectConfig, peer_a: bool) -> Client {
    client_with(cfg, peer_a, false)
}

/// `client_cfg`, with SACK-Permitted in the SYN/ACK if `sack`.
pub(super) fn client_with(cfg: ConnectConfig, peer_a: bool, sack: bool) -> Client {
    let mut ep = Endpoint::new(ChaCha20Rng::seed_from_u64(41));
    ep.cc = Some(reno);
    let h = ep
        .connect_mptcp(
            t(0),
            "10.0.0.1".parse().unwrap(),
            "10.0.0.2:80".parse().unwrap(),
            cfg,
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
    if sack {
        let n = crate::wire::tcp_options::write_sack_permitted(&mut o);
        opts.extend_from_slice(&o[..n]);
    }
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
    pub(super) fn head(&self) -> u64 {
        let MptcpOption::Capable(c) = mptcp::parse(&self.third).unwrap() else {
            panic!()
        };
        key_token_idsn(c.sender_key.unwrap()).1.wrapping_add(1)
    }
    /// The peer's DATA_ACK at our send head opens 128,000 octets and confirms us.
    pub(super) fn confirm(&mut self) {
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
    pub(super) fn sent(&mut self, now: Instant) -> Vec<Segment<'static>> {
        let out = drain(&mut self.ep, now);
        out.into_iter()
            .map(|p| packet::parse(p.leak()).unwrap())
            .collect()
    }
    /// The peer's segment at its next sequence number with `options` and `payload`.
    pub(super) fn peer(&mut self, options: &[u8], payload: &[u8]) -> Vec<Segment<'static>> {
        self.peer_at(5001, options, payload)
    }
    /// The peer's segment at `seq`, and what we send in answer.
    pub(super) fn peer_at(
        &mut self,
        seq: u32,
        options: &[u8],
        payload: &[u8],
    ) -> Vec<Segment<'static>> {
        let syn = self.syn.clone();
        feed(&mut self.ep, &peer_data(&syn, seq, options, payload), t(2));
        self.sent(t(2))
    }
}

/// The mapping of the DSS a segment carries.
pub(super) fn seg_mapping(seg: &Segment) -> Option<(Mapping, bool)> {
    let d = mpc(seg.options).into_iter().find_map(dss)?;
    d.mapping.map(|m| (m, d.data_fin))
}

pub(super) fn dsn64(m: &Mapping) -> u64 {
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

pub(super) fn pattern(len: usize) -> Vec<u8> {
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
    // Each mapping, its octets, and the distinct sequence numbers that carried it (a
    // retransmission is not a second segment).
    let mut maps: Vec<(Mapping, Vec<Option<u8>>, Vec<u32>)> = Vec::new();
    for seg in p.client_sent.iter().filter(|s| !s.payload.is_empty()) {
        let Some((m, fin)) = seg_mapping(seg) else {
            continue;
        };
        let i = match maps.iter().position(|(k, ..)| *k == m) {
            Some(i) => i,
            None => {
                let len = usize::from(m.data_len) - usize::from(fin);
                maps.push((m, vec![None; len], Vec::new()));
                maps.len() - 1
            }
        };
        let off = seg.seq.0.wrapping_sub(iss.0).wrapping_sub(m.ssn) as usize;
        let (_, bytes, segs) = &mut maps[i];
        bytes[off..off + seg.payload.len()]
            .iter_mut()
            .zip(seg.payload)
            .for_each(|(b, v)| *b = Some(*v));
        if !segs.contains(&seg.seq.0) {
            segs.push(seg.seq.0);
        }
    }
    assert!(!maps.is_empty());
    assert!(
        maps.iter().any(|(.., segs)| segs.len() > 1),
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

/// RST options for a checksum failure at `dsn`: MP_FAIL(`dsn`), then MP_TCPRST 0x06, T=0.
pub(super) fn mp_fail_rst(dsn: u64) -> Vec<u8> {
    let mut want = vec![30, 12, 0x60, 0];
    want.extend(dsn.to_be_bytes());
    want.extend([30, 4, 0x80, 0x06]);
    want
}

/// The MPTCP options of an RST among `sent`, if any.
pub(super) fn rst_reason(sent: &[Segment]) -> Option<Vec<u8>> {
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
pub(super) fn server(checksums: bool) -> Script {
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

/// A confirming option whose A differs from the decision (each form, the length right or
/// wrong), or MP_CAPABLE-with-data of length 22 when `csum` or 24 when not, is invalid: the G2b
/// fallback of M4a.
#[test]
fn server_third_ack_a_mismatch_falls_back() {
    for (checksums, peer_a) in BOTH {
        let csum = checksums || peer_a;
        let wrong = CAP_H | a(!csum);
        let cases: [(Vec<u8>, &[u8]); 4] = [
            (ack_cap(wrong, None), b""),
            (ack_cap(wrong, Some(5)), b"hello"),
            // With `csum`, only A is wrong: the length 24 matches.
            (cap_csum(wrong, b"hello"), b"hello"),
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

/// After confirmation, an MP_CAPABLE-with-data is a mapping: one whose checksum presence
/// differs from the decision resets the subflow with MP_TCPRST 0x01, as a DSS would (spec G3);
/// one invalid otherwise (another key) resets without it.
#[test]
fn server_later_capable_presence_mismatch_tcprst() {
    let rst_of = |checksums: bool, option: &[u8]| {
        let mut s = server(checksums);
        s.syn(&syn_cap(1, CAP_H));
        s.send(65535, &ack_cap(CAP_H | a(checksums), None), &[]);
        assert_eq!(s.negotiation().state, State::Confirmed);
        let out = s.send(65535, option, b"hello");
        let rst = out
            .iter()
            .find(|p| packet::parse(p).unwrap().flags.contains(TcpFlags::RST));
        rst.map(|p| mptcp_of(p))
    };
    let tcprst = vec![vec![30, 4, 0x80, 0x01]];
    assert_eq!(
        rst_of(true, &ack_cap(CAP_H | CAP_A, Some(5))),
        Some(tcprst.clone())
    );
    assert_eq!(rst_of(false, &cap_csum(CAP_H, b"hello")), Some(tcprst));
    let other_key = cap(1, CAP_H, Some(CLIENT_KEY), Some(SERVER_KEY ^ 1), Some(5));
    assert_eq!(rst_of(false, &other_key), Some(vec![]));
}

// ---------------------------------------------------------------------------------------------
// Receiving: hold, verify, completion credit (spec G6–G9).

/// Feeds `seg` at `now` (payloads up to 4 KiB).
pub(super) fn feed(ep: &mut Endpoint<ChaCha20Rng>, seg: &Segment, now: Instant) {
    let mut wire = [0; 4200];
    let n = packet::build(seg, 0, &mut wire).unwrap();
    ep.handle_packet(now, &wire[..n]);
}

/// The peer's first DSN.
pub(super) fn peer_head() -> u64 {
    key_token_idsn(PEER_KEY).1.wrapping_add(1)
}

/// A DSS mapping of `data` (plus a DATA_FIN if `fin`) with its checksum.
pub(super) fn csum_mapping(ssn: u32, dsn: u64, data: &[u8], fin: bool) -> Vec<u8> {
    let len = (data.len() + usize::from(fin)) as u16;
    dss_mapping(
        fin,
        ssn,
        dsn,
        len,
        Some(dss_checksum(dsn, ssn, len, &[data])),
    )
}

/// The same mapping with a checksum that does not verify.
pub(super) fn bad_mapping(ssn: u32, dsn: u64, data: &[u8], fin: bool) -> Vec<u8> {
    let len = (data.len() + usize::from(fin)) as u16;
    let ck = dss_checksum(dsn, ssn, len, &[data]) ^ 1;
    dss_mapping(fin, ssn, dsn, len, Some(ck))
}

pub(super) fn recv(
    ep: &Endpoint<ChaCha20Rng>,
    h: ConnectionHandle,
) -> &crate::mptcp::data::RecvAssembler {
    &ep.conns[&h].hooks.data.as_ref().unwrap().recv
}

pub(super) fn held(ep: &Endpoint<ChaCha20Rng>, h: ConnectionHandle) -> usize {
    ep.conns[&h].subflows.iter().map(|s| s.mp.hold.held()).sum()
}

/// The DATA_ACK a segment carries.
pub(super) fn data_ack_of(seg: &Segment) -> Option<u64> {
    match mpc(seg.options).into_iter().find_map(dss)?.data_ack? {
        mptcp::DataAck::Ack64(a) => Some(a),
        mptcp::DataAck::Ack32(_) => None,
    }
}

/// Our window scale, from our SYN.
fn our_scale(syn: &Segment) -> u8 {
    walk(syn.options)
        .find_map(|o| match o {
            Ok(TcpOpt::WindowScale(s)) => Some(s),
            _ => None,
        })
        .unwrap()
}

/// Every octet readable now.
pub(super) fn read_now(ep: &mut Endpoint<ChaCha20Rng>, h: ConnectionHandle) -> Vec<u8> {
    let mut all = Vec::new();
    let mut buf = [0; 8192];
    while let Ok(n) = ep.connection(h).unwrap().read(&mut buf) {
        if n == 0 {
            break;
        }
        all.extend_from_slice(&buf[..n]);
    }
    all
}

/// A confirmed client with checksums (1 MiB buffer) and a second subflow joined: (endpoint,
/// handle, initial SYN, join SYN, the peer's first DSN). The peer's ISN is 5000 on both.
pub(super) fn two_subflows() -> (
    Endpoint<ChaCha20Rng>,
    ConnectionHandle,
    Segment<'static>,
    Segment<'static>,
    u64,
) {
    two_subflows_with(ConnectConfig {
        recv_buffer: 1 << 20,
        ..checksums_cfg(true)
    })
}

/// `two_subflows` with the whole `ConnectConfig`.
fn two_subflows_with(
    cfg: ConnectConfig,
) -> (
    Endpoint<ChaCha20Rng>,
    ConnectionHandle,
    Segment<'static>,
    Segment<'static>,
    u64,
) {
    let (mut ep, h, syn, dsn) = connected_cfg("10.0.0.1", "10.0.0.2:80", cfg, None, false);
    open_window(&mut ep, &syn, h);
    assert!(negotiation(&ep, h).csum);
    let (_, jsyn) = joined(&mut ep, h, t(10_000_000), JOIN_IP, 1500, 7);
    (ep, h, syn, jsyn, dsn)
}

/// With `csum`, octets of a mapping are neither readable nor DATA_ACKed until the whole
/// mapping verifies; held octets are TCP-ACKed (spec G6, A3).
#[test]
fn rx_no_read_no_data_ack_before_verify() {
    let mut c = client(true, false);
    c.confirm();
    let dsn = peer_head();
    let data = pattern(3000);
    let opt = csum_mapping(1, dsn, &data, false);
    let sent = c.peer_at(5001, &opt, &data[..1460]);
    let ack = sent.last().expect("an ACK");
    assert_eq!(ack.ack, SeqNum(5001 + 1460), "held octets are TCP-ACKed");
    assert_eq!(data_ack_of(ack), Some(dsn));
    assert_eq!(read_now(&mut c.ep, c.h), b"");
    let sent = c.peer_at(5001 + 1460, &opt, &data[1460..]);
    assert_eq!(data_ack_of(sent.last().unwrap()), Some(dsn + 3000));
    assert_eq!(read_now(&mut c.ep, c.h), data);
    assert_eq!(held(&c.ep, c.h), 0);
}

/// Subflow 0 delivers DSN [0, 200); subflow 1 then sends a mapping [100, 300). It verifies
/// over all its octets and adds only [200, 300) (spec G7: coverage is not delivery).
#[test]
fn rx_mapping_prefix_delivered_elsewhere_verifies() {
    let (mut ep, h, syn, jsyn, dsn) = two_subflows();
    let now = t(20_000_000);
    let data = pattern(300);
    let opt = csum_mapping(1, dsn, &data[..200], false);
    feed(&mut ep, &peer_data(&syn, 5001, &opt, &data[..200]), now);
    assert_eq!(recv(&ep, h).next, dsn + 200);
    let opt = csum_mapping(1, dsn + 100, &data[100..], false);
    feed(&mut ep, &peer_data(&jsyn, 5001, &opt, &data[100..]), now);
    assert_eq!(recv(&ep, h).next, dsn + 300);
    assert_eq!(read_now(&mut ep, h), data);
    assert_eq!(held(&ep, h), 0);
}

/// On the one subflow, with no join completed and no connection-level retransmission sent, a
/// mapping that fails its checksum delivers nothing and draws no RST: we wait, with MP_FAIL on
/// our ACK (M4b spec G11, first bullet).
#[test]
fn rx_bad_checksum_single_subflow_waits() {
    let mut c = client(true, false);
    c.confirm();
    let dsn = peer_head();
    let sent = c.peer(&bad_mapping(1, dsn, b"hello", false), b"hello");
    assert_eq!(rst_reason(&sent), None);
    let fail = encode(&MptcpOption::Fail { dsn });
    assert!(mpc(sent.last().unwrap().options).contains(&&fail[..]));
    assert_eq!(recv(&c.ep, c.h).next, dsn);
    assert!(matches!(
        c.ep.conns[&c.h].hooks.mp_fail,
        crate::mptcp::MpFail::Waiting { .. }
    ));
}

/// Once we have sent a reinjection, the same failure resets the subflow with MP_FAIL and
/// MP_TCPRST 0x06 and delivers nothing (spec G10, G11 second bullet).
#[test]
fn rx_bad_checksum_after_reinjection_resets() {
    let mut c = client(true, false);
    c.confirm();
    c.ep.connection(c.h).unwrap().write(b"lost").unwrap();
    let sent = c.sent(t(2));
    let first = sent.iter().find(|s| s.payload == b"lost").unwrap();
    let syn = c.syn.clone();
    let head = una(&c.ep, c.h);
    let opts = data_ack(head);
    let mut ack = peer_data(&syn, 5001, &opts, &[]);
    ack.ack = first.seq.wrapping_add(4);
    feed(&mut c.ep, &ack, t(2));
    let deadline = c.ep.poll_timeout().expect("connection recovery timer");
    c.ep.handle_timeout(deadline);
    let retry = c.sent(deadline);
    assert!(retry.iter().any(|s| s.payload == b"lost"));
    assert!(!c.ep.conns[&c.h].hooks.infinite_ok);
    let dsn = peer_head();
    let opts = bad_mapping(1, dsn, b"hello", false);
    let seg = peer_data(&syn, 5001, &opts, b"hello");
    feed(&mut c.ep, &seg, deadline);
    assert_eq!(rst_reason(&c.sent(deadline)), Some(mp_fail_rst(dsn)));
    assert_eq!(recv(&c.ep, c.h).next, dsn);
}

/// Subflow 1 holds the first half of a mapping while subflow 0 delivers past its middle; the
/// held mapping still verifies once complete and adds only its new suffix.
#[test]
fn rx_recv_next_passes_partly_held_mapping() {
    let (mut ep, h, syn, jsyn, dsn) = two_subflows();
    let now = t(20_000_000);
    let data = pattern(2000);
    let whole = csum_mapping(1, dsn, &data, false);
    feed(&mut ep, &peer_data(&jsyn, 5001, &whole, &data[..1000]), now);
    assert_eq!((recv(&ep, h).next, held(&ep, h)), (dsn, 1000));
    let opt = csum_mapping(1, dsn, &data[..1500], false);
    feed(&mut ep, &peer_data(&syn, 5001, &opt, &data[..1500]), now);
    assert_eq!(recv(&ep, h).next, dsn + 1500);
    feed(&mut ep, &peer_data(&jsyn, 6001, &whole, &data[1000..]), now);
    assert_eq!(recv(&ep, h).next, dsn + 2000);
    assert_eq!(read_now(&mut ep, h), data);
    assert_eq!(held(&ep, h), 0);
}

/// Subflow 0 delivers through DSN N; subflow 1 sends a duplicate mapping ending at N with a
/// folded DATA_FIN. With a wrong checksum the DATA_FIN is not applied (the failure path
/// runs); with a correct one it is.
#[test]
fn rx_corrupt_folded_fin_after_other_subflow_delivered() {
    for good in [false, true] {
        let (mut ep, h, syn, jsyn, dsn) = two_subflows();
        let now = t(20_000_000);
        let data = pattern(500);
        let opt = csum_mapping(1, dsn, &data, false);
        feed(&mut ep, &peer_data(&syn, 5001, &opt, &data), now);
        assert_eq!(recv(&ep, h).next, dsn + 500);
        let opt = if good {
            csum_mapping(1, dsn, &data, true)
        } else {
            bad_mapping(1, dsn, &data, true)
        };
        feed(&mut ep, &peer_data(&jsyn, 5001, &opt, &data), now);
        assert_eq!(recv(&ep, h).has_fin(), good);
        let out: Vec<_> = drain(&mut ep, now)
            .into_iter()
            .map(|p| packet::parse(p.leak()).unwrap())
            .filter(|s| s.src == jsyn.src)
            .collect();
        let want = (!good).then(|| mp_fail_rst(dsn));
        assert_eq!(rst_reason(&out), want);
    }
}

/// While 3000 octets are held, new offers count `recv_buffer − 3000` free (spec G7, memory).
#[test]
fn rx_free_subtracts_held() {
    let cfg = ConnectConfig {
        recv_buffer: 8000,
        ..checksums_cfg(true)
    };
    let mut c = client_cfg(cfg, false);
    c.confirm();
    let scale = our_scale(&c.syn);
    let dsn = peer_head();
    // Mapping A, 4000 octets, delivered and read: the edge offered is still dsn + 8000.
    let a = pattern(4000);
    c.peer_at(5001, &csum_mapping(1, dsn, &a, false), &a);
    assert_eq!(read_now(&mut c.ep, c.h), a);
    // Mapping B, 4000 octets: 3000 of them held.
    let b = pattern(4000);
    let opt = csum_mapping(4001, dsn + 4000, &b, false);
    let sent = c.peer_at(9001, &opt, &b[..3000]);
    assert_eq!(held(&c.ep, c.h), 3000);
    assert_eq!(recv(&c.ep, c.h).free(), 8000 - 3000);
    // 5000 free and 4000 still offered from DATA_ACK dsn + 4000: below the SWS threshold, so
    // the edge stays (not dsn + 12000, as 8000 free would give).
    let ack = sent.last().unwrap();
    let edge = data_ack_of(ack).unwrap() + (u64::from(ack.wnd) << scale);
    assert_eq!(edge, dsn + 8000);
}

/// A DATA_FIN-only mapping whose checksum fails changes nothing (no RST either) unless its
/// DSN is `recv.next`: then it is taken, as some Linux kernels send it with an uninitialised
/// checksum. A correct one sets the DATA_FIN at any in-window DSN (spec G8).
#[test]
fn rx_data_fin_only_bad_checksum_ignored() {
    let head = peer_head();
    let fin_only = |dsn: u64, good: bool| {
        let ck = dss_checksum(dsn, 0, 1, &[]);
        dss_mapping(true, 0, dsn, 1, Some(if good { ck } else { ck ^ 1 }))
    };
    // Bad checksum past `recv.next`: ignored.
    let mut c = client(true, false);
    c.confirm();
    let sent = c.peer(&fin_only(head + 5, false), &[]);
    assert!(!recv(&c.ep, c.h).has_fin());
    assert_eq!(rst_reason(&sent), None);
    // Bad checksum at `recv.next`, after all the data: the DATA_FIN applies.
    let mut c = client(true, false);
    c.confirm();
    c.peer_at(5001, &csum_mapping(1, head, b"hello", false), b"hello");
    let sent = c.peer_at(5006, &fin_only(head + 5, false), &[]);
    assert!(recv(&c.ep, c.h).has_fin());
    assert_eq!(rst_reason(&sent), None);
    assert_eq!(data_ack_of(sent.last().unwrap()), Some(head + 6));
    // A correct checksum, past `recv.next`: the DATA_FIN applies, as before.
    let mut c = client(true, false);
    c.confirm();
    c.peer(&fin_only(head + 5, true), &[]);
    assert!(recv(&c.ep, c.h).has_fin());
}

/// Linux folds a late DATA_FIN into the final mapping it already declared
/// (`mptcp_write_data_fin`): the mapping's first segment says DLL n, a DATA_FIN-only DSS
/// follows, and the rest comes with the same DSN and SSN but DLL n + 1, the DATA_FIN flag and
/// a checksum over n + 1. Linux's receiver takes it as the same mapping
/// (`get_mapping_status`); so do we: it verifies, the stream ends, no reset. A retransmitted
/// first segment, with the mapping as first declared, changes nothing. (Linux interop,
/// csum-fail2 c2s: the reset killed the only subflow left.)
#[test]
fn rx_late_data_fin_folded_into_declared_mapping() {
    let mut c = client(true, false);
    c.confirm();
    let dsn = peer_head();
    let data = pattern(1783);
    let first = c.peer_at(5001, &csum_mapping(1, dsn, &data, false), &data[..1436]);
    let ck = dss_checksum(dsn + 1783, 0, 1, &[]);
    let fin = dss_mapping(true, 0, dsn + 1783, 1, Some(ck));
    let fin_only = c.peer_at(5001 + 1436, &fin, &[]);
    let rest = c.peer_at(
        5001 + 1436,
        &csum_mapping(1, dsn, &data, true),
        &data[1436..],
    );
    let again = c.peer_at(5001, &csum_mapping(1, dsn, &data, false), &data[..1436]);
    for sent in [&first, &fin_only, &rest, &again] {
        assert_eq!(rst_reason(sent), None);
    }
    assert_eq!(data_ack_of(rest.last().unwrap()), Some(dsn + 1784));
    assert_eq!(read_now(&mut c.ep, c.h), data);
    assert!(recv(&c.ep, c.h).has_fin());
}

/// Review Focus 2: a 4 KiB receive buffer against one 65,535-octet mapping sent within the
/// edge we offer. Completion credit opens the edge to the mapping's end; every octet arrives
/// and verifies, without a stall (spec G7).
#[test]
fn rx_small_buffer_large_mapping_completes() {
    let cfg = ConnectConfig {
        recv_buffer: 4096,
        ..checksums_cfg(true)
    };
    let mut c = client_cfg(cfg, false);
    c.confirm();
    let scale = our_scale(&c.syn);
    let dsn = peer_head();
    let data = pattern(65_535);
    let opt = csum_mapping(1, dsn, &data, false);
    let mut edge = dsn + 4096;
    let mut at = 0;
    while at < data.len() {
        let n = (data.len() - at).min(1460);
        assert!(dsn + (at + n) as u64 <= edge, "within the offered edge");
        let sent = c.peer_at(5001 + at as u32, &opt, &data[at..at + n]);
        for s in &sent {
            let offered = data_ack_of(s).unwrap() + (u64::from(s.wnd) << scale);
            edge = edge.max(offered);
        }
        if at == 0 {
            assert_eq!(edge, dsn + 65_535, "credit to the mapping's end");
        }
        at += n;
    }
    assert_eq!(read_now(&mut c.ep, c.h), data);
}

/// Review Focus 5: checksums off on both ends: the first segment of a two-segment mapping is
/// readable at once; nothing is ever held (spec G9).
#[test]
fn rx_csum_off_delivers_per_segment() {
    let mut c = client(false, false);
    c.confirm();
    assert!(!negotiation(&c.ep, c.h).csum);
    let dsn = peer_head();
    let data = pattern(3000);
    let opt = dss_mapping(false, 1, dsn, 3000, None);
    c.peer_at(5001, &opt, &data[..1460]);
    assert_eq!(held(&c.ep, c.h), 0);
    assert_eq!(read_now(&mut c.ep, c.h), &data[..1460]);
    c.peer_at(5001 + 1460, &opt, &data[1460..]);
    assert_eq!(held(&c.ep, c.h), 0);
    assert_eq!(read_now(&mut c.ep, c.h), &data[1460..]);
}

/// Checksums off on both ends: input never sums, prunes or flags anything for the hold buffers
/// (spec G9, A1). Octets planted in one by hand stay out of `free`.
#[test]
fn rx_csum_off_no_hold_accounting() {
    use crate::mptcp::hold::HoldMap;
    let mut c = client(false, false);
    c.confirm();
    let free = recv(&c.ep, c.h).free();
    let hold = &mut c.ep.conns.get_mut(&c.h).unwrap().subflows[0].mp.hold;
    let map = HoldMap {
        ssn: 1,
        dsn: 0,
        len: 100,
        data_fin: false,
        checksum: 0,
    };
    assert!(hold.install(map));
    hold.insert(1, &[0; 100], 1, 1 << 40, usize::MAX);
    assert_eq!(hold.held(), 100);
    c.peer(&[], &[]);
    assert_eq!(recv(&c.ep, c.h).free(), free);
    // Nor does a mapping or a receipt touch the offset flag or the hold buffer.
    let opt = dss_mapping(false, 1, peer_head() + 1000, 200, None);
    c.peer(&opt, &[0; 200]);
    let sf = &c.ep.conns[&c.h].subflows[0].mp;
    assert_eq!((sf.other_offset, sf.hold.maps().count()), (false, 1));
}

/// Each in-order octet arrives unmapped with a DSS mapping of the octet before it: the stale
/// mappings are pruned as the receipt passes them, so their metadata stays bounded (spec G7).
#[test]
fn rx_stale_mappings_stay_bounded() {
    let mut c = client(true, false);
    c.confirm();
    let dsn = peer_head();
    let data = pattern(500);
    c.peer_at(5001, &csum_mapping(1, dsn, &data[..1], false), &data[..1]);
    for k in 1..data.len() {
        let opt = csum_mapping(k as u32, dsn + k as u64 - 1, &data[k - 1..k], false);
        c.peer_at(5001 + k as u32, &opt, &data[k..k + 1]);
    }
    let sf = &c.ep.conns[&c.h].subflows[0];
    assert!(!sf.mp.reset);
    assert!(
        sf.mp.hold.maps().count() <= 1,
        "{}",
        sf.mp.hold.maps().count()
    );
}

/// Pure ACKs declaring one-octet subranges of a verified mapping. Below the frontier they are
/// not kept at all. Above it (the mapping verified over a hole) they count against the hold's
/// mapping cap, past which the subflow is reset, as for `RxMaps` (spec G7).
#[test]
fn rx_stale_mappings_on_pure_acks_stay_bounded() {
    let dsn = peer_head();
    let data = pattern(2000);
    let count = |c: &Client| c.ep.conns[&c.h].subflows[0].mp.hold.maps().count();
    // In order: the frontier is past the mapping.
    let mut c = client(true, false);
    c.confirm();
    c.peer_at(5001, &csum_mapping(1, dsn, &data, false), &data);
    for k in 0..data.len() {
        let opt = csum_mapping(1 + k as u32, dsn + k as u64, &data[k..k + 1], false);
        c.peer_at(7001, &opt, &[]);
    }
    assert_eq!(count(&c), 0);
    assert!(!c.ep.conns[&c.h].subflows[0].mp.reset);
    // Out of order, over a hole at SSN 1..11.
    let mut c = client(true, false);
    c.confirm();
    c.peer_at(5011, &csum_mapping(11, dsn + 10, &data, false), &data);
    assert_eq!(count(&c), 0, "verified");
    let mut rst = None;
    for k in 0..1100 {
        let opt = csum_mapping(11 + k as u32, dsn + 10 + k as u64, &data[k..k + 1], false);
        let sent = c.peer_at(5001, &opt, &[]);
        rst = rst.or(rst_reason(&sent));
        assert!(count(&c) <= 1024, "{}", count(&c));
    }
    assert!(rst.is_some(), "the subflow is reset past the cap");
}

// ---------------------------------------------------------------------------------------------
// Replay of held octets on fallback (spec G15).

/// The peer's infinite mapping, retroactive to its first octet (checksum field present, 0).
pub(super) fn peer_infinite() -> Vec<u8> {
    dss_mapping(false, 1, peer_head(), 0, Some(0))
}

/// With `csum`, the first 1460 octets of a 3000-octet mapping are held when the peer's infinite
/// mapping arrives with the plain octets after them: all 4000 are readable, in order.
#[test]
fn replay_partial_reverse_mapping_on_peer_infinite_mapping() {
    let mut c = client(true, false);
    c.confirm();
    let dsn = peer_head();
    let data = pattern(4000);
    c.peer_at(
        5001,
        &csum_mapping(1, dsn, &data[..3000], false),
        &data[..1460],
    );
    assert_eq!(held(&c.ep, c.h), 1460);
    c.peer_at(5001 + 1460, &peer_infinite(), &data[1460..]);
    assert_eq!(negotiation(&c.ep, c.h).state, State::FellBack);
    assert_eq!(read_now(&mut c.ep, c.h), data);
    assert_eq!(held(&c.ep, c.h), 0);
}

/// With `csum`, 1460 octets of a mapping are held when the DATA_ACK-stripping fallback fires:
/// they are readable at once, and the rest follows as plain TCP.
#[test]
fn replay_on_stripping_fallback() {
    let mut c = client(true, false);
    c.confirm();
    let dsn = peer_head();
    let data = pattern(3000);
    c.peer_at(5001, &csum_mapping(1, dsn, &data, false), &data[..1460]);
    assert_eq!(held(&c.ep, c.h), 1460);
    c.ep.connection(c.h).unwrap().write(b"first").unwrap();
    let sent = c.sent(t(2));
    let first = sent.iter().find(|s| s.payload == b"first").unwrap();
    // The peer ACKs it without any MPTCP option.
    let syn = c.syn.clone();
    let mut ack = peer_data(&syn, 5001 + 1460, &[], &[]);
    ack.ack = first.seq.wrapping_add(5);
    feed(&mut c.ep, &ack, t(2));
    assert_eq!(negotiation(&c.ep, c.h).state, State::FellBack);
    assert_eq!(read_now(&mut c.ep, c.h), &data[..1460]);
    c.peer_at(5001 + 1460, &[], &data[1460..]);
    assert_eq!(read_now(&mut c.ep, c.h), &data[1460..]);
}

/// A 4096-octet receive buffer full of unread octets when the fallback replays 3000 held ones:
/// they stay owned by the connection, and one read makes them readable with no further packet.
/// (4095 unread: a mapping is held only if it starts below the offered edge, spec G7.)
#[test]
fn replay_full_app_buffer_drains_on_read() {
    let cfg = ConnectConfig {
        recv_buffer: 4096,
        ..checksums_cfg(true)
    };
    let mut c = client_cfg(cfg, false);
    c.confirm();
    let dsn = peer_head();
    let a = pattern(4095);
    let opt = csum_mapping(1, dsn, &a, false);
    for at in (0..a.len()).step_by(1460) {
        let end = (at + 1460).min(a.len());
        c.peer_at(5001 + at as u32, &opt, &a[at..end]);
    }
    assert_eq!(recv(&c.ep, c.h).free(), 1);
    // Mapping B starts below the edge, so completion credit opens the edge to its end.
    let b = pattern(3001);
    let opt = csum_mapping(4096, dsn + 4095, &b, false);
    for (from, to) in [(0, 1), (1, 1461), (1461, 3000)] {
        c.peer_at(5001 + 4095 + from as u32, &opt, &b[from..to]);
    }
    assert_eq!(held(&c.ep, c.h), 3000);
    c.peer_at(5001 + 7095, &peer_infinite(), &[]);
    assert_eq!(negotiation(&c.ep, c.h).state, State::FellBack);
    assert_eq!(held(&c.ep, c.h), 0);
    let mut out = [0; 4095];
    assert_eq!(c.ep.connection(c.h).unwrap().read(&mut out), Ok(4095));
    assert_eq!(&out[..], &a[..]);
    assert_eq!(read_now(&mut c.ep, c.h), &b[..3000]);
}

/// Subflow 0 takes 63 of the 64 assembler ranges; subflow 1 is admitted to hold 5 octets past
/// them, then subflow 0 takes the 64th range. The peer's infinite mapping arrives on subflow
/// 1: the replayed run, a 65th range, is stored anyway, as it is TCP-ACKed and the peer never
/// resends it (spec G15): the octets move from the hold to the assembler, `free` unchanged.
#[test]
fn replay_past_range_cap_after_join() {
    let (mut ep, h, syn, jsyn, dsn) = two_subflows();
    let now = t(20_000_000);
    let island = |ep: &mut Endpoint<ChaCha20Rng>, k: u32| {
        let opt = csum_mapping(1 + k, dsn + 10 + 2 * u64::from(k), b"x", false);
        feed(ep, &peer_data(&syn, 5001 + k, &opt, b"x"), now);
    };
    for k in 0..63 {
        island(&mut ep, k);
    }
    let data = pattern(10);
    let opt = csum_mapping(1, dsn + 1000, &data, false);
    feed(&mut ep, &peer_data(&jsyn, 5001, &opt, &data[..5]), now);
    assert_eq!(held(&ep, h), 5);
    island(&mut ep, 63);
    let free = recv(&ep, h).free();
    let inf = dss_mapping(false, 6, dsn + 1005, 0, Some(0));
    feed(&mut ep, &peer_data(&jsyn, 5006, &inf, &[]), now);
    assert_eq!(negotiation(&ep, h).state, State::FellBack);
    assert_eq!((held(&ep, h), recv(&ep, h).free()), (0, free));
}

/// As above, but subflow 1's mapping then completes and verifies after subflow 0 took the 64th
/// range: the range cap refuses it, so it is dropped as without checksums (not DATA_ACKed),
/// and the stream is whole once it is sent again past the filled gaps (spec G7, design v3).
#[test]
fn range_refused_completion_after_race_dropped() {
    let (mut ep, h, syn, jsyn, dsn) = two_subflows();
    let now = t(20_000_000);
    let data = pattern(1010);
    for k in 0..63u32 {
        let i = 10 + 2 * k as usize;
        send_mapping(&mut ep, &syn, 1 + k, dsn + i as u64, &data[i..i + 1]);
    }
    let opt = csum_mapping(1, dsn + 1000, &data[1000..], false);
    feed(
        &mut ep,
        &peer_data(&jsyn, 5001, &opt, &data[1000..1005]),
        now,
    );
    assert_eq!(held(&ep, h), 5);
    send_mapping(&mut ep, &syn, 64, dsn + 136, &data[136..137]);
    let free = recv(&ep, h).free();
    feed(&mut ep, &peer_data(&jsyn, 5006, &opt, &data[1005..]), now);
    assert_eq!(
        (held(&ep, h), recv(&ep, h).free()),
        (0, free + 5),
        "dropped"
    );
    send_mapping(&mut ep, &syn, 65, dsn, &data[..1000]);
    send_mapping(&mut ep, &jsyn, 11, dsn + 1000, &data[1000..]);
    assert_eq!(read_now(&mut ep, h), data);
}

/// Subflow 0 takes the 64 assembler ranges; subflow 1's mapping past them would be a 65th, so
/// it is TCP-ACKed and dropped, not DATA_ACKed. Once subflow 0 fills every gap up to it, the
/// peer's resend of it goes in (spec G7, design v3).
#[test]
fn range_refused_completion_resent_after_gap_fills() {
    let (mut ep, h, syn, jsyn, dsn) = two_subflows();
    let now = t(20_000_000);
    let data = pattern(1010);
    for k in 0..64u32 {
        let i = 10 + 2 * k as usize;
        send_mapping(&mut ep, &syn, 1 + k, dsn + i as u64, &data[i..i + 1]);
    }
    send_mapping(&mut ep, &jsyn, 1, dsn + 1000, &data[1000..]);
    let ours = sent_on(&mut ep, &jsyn, now);
    let last = ours.last().unwrap();
    assert_eq!((last.ack, data_ack_of(last)), (SeqNum(5011), Some(dsn)));
    assert_eq!(held(&ep, h), 0);
    send_mapping(&mut ep, &syn, 65, dsn, &data[..1000]);
    send_mapping(&mut ep, &jsyn, 11, dsn + 1000, &data[1000..]);
    assert_eq!(read_now(&mut ep, h), data);
}

/// With the assembler's 64 ranges taken, valid 65,535-octet mappings of one DSN range arrive at
/// successive frontiers: each completes and is dropped by the range cap, so nothing stays held
/// and the subflow stays within `recv_buffer + 2 × 65,535` (G7; round 3 held them).
#[test]
fn range_refused_frontier_mappings_dropped_within_bound() {
    let recv_buffer = 1 << 16;
    let cfg = ConnectConfig {
        recv_buffer,
        ..checksums_cfg(true)
    };
    let mut c = client_with(cfg, false, false);
    c.confirm();
    let dsn = peer_head();
    let bound = recv_buffer as usize + 2 * 65_535;
    for k in 0..64u32 {
        let opt = csum_mapping(1 + k, dsn + 10 + 2 * u64::from(k), b"x", false);
        c.peer_at(5001 + k, &opt, b"x");
    }
    let data = pattern(65_535);
    let mut ssn = 65;
    for _ in 0..4 {
        let opt = csum_mapping(ssn, dsn + 200, &data, false);
        for off in (0..data.len()).step_by(4000) {
            let end = (off + 4000).min(data.len());
            c.peer_at(5000 + ssn + off as u32, &opt, &data[off..end]);
            assert!(held(&c.ep, c.h) <= bound, "{}", held(&c.ep, c.h));
        }
        assert_eq!(held(&c.ep, c.h), 0, "complete, dropped");
        ssn += data.len() as u32;
    }
}

/// Subflow 1 takes the 64 assembler ranges; on subflow 0, N and its duplicate N2 (DSN
/// [H+1000, H+66,535)) complete and are dropped by the range cap; X at `recv.next` completes.
/// N sent again then goes in, and the stream is whole (spec G7, liveness).
#[test]
fn frontier_mapping_at_recv_next_completes() {
    let (mut ep, h, syn, jsyn, dsn) = two_subflows_with(ConnectConfig {
        recv_buffer: 1 << 16,
        ..checksums_cfg(true)
    });
    let data = pattern(66_535);
    for k in 0..64u32 {
        let i = 10 + 2 * k as usize;
        send_mapping(&mut ep, &jsyn, 1 + k, dsn + i as u64, &data[i..i + 1]);
    }
    send_mapping(&mut ep, &syn, 1, dsn + 1000, &data[1000..]);
    send_mapping(&mut ep, &syn, 65_536, dsn + 1000, &data[1000..]);
    assert_eq!(held(&ep, h), 0, "N and N2 dropped");
    send_mapping(&mut ep, &syn, 131_071, dsn, &data[..65_535]);
    assert_eq!(held(&ep, h), 0);
    send_mapping(&mut ep, &syn, 196_606, dsn + 1000, &data[1000..]);
    assert_eq!(read_now(&mut ep, h), data);
}

/// Sends mapping `(ssn, dsn)` of `data` whole on `sf`, in segments of up to 4,000 octets.
fn send_mapping(ep: &mut Endpoint<ChaCha20Rng>, sf: &Segment, ssn: u32, dsn: u64, data: &[u8]) {
    let opt = csum_mapping(ssn, dsn, data, false);
    for off in (0..data.len()).step_by(4000) {
        let end = (off + 4000).min(data.len());
        let seq = 5000 + ssn + off as u32;
        feed(
            ep,
            &peer_data(sf, seq, &opt, &data[off..end]),
            t(20_000_000),
        );
    }
}

/// Codex's three subflows with a redundant sender (RFC 8684 L1369–1381): C takes the 64
/// assembler ranges and loses H; A and B each hold most of X = [H+1, H+259), while N =
/// [H+200, H+65,734) completes on both and is dropped by the range cap. X's last octet
/// completes it on both; N sent again on A then goes in, and the stream completes once A
/// resends H (spec G7, liveness).
#[test]
fn frontier_mapping_touching_a_range_completes() {
    let (mut ep, h, a, b, dsn) = two_subflows_with(ConnectConfig {
        recv_buffer: 256,
        ..checksums_cfg(true)
    });
    let (_, c) = joined(&mut ep, h, t(15_000_000), "10.0.2.1", 1500, 7);
    let now = t(20_000_000);
    let data = pattern(65_734);
    for k in 0..64u32 {
        let i = 10 + 2 * k as usize;
        send_mapping(&mut ep, &c, 1 + k, dsn + i as u64, &data[i..i + 1]);
    }
    let x = csum_mapping(1, dsn + 1, &data[1..259], false);
    for sf in [&a, &b] {
        feed(&mut ep, &peer_data(sf, 5001, &x, &data[1..258]), now);
        send_mapping(&mut ep, sf, 259, dsn + 200, &data[200..]);
    }
    assert_eq!(held(&ep, h), 2 * 257, "X held, N dropped");
    for sf in [&a, &b] {
        feed(&mut ep, &peer_data(sf, 5258, &[], &data[258..259]), now);
    }
    assert_eq!(held(&ep, h), 0);
    send_mapping(&mut ep, &a, 65_793, dsn + 200, &data[200..]);
    send_mapping(&mut ep, &a, 131_327, dsn, &data[..1]);
    assert_eq!(read_now(&mut ep, h), data);
}

/// Subflow 1 takes the 64 assembler ranges; on subflow 0, mappings of [H+200, H+65,735) at
/// successive frontiers would be a 65th range: none is admitted, nothing is held, and subflow
/// 0 is not reset (the full-hold escape of round 5 has no state left to escape). The stream
/// completes over subflow 1 (spec G7, design v2).
#[test]
fn range_capped_frontier_refused_without_reset() {
    let (mut ep, h, a, b, dsn) = two_subflows_with(ConnectConfig {
        recv_buffer: 1 << 16,
        ..checksums_cfg(true)
    });
    let now = t(20_000_000);
    let data = pattern(65_735);
    for k in 0..64u32 {
        let i = 10 + 2 * k as usize;
        send_mapping(&mut ep, &b, 1 + k, dsn + i as u64, &data[i..i + 1]);
    }
    send_mapping(&mut ep, &a, 1, dsn + 200, &data[200..]);
    send_mapping(&mut ep, &a, 65_536, dsn + 200, &data[200..]);
    assert_eq!(rst_reason(&sent_on(&mut ep, &a, now)), None);
    assert_eq!(held(&ep, h), 0);
    send_mapping(&mut ep, &b, 65, dsn, &data[..65_535]);
    send_mapping(&mut ep, &b, 65_600, dsn + 65_535, &data[65_535..]);
    assert_eq!(read_now(&mut ep, h), data);
}

/// The initial subflow holds all but the last octet of a 4,096-octet mapping when it is reset;
/// the joined subflow sends the mapping again and the application reads it. The reset
/// subflow's hold is discarded with it, so the window reopens and the transfer goes on (G7).
#[test]
fn closed_subflow_hold_is_discarded() {
    let (mut ep, h, a, b, dsn) = two_subflows_with(ConnectConfig {
        recv_buffer: 4096,
        ..checksums_cfg(true)
    });
    let now = t(20_000_000);
    let data = pattern(5096);
    let opt = csum_mapping(1, dsn, &data[..4096], false);
    feed(&mut ep, &peer_data(&a, 5001, &opt, &data[..4095]), now);
    assert_eq!(held(&ep, h), 4095);
    let rst = Segment {
        flags: TcpFlags::RST,
        ..peer_data(&a, 5001 + 4095, &[], &[])
    };
    feed(&mut ep, &rst, now);
    send_mapping(&mut ep, &b, 1, dsn, &data[..4096]);
    assert_eq!(read_now(&mut ep, h), &data[..4096]);
    assert_eq!((held(&ep, h), recv(&ep, h).free()), (0, 4096));
    drain(&mut ep, now);
    send_mapping(&mut ep, &b, 4097, dsn + 4096, &data[4096..]);
    assert_eq!(read_now(&mut ep, h), &data[4096..]);
}

/// A mapping at the frontier whose DSN lies 2^63 − 1 past `recv.next`: nothing of it is in
/// the window, so nothing is held, and nothing on the way overflows.
#[test]
fn hostile_dsn_at_the_frontier() {
    let mut c = client(true, false);
    c.confirm();
    let dsn = peer_head().wrapping_add(i64::MAX as u64);
    c.peer_at(5001, &csum_mapping(1, dsn, b"x", false), b"x");
    assert_eq!(held(&c.ep, c.h), 0);
}

/// Our segments from `sf`'s subflow among those due at `now`.
fn sent_on(ep: &mut Endpoint<ChaCha20Rng>, sf: &Segment, now: Instant) -> Vec<Segment<'static>> {
    (drain(ep, now).into_iter())
        .map(|p| packet::parse(p.leak()).unwrap())
        .filter(|s| s.src == sf.src)
        .collect()
}

/// The peer's FIN on `sf` at `seq`, ACKing our FIN among `ours` if there is one.
fn peer_fin(sf: &Segment, seq: u32, ours: &[Segment]) -> Segment<'static> {
    let ours = ours.iter().find(|g| g.flags.contains(TcpFlags::FIN));
    Segment {
        flags: TcpFlags::ACK | TcpFlags::FIN,
        ack: ours.map_or(sf.seq.wrapping_add(1), |f| f.seq.wrapping_add(1)),
        ..peer_data(sf, seq, &[], &[])
    }
}

/// Codex r7 P1 under design v3: subflow 1 takes the 64 assembler ranges; subflow 0's mapping
/// [H+200, H+300) completes and is dropped by the range cap (TCP-ACKed, not DATA_ACKed), and
/// subflow 0 then closes normally. As without checksums, the stream completes once the peer
/// sends the dropped octets again on subflow 1 (spec G7).
#[test]
fn range_refused_completion_dropped_across_close() {
    let (mut ep, h, a, b, dsn) = two_subflows();
    let now = t(20_000_000);
    let data = pattern(300);
    for k in 0..64u32 {
        let i = 10 + 2 * k as usize;
        send_mapping(&mut ep, &b, 1 + k, dsn + i as u64, &data[i..i + 1]);
    }
    send_mapping(&mut ep, &a, 1, dsn + 200, &data[200..]);
    let ours = sent_on(&mut ep, &a, now);
    assert_eq!(ours.last().map(|s| s.ack), Some(SeqNum(5101)), "TCP-ACKed");
    feed(&mut ep, &peer_fin(&a, 5101, &ours), now);
    let ours = sent_on(&mut ep, &a, now);
    feed(&mut ep, &peer_fin(&a, 5102, &ours), now);
    send_mapping(&mut ep, &b, 65, dsn, &data[..200]);
    send_mapping(&mut ep, &b, 265, dsn + 200, &data[200..]);
    assert_eq!(read_now(&mut ep, h), data);
}

/// Codex r7 P2: a subflow that holds part of a mapping and is retired to TIME-WAIT drops its
/// hold, so ended subflows never keep memory past the connection bound (spec G7).
#[test]
fn time_wait_subflow_hold_is_discarded() {
    let (mut ep, h, _, b, dsn) = two_subflows();
    let now = t(20_000_000);
    let data = pattern(100);
    let opt = csum_mapping(1, dsn, &data, false);
    feed(&mut ep, &peer_data(&b, 5001, &opt, &data[..50]), now);
    assert_eq!(held(&ep, h), 50);
    let s = ep.conns[&h].subflows[1].id;
    assert_eq!(ep.close_subflow(now, h, s), Ok(()));
    let ours = sent_on(&mut ep, &b, now);
    feed(&mut ep, &peer_fin(&b, 5051, &ours), now);
    assert_eq!(ep.conns[&h].subflows[1].tcb.state(), TcpState::TimeWait);
    assert_eq!(held(&ep, h), 0);
}

/// Codex r8: subflow 1 takes the 64 assembler ranges. Subflow 0's mapping N = [H+200, H+300)
/// verifies but would be a 65th range: as without checksums it is TCP-ACKed and dropped, not
/// DATA_ACKed, so subflow 0 goes on to the gap [H, H+200), and subflow 1's redundant copy of N
/// completes the stream (spec G7, design v3: parity).
#[test]
fn range_refused_completion_dropped_like_csum_off() {
    let (mut ep, h, a, b, dsn) = two_subflows();
    let now = t(20_000_000);
    let data = pattern(300);
    for k in 0..64u32 {
        let i = 10 + 2 * k as usize;
        send_mapping(&mut ep, &b, 1 + k, dsn + i as u64, &data[i..i + 1]);
    }
    send_mapping(&mut ep, &a, 1, dsn + 200, &data[200..]);
    let ours = sent_on(&mut ep, &a, now);
    let last = ours.last().unwrap();
    assert_eq!((last.ack, data_ack_of(last)), (SeqNum(5101), Some(dsn)));
    assert_eq!(held(&ep, h), 0);
    send_mapping(&mut ep, &a, 101, dsn, &data[..200]);
    send_mapping(&mut ep, &b, 65, dsn + 200, &data[200..]);
    assert_eq!(read_now(&mut ep, h), data);
}

/// As above, but the peer's infinite mapping arrives on subflow 0 while N's dropped octets are
/// still missing: plain TCP would never bring them, so subflow 0 is reset with MP_TCPRST 0x01
/// instead of falling back with a hole (spec G7, G15).
#[test]
fn fallback_with_dropped_octets_missing_resets() {
    let (mut ep, h, a, b, dsn) = two_subflows();
    let now = t(20_000_000);
    let data = pattern(300);
    for k in 0..64u32 {
        let i = 10 + 2 * k as usize;
        send_mapping(&mut ep, &b, 1 + k, dsn + i as u64, &data[i..i + 1]);
    }
    send_mapping(&mut ep, &a, 1, dsn + 200, &data[200..]);
    drain(&mut ep, now);
    let inf = dss_mapping(false, 101, dsn + 300, 0, Some(0));
    feed(&mut ep, &peer_data(&a, 5101, &inf, &[]), now);
    assert_eq!(
        rst_reason(&sent_on(&mut ep, &a, now)),
        Some(vec![30, 4, 0x80, 0x01])
    );
    assert_ne!(negotiation(&ep, h).state, State::FellBack);
}

/// One subflow: after the range cap dropped verified octets, a mapping that fails its checksum
/// resets the subflow with MP_FAIL rather than waiting (spec G10, G11).
#[test]
fn dropped_then_checksum_failure_resets() {
    let mut c = client(true, false);
    c.confirm();
    let dsn = peer_head();
    let data = pattern(300);
    for k in 0..64u32 {
        let i = 10 + 2 * k as usize;
        c.peer_at(
            5001 + k,
            &csum_mapping(1 + k, dsn + i as u64, &data[i..i + 1], false),
            &data[i..i + 1],
        );
    }
    c.peer_at(
        5065,
        &csum_mapping(65, dsn + 200, &data[200..], false),
        &data[200..],
    );
    assert_eq!(held(&c.ep, c.h), 0);
    let mut wire = data[..10].to_vec();
    wire[3] ^= 0xff;
    let sent = c.peer_at(5165, &csum_mapping(165, dsn, &data[..10], false), &wire);
    assert_eq!(rst_reason(&sent), Some(mp_fail_rst(dsn)));
}

// ---------------------------------------------------------------------------------------------
// The default (M4b G1, G23).

/// `ConnectConfig::default()` requires checksums, and the client's SYN says so.
#[test]
fn default_requires_checksums_client() {
    assert!(ConnectConfig::default().checksums);
    let mut ep = Endpoint::new(ChaCha20Rng::seed_from_u64(1));
    ep.connect_mptcp(
        t(0),
        "10.0.0.1".parse().unwrap(),
        "10.0.0.2:80".parse().unwrap(),
        ConnectConfig::default(),
    )
    .unwrap();
    let syn = packet::parse(transmit(&mut ep, t(0)).leak()).unwrap();
    assert_eq!(mpc(syn.options)[0][3], CAP_H | CAP_A);
}

/// A listener on the default config answers an A=0 SYN with A=1 (RFC 8684 L958–967).
#[test]
fn default_requires_checksums_server() {
    assert!(ListenConfig::default().connection.checksums);
    let mut s = Script::new(true);
    s.ep.listeners
        .get_mut(&SERVER.parse().unwrap())
        .unwrap()
        .cfg = ListenConfig::default();
    let synack = s.syn(&syn_cap(1, CAP_H));
    assert_eq!(mptcp_of(&synack)[0][3], CAP_H | CAP_A);
}
