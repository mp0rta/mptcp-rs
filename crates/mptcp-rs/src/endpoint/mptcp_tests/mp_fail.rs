//! MP_FAIL (M4b spec G10–G18, G21): the reset that carries it, `infinite_ok`, the MP_FAILs we
//! ignore, and the single-subflow fallback: `Waiting`, the echo, the freeze and the timers.
use super::checksum::*;
use super::join_tests::{JOIN_IP, join_syn, synack, synack_opts};
use super::*;
use crate::mptcp::initial_offset_ok;

fn mp_fail(dsn: u64) -> Vec<u8> {
    encode(&MptcpOption::Fail { dsn })
}

fn infinite_ok(ep: &Endpoint<ChaCha20Rng>, h: ConnectionHandle) -> bool {
    ep.conns[&h].hooks.infinite_ok
}

/// The packets due at `now` from `src`'s IP, parsed.
fn sent_from(ep: &mut Endpoint<ChaCha20Rng>, now: Instant, src: &Segment) -> Vec<Segment<'static>> {
    (drain(ep, now).into_iter())
        .map(|p| packet::parse(p.leak()).unwrap())
        .filter(|s| s.src == src.src)
        .collect()
}

fn rst_options(sent: &[Segment]) -> Option<Vec<u8>> {
    let rst = sent.iter().find(|s| s.flags.contains(TcpFlags::RST))?;
    Some(rst.options.to_vec())
}

/// Mapping X (10 octets, bad checksum) completes while mapping Y is partly held behind it:
/// the RST carries exactly MP_FAIL(X.dsn) and MP_TCPRST 0x06 (16 octets), nothing is
/// delivered, and Y's held octets are discarded (spec G11, second bullet). `infinite_ok` is
/// cleared, as a join or a reinjection would.
#[test]
fn rst_carries_mp_fail_and_tcprst() {
    let mut c = client(true, false);
    c.confirm();
    c.ep.conns.get_mut(&c.h).unwrap().hooks.infinite_ok = false;
    let dsn = peer_head();
    let (x, y) = (pattern(10), pattern(100));
    c.peer_at(5001, &bad_mapping(1, dsn, &x, false), &x[..5]);
    assert_eq!(held(&c.ep, c.h), 5);
    let payload = [&x[5..], &y[..20]].concat();
    let sent = c.peer_at(5006, &csum_mapping(11, dsn + 10, &y, false), &payload);
    assert_eq!(rst_options(&sent), Some(mp_fail_rst(dsn)));
    assert_eq!(mp_fail_rst(dsn).len(), 16);
    assert_eq!(recv(&c.ep, c.h).next, dsn);
    assert_eq!(held(&c.ep, c.h), 0);
}

/// After a join completed, a pure ACK with MP_FAIL(d) is answered with RST + MP_FAIL(d) +
/// MP_TCPRST 0x06 on that subflow (spec G13, third bullet; RFC 8684 L2419–2424).
#[test]
fn mp_fail_without_rst_when_not_infinite_ok_resets() {
    let (mut ep, h, syn, _, dsn) = two_subflows();
    assert!(!infinite_ok(&ep, h));
    let now = t(20_000_000);
    let d = dsn + 3;
    feed(&mut ep, &peer_data(&syn, 5001, &mp_fail(d), &[]), now);
    assert_eq!(
        rst_options(&sent_from(&mut ep, now, &syn)),
        Some(mp_fail_rst(d))
    );
}

/// A join refused for a bad HMAC never completed: `infinite_ok` stays, though
/// `joined_ever` is set (spec G10).
#[test]
fn failed_join_keeps_infinite_ok() {
    let (mut ep, h, syn, _) = connected_scaled(1 << 20);
    open_window(&mut ep, &syn, h);
    let now = t(10_000_000);
    let (_, jsyn) = join_syn(&mut ep, h, now, JOIN_IP, 1500);
    let opts = synack_opts(&ep, h, &jsyn, 7, Some(0x0123_4567_89ab_cdef));
    synack(&mut ep, &jsyn, &opts, now);
    let out = sent_from(&mut ep, now, &jsyn);
    assert_eq!(rst_options(&out), Some(vec![30, 4, 0x80, 0x01]));
    assert!(ep.conns[&h].hooks.joined_ever);
    assert!(infinite_ok(&ep, h));
}

/// Sending a connection-level retransmission (here the recovery timer's reinjection on the
/// only subflow) clears `infinite_ok` for good (spec G10).
#[test]
fn reinjection_clears_infinite_ok() {
    let (mut ep, h, syn, _) = connected_with_capacity(64);
    let syn = packet::parse(&syn).unwrap();
    ep.connection(h).unwrap().write(b"lost").unwrap();
    let first = transmit(&mut ep, t(2));
    let first = packet::parse(&first).unwrap();
    let head = una(&ep, h);
    let options = data_ack(head);
    let mut ack = peer_data(&syn, 5001, &options, &[]);
    ack.ack = first.seq.wrapping_add(4);
    input(&mut ep, &ack);
    assert!(infinite_ok(&ep, h));
    let deadline = ep.poll_timeout().expect("connection recovery timer");
    ep.handle_timeout(deadline);
    let retry = transmit(&mut ep, deadline);
    let retry = packet::parse(&retry).unwrap();
    assert_eq!(retry.payload, b"lost");
    assert!(!infinite_ok(&ep, h));
}

/// The offset check is wrap-aware: only the low 32 bits of `dsn − peer_idsn` count.
#[test]
fn initial_offset_ok_wraps() {
    let idsn = 0xffff_ffff_ffff_fff0_u64;
    let dsn = idsn.wrapping_add(1 + (1 << 32) + 7);
    assert!(initial_offset_ok(idsn, dsn, (1 + (1_u64 << 32) + 7) as u32));
    assert!(!initial_offset_ok(idsn, dsn, 7));
}

/// With `infinite_ok` cleared, an MP_FAIL resets nothing after fallback, when malformed
/// (length 11), or on a subflow whose join has not completed (spec G18).
#[test]
fn mp_fail_ignored_after_fallback_and_malformed_and_joining() {
    // After fallback.
    let (mut ep, h, syn, _) = stripped_fallback();
    ep.conns.get_mut(&h).unwrap().hooks.infinite_ok = false;
    let fail = mp_fail(7);
    let mut seg = peer_data(&syn, 5001, &fail, &[]);
    seg.ack = syn.seq.wrapping_add(6);
    input(&mut ep, &seg);
    assert_eq!(rst_options(&sent_from(&mut ep, t(3), &syn)), None);

    // Malformed: Length 11, padded with a NOP.
    let (mut ep, h, syn, _, _) = two_subflows();
    let mut short = mp_fail(7);
    short[1] = 11;
    short[11] = 1;
    let now = t(20_000_000);
    feed(&mut ep, &peer_data(&syn, 5001, &short, &[]), now);
    assert_eq!(rst_options(&sent_from(&mut ep, now, &syn)), None);
    assert_eq!(ep.conns[&h].subflows.len(), 2);

    // Joining: the SYN/ACK arrived, our third ACK is not yet sent.
    let (mut ep, h, syn, _) = connected_scaled(1 << 20);
    open_window(&mut ep, &syn, h);
    ep.conns.get_mut(&h).unwrap().hooks.infinite_ok = false;
    let now = t(10_000_000);
    let (_, jsyn) = join_syn(&mut ep, h, now, JOIN_IP, 1500);
    let opts = synack_opts(&ep, h, &jsyn, 7, None);
    synack(&mut ep, &jsyn, &opts, now);
    feed(&mut ep, &peer_data(&jsyn, 5001, &fail, &[]), now);
    let out = sent_from(&mut ep, now, &jsyn);
    assert!(!out.is_empty(), "the third ACK");
    assert_eq!(rst_options(&out), None);
}

// ---------------------------------------------------------------------------------------------
// Single-subflow fallback (spec G11–G18, G21).

use super::super::server_tests::{
    SERVER, SERVER_KEY, Script, ack_cap, client_idsn, dss_ack, mptcp_of, syn_cap,
};
use crate::mptcp::MpFail;
use crate::wire::mptcp::{CAP_A, MpJoin};

const MP_FAIL_WAIT: Duration = Duration::from_secs(120);

/// The DSN of the MP_FAIL a segment carries.
fn fail_of(seg: &Segment) -> Option<u64> {
    mpc(seg.options)
        .into_iter()
        .find_map(|o| match mptcp::parse(o) {
            Ok(MptcpOption::Fail { dsn }) => Some(dsn),
            _ => None,
        })
}

/// The SACK blocks a segment carries.
fn sack_blocks(seg: &Segment) -> usize {
    walk(seg.options)
        .find_map(|o| match o {
            Ok(TcpOpt::Sack(b)) => Some(b.len() / 8),
            _ => None,
        })
        .unwrap_or(0)
}

/// `FellBack` events since the last call (other events are dropped).
fn fell_back(ep: &mut Endpoint<ChaCha20Rng>) -> usize {
    std::iter::from_fn(|| ep.poll_event())
        .filter(|(_, e)| *e == Event::FellBack)
        .count()
}

fn state(c: &Client) -> MpFail {
    c.ep.conns[&c.h].hooks.mp_fail
}

fn deadline(c: &Client) -> Option<Instant> {
    c.ep.conns[&c.h].mp_fail_deadline()
}

fn rto(c: &Client) -> Duration {
    c.ep.conns[&c.h].subflows[0].tcb.retransmission_timeout()
}

/// How many retries the doubling schedule from `rto` sends within the 120 s wait.
fn retries_within_wait(rto: Duration) -> usize {
    let (mut at, mut interval, mut n) = (Duration::ZERO, rto, 0);
    while at + interval < MP_FAIL_WAIT {
        at += interval;
        interval *= 2;
        n += 1;
    }
    n
}

/// A confirmed client with checksums whose peer sent mapping A (100 octets, verified) and then
/// mapping M (10 octets at SSN 101) with its fourth octet inverted by a middlebox: we are
/// `Waiting` on M since t(2).
struct Waiting {
    c: Client,
    /// M's DSN.
    m: u64,
    /// A and M as they arrived.
    received: Vec<u8>,
    /// Our answer to M.
    sent: Vec<Segment<'static>>,
}

fn waiting_with(sack: bool) -> Waiting {
    let mut c = client_with(checksums_cfg(true), false, sack);
    c.confirm();
    let dsn = peer_head();
    let a = pattern(100);
    c.peer_at(5001, &csum_mapping(1, dsn, &a, false), &a);
    let m = pattern(10);
    let mut wire = m.clone();
    wire[3] ^= 0xff;
    let sent = c.peer_at(5101, &csum_mapping(101, dsn + 100, &m, false), &wire);
    fell_back(&mut c.ep);
    Waiting {
        c,
        m: dsn + 100,
        received: [a, wire].concat(),
        sent,
    }
}

fn waiting() -> Waiting {
    waiting_with(false)
}

/// Our ACK of a corrupt mapping M carries MP_FAIL(M.dsn) and a DATA_ACK at M. With the peer
/// silent, a pure ACK with MP_FAIL is forced at RTO, then 2·RTO and 4·RTO later; the DATA_ACK
/// stays at M (spec G11).
#[test]
fn waiting_sends_mp_fail_on_acks_and_retries() {
    let Waiting { mut c, m, sent, .. } = waiting();
    let ack = sent.last().expect("an ACK");
    assert_eq!((fail_of(ack), data_ack_of(ack)), (Some(m), Some(m)));
    assert!(matches!(state(&c), MpFail::Waiting { dsn, .. } if dsn == m));
    let (mut at, mut interval) = (t(2), rto(&c));
    for _ in 0..3 {
        at = at + interval;
        assert_eq!(deadline(&c), Some(at));
        c.ep.handle_timeout(at);
        let out = c.sent(at);
        assert_eq!(out.len(), 1);
        assert!(out[0].payload.is_empty());
        assert_eq!((fail_of(&out[0]), data_ack_of(&out[0])), (Some(m), Some(m)));
        interval *= 2;
    }
}

/// The peer's echo: we fall back at once, M's octets (the corrupt one included) are readable,
/// and our next data segment carries the infinite mapping `(SSN of send.una, send.una)`, without
/// an MP_FAIL of ours (spec G10a, G13, G15).
#[test]
fn echo_triggers_fallback_and_replay() {
    let Waiting {
        mut c, m, received, ..
    } = waiting();
    c.peer_at(5111, &mp_fail(m + 3), &[]);
    assert_eq!(fell_back(&mut c.ep), 1);
    assert_eq!(state(&c), MpFail::Idle);
    assert_eq!(read_now(&mut c.ep, c.h), received);
    c.ep.connection(c.h).unwrap().write(b"reply").unwrap();
    let out = c.sent(t(2));
    let reply = out.iter().find(|s| s.payload == b"reply").unwrap();
    let (mapping, _) = seg_mapping(reply).expect("our infinite mapping");
    let una = una(&c.ep, c.h);
    let ssn = (una - c.head() + 1) as u32;
    assert_eq!(
        (mapping.data_len, mapping.ssn, dsn64(&mapping)),
        (0, ssn, una)
    );
    assert!(out.iter().all(|s| fail_of(s).is_none()));
}

/// A received infinite mapping falls back as the echo does; so do the echo and the infinite
/// mapping in one segment, in either order: one fallback, no echo, M readable (spec G14, G15).
#[test]
fn infinite_mapping_triggers_fallback_too() {
    let (fail, inf) = (mp_fail(peer_head()), peer_infinite());
    let both = [[&fail[..], &inf].concat(), [&inf[..], &fail].concat()];
    for opts in [inf.clone(), both[0].clone(), both[1].clone()] {
        let Waiting {
            mut c, received, ..
        } = waiting();
        let sent = c.peer_at(5111, &opts, &[]);
        assert_eq!(fell_back(&mut c.ep), 1, "{opts:?}");
        assert_eq!(state(&c), MpFail::Idle);
        assert!(sent.iter().all(|s| fail_of(s).is_none()), "{opts:?}");
        assert_eq!(read_now(&mut c.ep, c.h), received);
    }
}

/// Review Focus 1: the peer sends one request whose only mapping fails, then only ACKs. After
/// its echo the request is readable with no peer data, and our response goes out as plain TCP
/// (spec G15).
#[test]
fn request_response_last_mapping_corrupted() {
    let mut c = client(true, false);
    c.confirm();
    let dsn = peer_head();
    let request = pattern(300);
    let mut wire = request.clone();
    wire[299] ^= 0xff;
    c.peer_at(5001, &csum_mapping(1, dsn, &request, false), &wire);
    assert_eq!(read_now(&mut c.ep, c.h), b"");
    fell_back(&mut c.ep);
    c.peer_at(5301, &mp_fail(dsn), &[]);
    assert_eq!(fell_back(&mut c.ep), 1);
    assert_eq!(read_now(&mut c.ep, c.h), wire);
    c.ep.connection(c.h).unwrap().write(b"response").unwrap();
    let out = c.sent(t(2));
    let response = out.iter().find(|s| s.payload == b"response").unwrap();
    assert_eq!(seg_mapping(response).map(|(m, _)| m.data_len), Some(0));
}

/// Both directions fail at once: the peer's own MP_FAIL reaches us while we are `Waiting`. It
/// is taken as the echo: one fallback, no echo from us, no retry left (spec G13).
#[test]
fn both_directions_fail_at_once() {
    let Waiting {
        mut c, received, ..
    } = waiting();
    let sent = c.peer_at(5111, &mp_fail(c.head() + 50), &[]);
    assert_eq!(fell_back(&mut c.ep), 1);
    assert_eq!(state(&c), MpFail::Idle);
    assert!(!sent.is_empty(), "our infinite mapping");
    assert!(sent.iter().all(|s| fail_of(s).is_none()), "no echo");
    assert_eq!(deadline(&c), None);
    assert_eq!(read_now(&mut c.ep, c.h), received);
}

/// Neither an MP_FAIL nor an infinite mapping 120 s after ours: RST + MP_TCPRST 0x06 then, and
/// not earlier; the held octets are dropped (spec G16).
#[test]
fn waiting_times_out_at_120s() {
    let Waiting { mut c, .. } = waiting();
    let end = t(2) + MP_FAIL_WAIT;
    while let Some(at) = deadline(&c).filter(|&at| at < end) {
        c.ep.handle_timeout(at);
        assert_eq!(rst_options(&c.sent(at)), None);
    }
    assert_eq!(deadline(&c), Some(end));
    let before = Instant::from_nanos(end.as_nanos() - 1);
    c.ep.handle_timeout(before);
    assert_eq!(rst_options(&c.sent(before)), None);
    c.ep.handle_timeout(end);
    assert_eq!(rst_options(&c.sent(end)), Some(vec![30, 4, 0x80, 0x06]));
    assert_eq!(held(&c.ep, c.h), 0);
    assert_eq!(state(&c), MpFail::Idle);
}

/// The client's MP_JOIN SYN from `src` to `SERVER`, for the connection of `SERVER_KEY`; returns
/// what the server sends in answer.
fn join_syn_to_server(s: &mut Script, src: &str) -> Vec<Segment<'static>> {
    let join = MpJoin::Syn {
        backup: false,
        addr_id: 3,
        token: crate::crypto::key_token_idsn(SERVER_KEY).0,
        nonce: 0xa1a2_a3a4,
    };
    let opts = encode(&MptcpOption::Join(join));
    let seg = Segment {
        src: src.parse().unwrap(),
        dst: SERVER.parse().unwrap(),
        seq: SeqNum(7000),
        ack: SeqNum(0),
        flags: TcpFlags::SYN,
        wnd: 65535,
        options: &opts,
        payload: &[],
    };
    feed(&mut s.ep, &seg, s.now);
    (s.output().into_iter())
        .map(|p| packet::parse(p.leak()).unwrap())
        .collect()
}

/// A client with checksums whose peer TCP-ACKed our "lost" without DATA_ACKing it: the
/// recovery timer is armed. Returns the client and its deadline.
fn recovery_armed() -> (Client, Instant) {
    let mut c = client(true, false);
    c.confirm();
    c.ep.connection(c.h).unwrap().write(b"lost").unwrap();
    let sent = c.sent(t(2));
    let first = sent.iter().find(|s| s.payload == b"lost").unwrap();
    let opts = data_ack(una(&c.ep, c.h));
    let syn = c.syn.clone();
    let mut ack = peer_data(&syn, 5001, &opts, &[]);
    ack.ack = first.seq.wrapping_add(4);
    feed(&mut c.ep, &ack, t(2));
    let at = c.ep.conns[&c.h].hooks.recovery_deadline();
    (c, at.expect("recovery timer"))
}

/// A corrupt 10-octet mapping at the peer's first DSN, fed at `now`.
fn corrupt_first_mapping(c: &mut Client, now: Instant) {
    let data = pattern(10);
    let syn = c.syn.clone();
    let opts = bad_mapping(1, peer_head(), &data, false);
    feed(&mut c.ep, &peer_data(&syn, 5001, &opts, &data), now);
    assert!(matches!(state(c), MpFail::Waiting { .. }));
}

/// While `Waiting` nothing may break contiguity (spec G12): a join in SYN-SENT or
/// SYN-RECEIVED is reset (the listener's half-open count drops back), a new `add_subflow` is
/// queued and not started, an incoming join SYN is refused with a RST, a reinjection queued
/// before the failure is not sent, and a recovery deadline passes without one.
#[test]
fn waiting_freezes_joins_and_recovery() {
    let mut s = server(true);
    let server: SocketAddr = SERVER.parse().unwrap();
    s.syn(&syn_cap(1, CAP_H));
    s.send(65535, &ack_cap(CAP_H | CAP_A, None), &[]);
    s.send(
        65535,
        &dss_ack(super::super::server_tests::server_idsn() + 1),
        &[],
    );
    let h = ConnectionHandle(0);
    let (local, other) = ("10.0.0.2".parse().unwrap(), "10.0.3.1:80".parse().unwrap());
    let outgoing =
        s.ep.add_subflow(s.now, h, local, other, 1500, false)
            .unwrap();
    let out = s.output();
    assert!(
        out.iter()
            .any(|p| packet::parse(p).unwrap().flags == TcpFlags::SYN)
    );
    let answer = join_syn_to_server(&mut s, "10.0.1.1:40000");
    assert_eq!(answer[0].flags, TcpFlags::SYN | TcpFlags::ACK);
    assert_eq!(s.ep.listeners[&server].half_open, 1);
    s.events();
    let data = pattern(100);
    let mut wire = data.clone();
    wire[7] ^= 0xff;
    let out = s.send(
        65535,
        &csum_mapping(1, client_idsn() + 1, &data, false),
        &wire,
    );
    let out: Vec<_> = out.iter().map(|p| packet::parse(p).unwrap()).collect();
    let rst: Vec<_> = out
        .iter()
        .filter(|p| p.flags.contains(TcpFlags::RST))
        .collect();
    assert_eq!(
        rst.len(),
        1,
        "the answered join is reset; SYN-SENT sends nothing"
    );
    assert_eq!(rst[0].dst, "10.0.1.1:40000".parse().unwrap());
    assert!(out.iter().any(|p| fail_of(p).is_some()), "our MP_FAIL");
    assert_eq!(s.ep.listeners[&server].half_open, 0);
    let down = Event::SubflowDown {
        subflow: outgoing,
        reason: CloseReason::Reset,
        rst: None,
    };
    assert_eq!(s.events(), [down]);
    let c = &s.ep.conns[&h];
    assert!(matches!(c.hooks.mp_fail, MpFail::Waiting { .. }));
    assert!(c.hooks.infinite_ok);
    // A new join is queued, not started; an incoming one is refused.
    s.ep.add_subflow(s.now, h, local, other, 1500, false)
        .unwrap();
    assert!(
        s.output()
            .iter()
            .all(|p| mptcp_of(p).iter().all(|o| !is_join(o)))
    );
    let subflows = s.ep.conns[&h].subflows.len();
    let answer = join_syn_to_server(&mut s, "10.0.1.1:40001");
    assert_eq!(answer.len(), 1);
    assert!(answer[0].flags.contains(TcpFlags::RST));
    assert_eq!(answer[0].options, [30, 4, 0x80, 0x01]);
    assert_eq!(s.ep.conns[&h].subflows.len(), subflows);

    // A reinjection queued before the failure is not sent.
    let (mut c, at) = recovery_armed();
    c.ep.handle_timeout(at);
    assert!(queue_first(&c.ep, c.h).is_some());
    corrupt_first_mapping(&mut c, at);
    assert!(c.sent(at).iter().all(|s| s.payload != b"lost"));
    assert!(c.ep.conns[&c.h].hooks.infinite_ok);

    // A recovery deadline passes without one.
    let (mut c, at) = recovery_armed();
    corrupt_first_mapping(&mut c, t(2));
    c.ep.handle_timeout(at);
    assert!(c.sent(at).iter().all(|s| s.payload != b"lost"));
    assert_eq!(queue_first(&c.ep, c.h), None);
    assert!(c.ep.conns[&c.h].hooks.infinite_ok);
}

/// A held mapping Y whose DSN−SSN offset is not the initial one (the peer reinjected): a
/// failure of X takes the RST + MP_FAIL path, not `Waiting` (spec G10, G11).
#[test]
fn offset_mismatch_resets() {
    let mut c = client(true, false);
    c.confirm();
    let dsn = peer_head();
    let (x, y) = (pattern(10), pattern(100));
    c.peer_at(5001, &bad_mapping(1, dsn, &x, false), &x[..5]);
    let payload = [&x[5..], &y[..20]].concat();
    let sent = c.peer_at(5006, &csum_mapping(11, dsn + 5000, &y, false), &payload);
    assert_eq!(rst_options(&sent), Some(mp_fail_rst(dsn)));
    assert_eq!(state(&c), MpFail::Idle);
}

/// No local failure: half of a peer mapping is held when the peer's MP_FAIL arrives. We echo
/// with our infinite mapping and fall back; the held half and the plain octets after it are
/// readable in order (spec G13, G15).
#[test]
fn echoer_replays_partial_reverse_mapping() {
    let mut c = client(true, false);
    c.confirm();
    let dsn = peer_head();
    let data = pattern(4000);
    let opt = csum_mapping(1, dsn, &data[..3000], false);
    c.peer_at(5001, &opt, &data[..1460]);
    assert_eq!(held(&c.ep, c.h), 1460);
    fell_back(&mut c.ep);
    let sent = c.peer_at(5001 + 1460, &mp_fail(dsn), &[]);
    assert_eq!(fell_back(&mut c.ep), 1);
    assert!(matches!(state(&c), MpFail::Echo { .. }));
    let echo = sent
        .iter()
        .find(|s| fail_of(s).is_some())
        .expect("our echo");
    assert_eq!(seg_mapping(echo).map(|(m, _)| m.data_len), Some(0));
    c.peer_at(5001 + 1460, &[], &data[1460..]);
    assert_eq!(read_now(&mut c.ep, c.h), data);
}

/// G21: MP_FAIL goes before SACK blocks. An ACK with the 12-octet DSS and MP_FAIL has room for
/// one SACK block; a data segment with the full 28-octet DSS and MP_FAIL has none.
#[test]
fn mp_fail_beats_sack() {
    let Waiting { mut c, m, .. } = waiting_with(true);
    // The second half of the next mapping, past a hole.
    let z = pattern(20);
    let opt = csum_mapping(111, peer_head() + 110, &z, false);
    let sent = c.peer_at(5121, &opt, &z[10..]);
    let ack = sent.last().unwrap();
    assert_eq!(fail_of(ack), Some(m));
    assert_eq!(sack_blocks(ack), 1);
    c.ep.connection(c.h).unwrap().write(&pattern(100)).unwrap();
    let out = c.sent(t(2));
    let data = out.iter().find(|s| !s.payload.is_empty()).unwrap();
    assert_eq!(fail_of(data), Some(m));
    assert_eq!((data.options.len(), sack_blocks(data)), (40, 0));
}

/// The echo rides our segments until the peer TCP-ACKs an octet that only ever travelled with
/// it: a late ACK of older data does not retire it (spec G13).
#[test]
fn echoer_echo_rides_segments_until_first_new_octet_acked() {
    let mut c = client(true, false);
    c.confirm();
    c.ep.connection(c.h).unwrap().set_nodelay(true);
    c.ep.connection(c.h).unwrap().write(b"old").unwrap();
    let sent = c.sent(t(2));
    let old = sent.iter().find(|s| s.payload == b"old").unwrap().clone();
    let sent = c.peer_at(5001, &mp_fail(peer_head()), &[]);
    assert!(sent.iter().any(|s| fail_of(s).is_some()), "the echo");
    c.ep.connection(c.h).unwrap().write(b"new").unwrap();
    let out = c.sent(t(2));
    let new = out.iter().find(|s| s.payload == b"new").unwrap().clone();
    assert!(fail_of(&new).is_some());
    assert_eq!(seg_mapping(&new).map(|(m, _)| m.data_len), Some(0));
    let syn = c.syn.clone();
    let mut ack = peer_data(&syn, 5001, &[], &[]);
    ack.ack = old.seq.wrapping_add(3);
    feed(&mut c.ep, &ack, t(2));
    assert!(deadline(&c).is_some(), "the echo is still due");
    let out = c.peer_at(5001, &[], b"x");
    assert!(fail_of(out.last().unwrap()).is_some());
    ack.seq = SeqNum(5002);
    ack.ack = new.seq.wrapping_add(3);
    feed(&mut c.ep, &ack, t(2));
    assert_eq!(deadline(&c), None);
    let out = c.peer_at(5002, &[], b"y");
    assert_eq!(fail_of(out.last().unwrap()), None);
}

/// The peer reports a failure; we have no data. Our echo is re-sent on a pure ACK on the
/// doubling schedule from the RTO and stops 120 s after the first (spec G13).
#[test]
fn echoer_idle_retries_bounded() {
    let mut c = client(true, false);
    c.confirm();
    let sent = c.peer_at(5001, &mp_fail(peer_head()), &[]);
    assert_eq!(sent.iter().filter(|s| fail_of(s).is_some()).count(), 1);
    let (since, mut interval) = (t(2), rto(&c));
    let (mut at, mut retries) = (since, 0);
    while let Some(next) = deadline(&c) {
        assert_eq!(next, at + interval);
        at = next;
        c.ep.handle_timeout(at);
        let out = c.sent(at);
        assert_eq!(out.len(), 1);
        assert!(out[0].payload.is_empty() && fail_of(&out[0]).is_some());
        interval *= 2;
        retries += 1;
    }
    assert_eq!(retries, retries_within_wait(rto(&c)));
    assert!(retries >= 3);
    let late = since + 2 * MP_FAIL_WAIT;
    c.ep.handle_timeout(late);
    assert!(c.sent(late).is_empty());
}

/// A peer that answers every echo with an MP_FAIL (Linux once its timer is clear) gets no
/// more segments from us than the schedule sends, through and beyond 120 s (spec G18).
#[test]
fn after_fallback_mp_fail_triggers_nothing() {
    let mut c = client(true, false);
    c.confirm();
    let mut total = c.peer_at(5001, &mp_fail(peer_head()), &[]).len();
    let syn = c.syn.clone();
    let answer = mp_fail(peer_head() + 1);
    let answer_at = |c: &mut Client, now: Instant| {
        feed(&mut c.ep, &peer_data(&syn, 5001, &answer, &[]), now);
        c.sent(now).len()
    };
    assert_eq!(answer_at(&mut c, t(2)), 0);
    while let Some(at) = deadline(&c) {
        c.ep.handle_timeout(at);
        total += c.sent(at).len();
        assert_eq!(answer_at(&mut c, at), 0);
    }
    assert_eq!(total, 1 + retries_within_wait(rto(&c)));
    let late = t(2) + 2 * MP_FAIL_WAIT;
    assert_eq!(answer_at(&mut c, late), 0);
    assert_eq!(deadline(&c), None);
}

/// An MP_FAIL on the ACK that completes our join arrived while the join was not complete: it is
/// ignored, though the join completes and clears `infinite_ok` (spec G10, G18).
#[test]
fn mp_fail_on_join_completing_ack_ignored() {
    let (mut ep, h, syn, _) = connected_scaled(1 << 20);
    open_window(&mut ep, &syn, h);
    let now = t(10_000_000);
    let (id, jsyn) = join_syn(&mut ep, h, now, JOIN_IP, 1500);
    let opts = synack_opts(&ep, h, &jsyn, 7, None);
    synack(&mut ep, &jsyn, &opts, now);
    assert!(!sent_from(&mut ep, now, &jsyn).is_empty(), "the third ACK");
    ep.poll_event();
    let opts = [data_ack(una(&ep, h)), mp_fail(7)].concat();
    feed(&mut ep, &peer_data(&jsyn, 5001, &opts, &[]), now);
    assert_eq!(rst_options(&sent_from(&mut ep, now, &jsyn)), None);
    assert_eq!(ep.poll_event(), Some((h, Event::SubflowUp { subflow: id })));
    assert!(!infinite_ok(&ep, h));
}
