//! MP_FAIL (M4b spec G10–G18): the reset that carries it, `infinite_ok`, and the MP_FAILs we
//! ignore.
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
/// delivered, and Y's held octets are discarded (spec G11, second bullet).
#[test]
fn rst_carries_mp_fail_and_tcprst() {
    let mut c = client(true, false);
    c.confirm();
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
