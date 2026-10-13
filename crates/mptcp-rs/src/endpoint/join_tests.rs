//! MP_JOIN subflows (RFC 8684 §3.2, spec §5.6) against a scripted Linux-like peer. A child of
//! `mptcp_tests`, whose helpers it reuses.
use super::*;
use crate::crypto::join_hmac;
use crate::endpoint::AddSubflowError;
use crate::mptcp::State;
use crate::wire::mptcp::MpJoin;

pub(super) const JOIN_IP: &str = "10.0.1.1";
const PEER_NONCE: u32 = 0xb1b2_b3b4;

/// The initial subflow's remote (`open`).
fn remote() -> SocketAddr {
    "10.0.0.2:80".parse().unwrap()
}
fn ms(n: u64) -> Instant {
    Instant::from_nanos(n * 1_000_000)
}
fn leak(p: Vec<u8>) -> Segment<'static> {
    packet::parse(p.leak()).unwrap()
}
/// Feeds `seg` at `now`.
fn input_at(ep: &mut Endpoint<ChaCha20Rng>, seg: &Segment, now: Instant) {
    let mut wire = [0; 1500];
    let n = packet::build(seg, 0, &mut wire).unwrap();
    ep.handle_packet(now, &wire[..n]);
}
fn events(ep: &mut Endpoint<ChaCha20Rng>) -> Vec<Event> {
    std::iter::from_fn(|| ep.poll_event())
        .map(|(_, e)| e)
        .collect()
}
fn state(ep: &Endpoint<ChaCha20Rng>, h: ConnectionHandle) -> State {
    ep.conns[&h].hooks.negotiation.as_ref().unwrap().state
}
fn local_key(ep: &Endpoint<ChaCha20Rng>, h: ConnectionHandle) -> u64 {
    ep.conns[&h].hooks.negotiation.as_ref().unwrap().local_key
}
/// The segment's only MPTCP option, which must be an MP_JOIN, and its length.
fn mp_join(seg: &Segment) -> (MpJoin, usize) {
    let opts = mpc(seg.options);
    assert_eq!(opts.len(), 1, "exactly one MPTCP option (no DSS)");
    let Ok(MptcpOption::Join(j)) = mptcp::parse(opts[0]) else {
        panic!("not MP_JOIN: {:?}", mptcp::parse(opts[0]))
    };
    (j, opts[0].len())
}
fn mss(seg: &Segment) -> Option<u16> {
    walk(seg.options).find_map(|o| match o {
        Ok(TcpOpt::Mss(m)) => Some(m),
        _ => None,
    })
}
fn from(pkts: &[Vec<u8>], ip: &str) -> Vec<Segment<'static>> {
    pkts.iter()
        .map(|p| leak(p.clone()))
        .filter(|s| s.src.ip() == ip.parse::<IpAddr>().unwrap())
        .collect()
}

/// A Confirmed connection (peer window scale 7, peer DSS received, window open).
fn confirmed() -> Connected {
    let (mut ep, h, syn, dsn) = connected_scaled(1 << 20);
    open_window(&mut ep, &syn, h);
    assert_eq!(state(&ep, h), State::Confirmed);
    (ep, h, syn, dsn)
}

/// `add_subflow` from `ip` and the MP_JOIN SYN it sends.
pub(super) fn join_syn(
    ep: &mut Endpoint<ChaCha20Rng>,
    h: ConnectionHandle,
    now: Instant,
    ip: &str,
    mtu: u16,
) -> (SubflowId, Segment<'static>) {
    let id = ep
        .add_subflow(now, h, ip.parse().unwrap(), remote(), mtu, false)
        .unwrap();
    let syn = from(&drain(ep, now), ip).pop().expect("join SYN");
    (id, syn)
}

/// The peer's SYN/ACK options: MP_JOIN with the right HMAC-B (unless `hmac` overrides it),
/// MSS 1460 and window scale `ws`.
pub(super) fn synack_opts(
    ep: &Endpoint<ChaCha20Rng>,
    h: ConnectionHandle,
    jsyn: &Segment,
    ws: u8,
    hmac: Option<u64>,
) -> Vec<u8> {
    synack_opts_mss(ep, h, jsyn, ws, hmac, 1460)
}
/// `synack_opts` with MSS option `mss`.
fn synack_opts_mss(
    ep: &Endpoint<ChaCha20Rng>,
    h: ConnectionHandle,
    jsyn: &Segment,
    ws: u8,
    hmac: Option<u64>,
    mss: u16,
) -> Vec<u8> {
    let (MpJoin::Syn { nonce, .. }, _) = mp_join(jsyn) else {
        panic!()
    };
    let mac = join_hmac(PEER_KEY, local_key(ep, h), PEER_NONCE, nonce);
    let hmac64 = hmac.unwrap_or(u64::from_be_bytes(mac[..8].try_into().unwrap()));
    let mut out = [0; 40];
    let n = mptcp::encode(
        &MptcpOption::Join(MpJoin::SynAck {
            backup: false,
            addr_id: 5,
            hmac64,
            nonce: PEER_NONCE,
        }),
        &mut out,
    )
    .unwrap();
    let n = n + crate::wire::tcp_options::write_mss(&mut out[n..], mss);
    let n = n + crate::wire::tcp_options::write_ws(&mut out[n..], ws);
    out[..n].to_vec()
}
/// The peer's SYN/ACK on the join 4-tuple (ISN 5000, like the initial subflow's peer).
pub(super) fn synack(ep: &mut Endpoint<ChaCha20Rng>, jsyn: &Segment, opts: &[u8], now: Instant) {
    let seg = Segment {
        flags: TcpFlags::SYN | TcpFlags::ACK,
        seq: SeqNum(5000),
        ..peer_data(jsyn, 5001, opts, &[])
    };
    input_at(ep, &seg, now);
}
fn third_ack_hmac(ep: &Endpoint<ChaCha20Rng>, h: ConnectionHandle, jsyn: &Segment) -> [u8; 20] {
    let (MpJoin::Syn { nonce, .. }, _) = mp_join(jsyn) else {
        panic!()
    };
    join_hmac(local_key(ep, h), PEER_KEY, nonce, PEER_NONCE)[..20]
        .try_into()
        .unwrap()
}
/// Asserts `seg` is our third ACK: ACK only, MP_JOIN length 24 with HMAC-A, no DSS.
fn assert_third_ack(
    ep: &Endpoint<ChaCha20Rng>,
    h: ConnectionHandle,
    jsyn: &Segment,
    seg: &Segment,
) {
    assert_eq!(seg.flags, TcpFlags::ACK);
    assert_eq!(seg.seq, jsyn.seq.wrapping_add(1));
    assert_eq!(seg.ack, SeqNum(5001));
    assert_eq!(
        mp_join(seg),
        (
            MpJoin::Ack {
                hmac160: third_ack_hmac(ep, h, jsyn)
            },
            24
        )
    );
}
/// Opens a subflow from `ip` and completes the four-way join (peer scale `ws`).
pub(super) fn joined(
    ep: &mut Endpoint<ChaCha20Rng>,
    h: ConnectionHandle,
    now: Instant,
    ip: &str,
    mtu: u16,
    ws: u8,
) -> (SubflowId, Segment<'static>) {
    joined_mss(ep, h, now, ip, mtu, ws, 1460)
}
/// `joined` with the peer's MSS option `mss` in its SYN/ACK.
fn joined_mss(
    ep: &mut Endpoint<ChaCha20Rng>,
    h: ConnectionHandle,
    now: Instant,
    ip: &str,
    mtu: u16,
    ws: u8,
    mss: u16,
) -> (SubflowId, Segment<'static>) {
    let (id, jsyn) = join_syn(ep, h, now, ip, mtu);
    let opts = synack_opts_mss(ep, h, &jsyn, ws, None, mss);
    synack(ep, &jsyn, &opts, now);
    let ack = from(&drain(ep, now), ip).pop().expect("third ACK");
    assert_third_ack(ep, h, &jsyn, &ack);
    let head = una(ep, h);
    peer_ack(ep, &jsyn, now, jsyn.seq.wrapping_add(1), head, 1000);
    assert_eq!(events(ep), vec![Event::SubflowUp { subflow: id }]);
    (id, jsyn)
}

/// Writes `n` octets and acknowledges them at both levels until all are DATA_ACKed. Every data
/// segment must go out on the initial subflow; the peer's stream must be byte-exact.
fn transfer_on_initial(
    ep: &mut Endpoint<ChaCha20Rng>,
    h: ConnectionHandle,
    syn: &Segment,
    n: usize,
    mut now: Instant,
) -> Instant {
    let data: Vec<u8> = (0..n).map(|i| (i % 251) as u8).collect();
    let head = una(ep, h);
    assert_eq!(ep.connection(h).unwrap().write(&data), Ok(n));
    let mut received = vec![None; n];
    while una(ep, h) != head + n as u64 {
        let mut last = None;
        for pkt in drain(ep, now) {
            let seg = packet::parse(&pkt).unwrap();
            if seg.payload.is_empty() {
                continue;
            }
            assert_eq!(seg.src, syn.src, "data only on the initial subflow");
            let (dsn, _) = dsn_of(&seg, syn.seq).unwrap();
            for (i, b) in seg.payload.iter().enumerate() {
                received[(dsn - head) as usize + i] = Some(*b);
            }
            last = Some((
                seg.seq.wrapping_add(seg.payload.len() as u32),
                dsn + seg.payload.len() as u64,
            ));
        }
        let (ack, end) = last.expect("progress");
        now = now + Duration::from_millis(10);
        peer_ack(ep, syn, now, ack, end, 1000);
    }
    let received: Vec<u8> = received.into_iter().map(Option::unwrap).collect();
    assert_eq!(received, data);
    now
}

#[test]
fn join_syn_layout() {
    let (mut ep, h, syn, _) = confirmed();
    let now = ms(10);
    let (id, jsyn) = join_syn(&mut ep, h, now, JOIN_IP, 1500);
    assert_eq!(id, SubflowId(1));
    assert_eq!(jsyn.flags, TcpFlags::SYN);
    assert_eq!(jsyn.dst, syn.dst);
    assert_ne!(jsyn.src.port(), 0);
    let token = crate::crypto::key_token_idsn(PEER_KEY).0;
    let (
        MpJoin::Syn {
            backup,
            addr_id,
            token: t,
            nonce,
        },
        len,
    ) = mp_join(&jsyn)
    else {
        panic!()
    };
    assert_eq!((backup, addr_id, t, len), (false, 1, token, 12));
    assert_eq!(mss(&jsyn), Some(1460));
    assert!(
        walk(jsyn.options).any(|o| matches!(o, Ok(TcpOpt::WindowScale(_)))),
        "window scale offered"
    );
    // SACK-Permitted too (RFC 2018 §2): MP_JOIN 12 + MSS 4 + WS 4 + SACK-Permitted 4.
    assert!(walk(jsyn.options).any(|o| matches!(o, Ok(TcpOpt::SackPermitted))));
    assert_eq!(jsyn.options.len(), 24);
    // Retransmitted on RTO with the same ISN and nonce.
    let rto = ep.poll_timeout().unwrap();
    assert_eq!(rto, now + Duration::from_secs(1));
    ep.handle_timeout(rto);
    let again = from(&drain(&mut ep, rto), JOIN_IP)
        .pop()
        .expect("SYN resent");
    assert_eq!((again.flags, again.seq), (TcpFlags::SYN, jsyn.seq));
    assert!(matches!(mp_join(&again).0, MpJoin::Syn { nonce: n, .. } if n == nonce));
    // Address IDs: 0 for the initial local IP, then one per new distinct local IP.
    for (ip, want) in [("10.0.0.1", 0), ("10.0.2.1", 2), (JOIN_IP, 1)] {
        let (_, s) = join_syn(&mut ep, h, rto, ip, 1500);
        assert!(matches!(mp_join(&s).0, MpJoin::Syn { addr_id, .. } if addr_id == want));
    }
}

#[test]
fn join_completes_on_fourth_ack() {
    let (mut ep, h, _, _) = confirmed();
    let t0 = ms(10);
    let (id, jsyn) = join_syn(&mut ep, h, t0, JOIN_IP, 1500);
    let opts = synack_opts(&ep, h, &jsyn, 7, None);
    synack(&mut ep, &jsyn, &opts, ms(20));
    let ack = from(&drain(&mut ep, ms(20)), JOIN_IP)
        .pop()
        .expect("third ACK");
    assert_third_ack(&ep, h, &jsyn, &ack);
    assert_eq!(
        events(&mut ep),
        vec![],
        "no SubflowUp before the peer's ACK"
    );
    let c = &ep.conns[&h];
    assert_eq!(c.subflows[1].state, SubflowState::Joining);
    let sf = &c.subflows[1].mp;
    assert_eq!(sf.local_isn, jsyn.seq, "joined subflow's own ISN");
    assert_eq!(sf.peer_scale, 7, "scale from the join SYN/ACK");
    assert_eq!(sf.tcp_acked_dsn, una(&ep, h), "nothing TCP-acked on it yet");
    // Resent on the backed-off RTO until the peer acknowledges it.
    let mut at = ms(20);
    for gap in [1, 2] {
        let due = ep.poll_timeout().unwrap();
        assert_eq!(due, at + Duration::from_secs(gap));
        at = due;
        ep.handle_timeout(at);
        let again = from(&drain(&mut ep, at), JOIN_IP);
        assert_eq!(again.len(), 1);
        assert_third_ack(&ep, h, &jsyn, &again[0]);
    }
    let head = una(&ep, h);
    peer_ack(&mut ep, &jsyn, at, jsyn.seq.wrapping_add(1), head, 1000);
    assert_eq!(events(&mut ep), vec![Event::SubflowUp { subflow: id }]);
    assert_eq!(ep.conns[&h].subflows[1].state, SubflowState::Active);
    // Done: no more MP_JOIN, no join timer.
    assert_eq!(ep.poll_timeout(), None);
    assert!(drain(&mut ep, at).iter().map(|p| leak(p.clone())).all(|s| {
        !mpc(s.options)
            .iter()
            .any(|o| matches!(mptcp::parse(o), Ok(MptcpOption::Join(_))))
    }));
}

#[test]
fn duplicate_synack_answered_with_mp_join_ack() {
    let (mut ep, h, _, _) = confirmed();
    let (id, jsyn) = join_syn(&mut ep, h, ms(10), JOIN_IP, 1500);
    let opts = synack_opts(&ep, h, &jsyn, 7, None);
    synack(&mut ep, &jsyn, &opts, ms(20));
    assert_eq!(
        from(&drain(&mut ep, ms(20)), JOIN_IP).len(),
        1,
        "third ACK (lost)"
    );
    // The peer retransmits its SYN/ACK before our resend deadline.
    assert!(ep.poll_timeout().unwrap() > ms(300));
    synack(&mut ep, &jsyn, &opts, ms(300));
    let ack = from(&drain(&mut ep, ms(300)), JOIN_IP);
    assert_eq!(ack.len(), 1, "immediate ACK");
    assert_third_ack(&ep, h, &jsyn, &ack[0]);
    assert_eq!(events(&mut ep), vec![]);
    let head = una(&ep, h);
    peer_ack(
        &mut ep,
        &jsyn,
        ms(310),
        jsyn.seq.wrapping_add(1),
        head,
        1000,
    );
    assert_eq!(events(&mut ep), vec![Event::SubflowUp { subflow: id }]);
}

/// The peer's answer to the join SYN ends only that subflow; the initial one keeps working.
fn refused(answer: impl FnOnce(&mut Endpoint<ChaCha20Rng>, ConnectionHandle, &Segment), rst: bool) {
    let (mut ep, h, syn, _) = confirmed();
    let (id, jsyn) = join_syn(&mut ep, h, ms(10), JOIN_IP, 1500);
    answer(&mut ep, h, &jsyn);
    let out = from(&drain(&mut ep, ms(20)), JOIN_IP);
    if rst {
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].flags, TcpFlags::RST);
        assert_eq!(out[0].seq, jsyn.seq.wrapping_add(1));
        assert_eq!(out[0].options, [30, 4, 0x80, 0x01], "MP_TCPRST 0x01/T0");
    } else {
        assert!(out.is_empty(), "a RST is not answered");
    }
    assert_eq!(
        events(&mut ep),
        vec![Event::SubflowDown {
            subflow: id,
            reason: CloseReason::Reset,
            rst: None
        }]
    );
    assert_eq!(state(&ep, h), State::Confirmed);
    let now = transfer_on_initial(&mut ep, h, &syn, 30_000, ms(30));
    // The dead subflow and its port are released.
    ep.handle_timeout(now);
    assert_eq!(ep.conns[&h].subflows.len(), 1);
    assert!(!ep.demux.contains_key(&(jsyn.src, jsyn.dst)));
    assert_eq!(events(&mut ep), vec![]);
    assert_eq!(ep.poll_timeout(), None, "no no-subflow wait");
}

#[test]
fn join_bad_hmac_resets_subflow() {
    refused(
        |ep, h, jsyn| {
            let opts = synack_opts(ep, h, jsyn, 7, Some(0x0123_4567_89ab_cdef));
            synack(ep, jsyn, &opts, ms(20));
        },
        true,
    );
}

#[test]
fn join_synack_without_mpjoin_resets_subflow() {
    refused(
        |ep, _, jsyn| {
            let mut opts = [0; 8];
            let n = crate::wire::tcp_options::write_mss(&mut opts, 1460);
            let n = n + crate::wire::tcp_options::write_ws(&mut opts[n..], 7);
            synack(ep, jsyn, &opts[..n], ms(20));
        },
        true,
    );
}

#[test]
fn join_rst_from_peer_is_subflow_down() {
    refused(
        |ep, _, jsyn| {
            let rst = Segment {
                flags: TcpFlags::RST | TcpFlags::ACK,
                ..peer_data(jsyn, 0, &[], &[])
            };
            input_at(ep, &rst, ms(20));
        },
        false,
    );
}

#[test]
fn join_third_ack_gives_up_at_r2() {
    let (mut ep, h, _, _) = confirmed();
    ep.conns.get_mut(&h).unwrap().cfg.r2_data = Duration::from_secs(5);
    let (id, jsyn) = join_syn(&mut ep, h, ms(10), JOIN_IP, 1500);
    let opts = synack_opts(&ep, h, &jsyn, 7, None);
    let t1 = ms(20);
    synack(&mut ep, &jsyn, &opts, t1);
    assert_eq!(from(&drain(&mut ep, t1), JOIN_IP).len(), 1);
    let mut sent = Vec::new();
    while let Some(t) = ep
        .poll_timeout()
        .filter(|&t| t < t1 + Duration::from_secs(20))
    {
        ep.handle_timeout(t);
        for s in from(&drain(&mut ep, t), JOIN_IP) {
            sent.push((t, s.flags));
        }
    }
    let s = |n| t1 + Duration::from_secs(n);
    assert_eq!(
        sent,
        vec![
            (s(1), TcpFlags::ACK),
            (s(3), TcpFlags::ACK),
            (s(5), TcpFlags::RST)
        ]
    );
    assert_eq!(
        events(&mut ep),
        vec![Event::SubflowDown {
            subflow: id,
            reason: CloseReason::Timeout,
            rst: None
        }]
    );
    ep.handle_timeout(s(6));
    assert_eq!(ep.conns[&h].subflows.len(), 1);
    assert_eq!(state(&ep, h), State::Confirmed);
}

#[test]
fn add_subflow_errors() {
    use AddSubflowError::*;
    let ip = |s: &str| s.parse::<IpAddr>().unwrap();
    // Queued before Confirmed: no SYN until a peer DSS arrives (RFC 8684 L884–887).
    let (mut ep, h, syn, _) = connected_scaled(1 << 20);
    assert_eq!(state(&ep, h), State::PreConfirmed);
    let t = Instant::from_nanos(1);
    assert_eq!(
        ep.add_subflow(t, h, ip(JOIN_IP), remote(), 1500, false),
        Ok(SubflowId(1))
    );
    assert!(from(&drain(&mut ep, t), JOIN_IP).is_empty());
    assert_eq!(ep.conns[&h].subflows.len(), 1);
    open_window(&mut ep, &syn, h);
    let jsyn = from(&drain(&mut ep, ms(2)), JOIN_IP);
    assert_eq!(jsyn.len(), 1);
    assert!(matches!(mp_join(&jsyn[0]).0, MpJoin::Syn { .. }));
    // Queued in SYN-SENT, then the peer sets C=1: dropped, never sent; later calls refused.
    let mut ep = Endpoint::new(ChaCha20Rng::seed_from_u64(40));
    let h = open(&mut ep);
    let syn = leak(transmit(&mut ep, ms(0)));
    assert_eq!(
        ep.add_subflow(ms(0), h, ip(JOIN_IP), remote(), 1500, false),
        Ok(SubflowId(1))
    );
    reply(
        &mut ep,
        &syn,
        &capable(1, CAP_H | mptcp::CAP_C),
        syn.seq.wrapping_add(1),
    );
    assert!(from(&drain(&mut ep, ms(1)), JOIN_IP).is_empty());
    assert!(ep.conns[&h].hooks.negotiation.as_ref().unwrap().peer_c);
    let ev = events(&mut ep);
    assert!(ev.contains(&Event::SubflowDown {
        subflow: SubflowId(1),
        reason: CloseReason::Reset,
        rst: None
    }));
    assert_eq!(
        ep.add_subflow(ms(1), h, ip(JOIN_IP), remote(), 1500, false),
        Err(PeerForbidsJoin)
    );
    let dss = data_ack(una(&ep, h));
    input_at(&mut ep, &peer_data(&syn, 5001, &dss, &[]), ms(2));
    assert_eq!(state(&ep, h), State::Confirmed);
    assert_eq!(
        ep.add_subflow(ms(2), h, ip(JOIN_IP), remote(), 1500, false),
        Err(PeerForbidsJoin)
    );
    assert!(from(&drain(&mut ep, ms(2)), JOIN_IP).is_empty());
    // Queued, then handshake fallback: dropped, never sent; NotMptcp afterwards.
    let mut ep = Endpoint::new(ChaCha20Rng::seed_from_u64(41));
    let h = open(&mut ep);
    let syn = leak(transmit(&mut ep, ms(0)));
    assert_eq!(
        ep.add_subflow(ms(0), h, ip(JOIN_IP), remote(), 1500, false),
        Ok(SubflowId(1))
    );
    reply(&mut ep, &syn, &[], syn.seq.wrapping_add(1));
    assert!(from(&drain(&mut ep, ms(1)), JOIN_IP).is_empty());
    assert!(events(&mut ep).contains(&Event::SubflowDown {
        subflow: SubflowId(1),
        reason: CloseReason::Reset,
        rst: None
    }));
    assert_eq!(
        ep.add_subflow(ms(1), h, ip(JOIN_IP), remote(), 1500, false),
        Err(NotMptcp)
    );
    // Plain TCP.
    let mut ep = Endpoint::new(ChaCha20Rng::seed_from_u64(42));
    let h = ep
        .connect(
            ms(0),
            ip("10.0.0.1"),
            "10.0.0.2:80".parse().unwrap(),
            ConnectConfig::default(),
        )
        .unwrap();
    assert_eq!(
        ep.add_subflow(ms(0), h, ip(JOIN_IP), remote(), 1500, false),
        Err(NotMptcp)
    );
    assert_eq!(
        ep.add_subflow(
            ms(0),
            ConnectionHandle(99),
            ip(JOIN_IP),
            remote(),
            1500,
            false
        ),
        Err(NoConnection)
    );
    // Confirmed: address family, MTU, the subflow cap, then close.
    let (mut ep, h, _, _) = confirmed();
    assert_eq!(
        ep.add_subflow(ms(5), h, ip("fd00::1"), remote(), 1500, false),
        Err(FamilyMismatch)
    );
    assert_eq!(
        ep.add_subflow(ms(5), h, ip(JOIN_IP), remote(), 67, false),
        Err(InvalidMtu)
    );
    for i in 1..8 {
        assert_eq!(
            ep.add_subflow(ms(5), h, ip(JOIN_IP), remote(), 68, false),
            Ok(SubflowId(i))
        );
    }
    assert_eq!(
        ep.add_subflow(ms(5), h, ip(JOIN_IP), remote(), 1500, false),
        Err(TooManySubflows)
    );
    assert_eq!(from(&drain(&mut ep, ms(5)), JOIN_IP).len(), 7);
    let (mut ep, h, _, _) = confirmed();
    ep.connection(h).unwrap().close();
    assert_eq!(
        ep.add_subflow(ms(5), h, ip(JOIN_IP), remote(), 1500, false),
        Err(Closed)
    );
    assert!(from(&drain(&mut ep, ms(5)), JOIN_IP).is_empty());
}

#[test]
fn join_syn_mss_from_subflow_mtu() {
    let (mut ep, h, syn, _) = confirmed();
    let (_, jsyn) = join_syn(&mut ep, h, ms(10), JOIN_IP, 1280);
    assert_eq!(mss(&jsyn), Some(1240));
    assert_eq!(mss(&syn), Some(1460));
    assert_eq!(ep.conns[&h].subflows[0].tcb.mtu(), 1500);
}

#[test]
fn small_buffer_skips_large_mtu_subflow() {
    let (mut ep, h, syn, dsn) = confirmed();
    let (_, jsyn) = joined(&mut ep, h, ms(10), JOIN_IP, 1280, 7);
    // Subflow 0 owes an ACK for peer data; the application queues more than one cwnd.
    let opts = mapping(1, dsn, 100);
    input_at(&mut ep, &peer_data(&syn, 5001, &opts, &[7; 100]), ms(20));
    ep.connection(h).unwrap().write(&[9; 50_000]).unwrap();
    let sf0 = |ep: &Endpoint<ChaCha20Rng>| {
        let sf = &ep.conns[&h].subflows[0];
        (format!("{:?}", sf.tcb), sf.mp.tx.assigned_end())
    };
    let before = sf0(&ep);
    let mut small = Vec::new();
    let mut buf = [0; 1280];
    while let Some(n) = ep.poll_transmit(ms(20), &mut buf) {
        small.push(leak(buf[..n].to_vec()));
    }
    assert!(!small.is_empty(), "subflow 1 sends");
    assert!(
        small
            .iter()
            .all(|s| s.src == jsyn.src && !s.payload.is_empty())
    );
    assert_eq!(sf0(&ep), before, "nothing built for subflow 0");
    let big = drain(&mut ep, ms(20));
    let on0 = from(&big, "10.0.0.1");
    assert!(on0.iter().any(|s| s.ack == SeqNum(5101)), "the owed ACK");
    assert!(
        on0.iter().any(|s| !s.payload.is_empty()),
        "subflow 0's data"
    );
}

#[test]
fn join_data_ack_window_uses_join_scale() {
    let (mut ep, h, _, _) = confirmed();
    let (_, jsyn) = joined(&mut ep, h, ms(10), JOIN_IP, 1500, 9);
    let head = una(&ep, h);
    peer_ack(&mut ep, &jsyn, ms(20), jsyn.seq.wrapping_add(1), head, 1000);
    let edge = ep.conns[&h]
        .hooks
        .negotiation
        .as_ref()
        .unwrap()
        .send_right_edge;
    assert_eq!(
        edge,
        Some(head + (1000 << 9)),
        "the joined subflow's scale 9"
    );
}

#[test]
fn join_rogue_plan_naming_joining_subflow_rejected() {
    let (mut ep, h, syn, _) = confirmed();
    let (id, jsyn) = join_syn(&mut ep, h, ms(10), JOIN_IP, 1500);
    let opts = synack_opts(&ep, h, &jsyn, 7, None);
    synack(&mut ep, &jsyn, &opts, ms(20));
    assert_eq!(from(&drain(&mut ep, ms(20)), JOIN_IP).len(), 1, "third ACK");
    // Established at TCP level, still Joining: it must get no data.
    let (log, rogue) = install_probe(&mut ep, h);
    *rogue.lock().unwrap() = Some(Rogue::Named(id));
    ep.connection(h).unwrap().write(&[1; 5000]).unwrap();
    assert!(
        drain(&mut ep, ms(30)).is_empty(),
        "rejected plan: nothing sent"
    );
    assert_eq!(ep.conns[&h].hooks.rejected_plans, 1);
    assert!(log.lock().unwrap().assigned.is_empty());
    let snapshot = ep.conns[&h].snapshots()[1];
    assert_eq!(snapshot.state, SubflowState::Joining);
    assert_eq!(snapshot.new_budget.bytes(), 0, "not usable");
    *rogue.lock().unwrap() = None;
    let out = drain(&mut ep, ms(30));
    assert!(!out.is_empty());
    assert!(
        out.iter()
            .map(|p| leak(p.clone()))
            .all(|s| s.src == syn.src)
    );
}

/// An ACK carrying only `option` (no DSS), duplicate at TCP level.
fn signal_ack(
    ep: &mut Endpoint<ChaCha20Rng>,
    syn: &Segment,
    ack: SeqNum,
    option: &[u8],
    now: Instant,
) {
    let seg = Segment {
        ack,
        wnd: 1000,
        ..peer_data(syn, 5001, option, &[])
    };
    input_at(ep, &seg, now);
}

/// After `dss_confirmed` on `syn`'s subflow, with `seq` outstanding on it: ADD_ADDR and
/// MP_PRIO without DSS neither fall back, nor reset, nor count as duplicate ACKs; DSS
/// duplicates still do.
fn signals_ignored(
    ep: &mut Endpoint<ChaCha20Rng>,
    h: ConnectionHandle,
    syn: &Segment,
    seq: SeqNum,
    now: Instant,
) {
    let add_addr = [30, 8, 0x30, 1, 10, 0, 8, 2];
    let mp_prio = [30, 3, 0x50, 1];
    for opt in [&add_addr[..], &mp_prio, &add_addr, &mp_prio] {
        signal_ack(ep, syn, seq, opt, now);
        assert!(drain(ep, now).is_empty(), "no retransmission, no RST");
    }
    // MP_PRIO only reports the peer's preference (M3 Task 7).
    let ev = events(ep);
    assert_eq!(ev.len(), 2);
    assert!((ev.iter()).all(|e| matches!(e, Event::PeerPriority { backup: false, .. })));
    assert_eq!(state(ep, h), State::Confirmed);
    let dss = data_ack(una(ep, h));
    for _ in 0..2 {
        signal_ack(ep, syn, seq, &dss, now);
        assert!(drain(ep, now).is_empty());
    }
    signal_ack(ep, syn, seq, &dss, now);
    let fr = leak(transmit(ep, now));
    assert_eq!((fr.src, fr.seq), (syn.src, seq), "third DSS duplicate");
}

#[test]
fn unknown_mptcp_signal_is_not_stripping() {
    let (mut ep, h, syn, _) = confirmed();
    // Initial subflow.
    ep.connection(h).unwrap().write(&[1; 100]).unwrap();
    let first = leak(transmit(&mut ep, ms(30)));
    let end = first.seq.wrapping_add(100);
    let head = una(&ep, h);
    peer_ack(&mut ep, &syn, ms(30), end, head + 100, 1000);
    assert!(ep.conns[&h].subflows[0].mp.dss_confirmed);
    ep.connection(h).unwrap().write(&[2; 100]).unwrap();
    assert_eq!(leak(transmit(&mut ep, ms(30))).seq, end);
    signals_ignored(&mut ep, h, &syn, end, ms(40));
    let head = una(&ep, h);
    peer_ack(
        &mut ep,
        &syn,
        ms(40),
        end.wrapping_add(100),
        head + 100,
        1000,
    );
    // Joined subflow: close subflow 0's window so data goes on subflow 1.
    let (_, jsyn) = joined(&mut ep, h, ms(50), JOIN_IP, 1500, 7);
    let head = una(&ep, h);
    peer_ack(&mut ep, &syn, ms(50), end.wrapping_add(100), head, 0);
    ep.connection(h).unwrap().write(&[3; 100]).unwrap();
    let on1 = leak(transmit(&mut ep, ms(60)));
    assert_eq!((on1.src, on1.payload.len()), (jsyn.src, 100));
    let end1 = on1.seq.wrapping_add(100);
    peer_ack(&mut ep, &jsyn, ms(60), end1, head + 100, 1000);
    assert!(ep.conns[&h].subflows[1].mp.dss_confirmed);
    ep.connection(h).unwrap().write(&[4; 100]).unwrap();
    assert_eq!(leak(transmit(&mut ep, ms(60))).seq, end1);
    signals_ignored(&mut ep, h, &jsyn, end1, ms(60));
    assert_eq!(
        ep.conns[&h].subflows[1].tcb.state(),
        crate::tcp::TcpState::Established
    );
}

// M2 Task 5: data across two Active subflows.

/// `confirmed` with congestion controller `cc` on every new subflow.
fn confirmed_cc(cc: fn() -> Box<dyn CongestionControl>) -> Connected {
    let (mut ep, h, syn, dsn) = connected_scaled_cc(1 << 20, Some(cc));
    open_window(&mut ep, &syn, h);
    (ep, h, syn, dsn)
}
/// A Confirmed connection plus subflow 1 joined from `JOIN_IP` at `ms(10)` (MTU 1500, peer
/// scale 7); subflow 0 runs `cc0`, subflow 1 `cc1`.
fn two_paths(
    cc0: fn() -> Box<dyn CongestionControl>,
    cc1: fn() -> Box<dyn CongestionControl>,
) -> (
    Endpoint<ChaCha20Rng>,
    ConnectionHandle,
    Segment<'static>,
    Segment<'static>,
) {
    let (mut ep, h, syn, _) = confirmed_cc(cc0);
    ep.cc = Some(cc1);
    let (_, jsyn) = joined(&mut ep, h, ms(10), JOIN_IP, 1500, 7);
    (ep, h, syn, jsyn)
}
/// `two_paths` with `n` octets queued while the connection window is closed, so no pass ends
/// idle before the test starts (no `NoData` interval on either subflow); then both peer
/// windows open to 8 MiB. Returns the head DSN and the data too.
fn two_paths_queued(
    cc0: fn() -> Box<dyn CongestionControl>,
    cc1: fn() -> Box<dyn CongestionControl>,
    n: usize,
) -> (
    Endpoint<ChaCha20Rng>,
    ConnectionHandle,
    Segment<'static>,
    Segment<'static>,
    u64,
    Vec<u8>,
) {
    let (mut ep, h, syn, _) = confirmed_cc(cc0);
    let head = una(&ep, h);
    set_edge(&mut ep, h, head);
    let data: Vec<u8> = (0..n).map(|i| (i % 251) as u8).collect();
    assert_eq!(ep.connection(h).unwrap().write(&data), Ok(n));
    ep.cc = Some(cc1);
    let (_, jsyn) = joined(&mut ep, h, ms(10), JOIN_IP, 1500, 7);
    for s in [&syn, &jsyn] {
        peer_ack(&mut ep, s, ms(10), s.seq.wrapping_add(1), head, 65535);
    }
    (ep, h, syn, jsyn, head, data)
}
/// Sets the peer's connection-level right edge (test shortcut).
fn set_edge(ep: &mut Endpoint<ChaCha20Rng>, h: ConnectionHandle, edge: u64) {
    let m = ep.conns.get_mut(&h).unwrap().hooks.negotiation.as_mut();
    m.unwrap().send_right_edge = Some(edge);
}
fn edge(ep: &Endpoint<ChaCha20Rng>, h: ConnectionHandle) -> Option<u64> {
    ep.conns[&h]
        .hooks
        .negotiation
        .as_ref()
        .unwrap()
        .send_right_edge
}
fn queue_reinject(ep: &mut Endpoint<ChaCha20Rng>, h: ConnectionHandle, dsn: u64, len: u64) {
    let d = ep.conns.get_mut(&h).unwrap().hooks.data.as_mut().unwrap();
    d.reinject.insert(dsn, len);
}
/// Segments in `pkts` sent on `syn`'s subflow.
fn on(pkts: &[Vec<u8>], syn: &Segment) -> Vec<Segment<'static>> {
    let all = pkts.iter().map(|p| leak(p.clone()));
    all.filter(|s| s.src == syn.src).collect()
}
/// Data segments in `pkts` sent on `syn`'s subflow.
fn data_on(pkts: &[Vec<u8>], syn: &Segment) -> Vec<Segment<'static>> {
    let mut v = on(pkts, syn);
    v.retain(|s| !s.payload.is_empty());
    v
}
fn end(seg: &Segment) -> SeqNum {
    seg.seq.wrapping_add(seg.payload.len() as u32)
}
/// Pins the scheduler to subflow `id`; `None`: MinRTT.
fn pin(ep: &mut Endpoint<ChaCha20Rng>, h: ConnectionHandle, id: Option<SubflowId>) {
    let (_, rogue) = install_probe(ep, h);
    *rogue.lock().unwrap() = id.map(Rogue::Pin);
}
/// An RTT sample of `rtt` on subflow `id`, whose SYN is `syn`: 100 octets pinned to it at
/// `now`, ACKed at both levels `rtt` later (window field 65535). Returns the ACK's time and
/// the subflow's SND.UNA after it.
fn prime(
    ep: &mut Endpoint<ChaCha20Rng>,
    h: ConnectionHandle,
    syn: &Segment,
    id: SubflowId,
    now: Instant,
    rtt: u64,
) -> (Instant, SeqNum) {
    pin(ep, h, Some(id));
    let head = una(ep, h);
    ep.connection(h).unwrap().write(&[0; 100]).unwrap();
    let seg = data_on(&drain(ep, now), syn).pop().expect("primed");
    assert_eq!(seg.payload.len(), 100);
    let at = now + Duration::from_millis(rtt);
    peer_ack(ep, syn, at, end(&seg), head + 100, 65535);
    pin(ep, h, None);
    (at, end(&seg))
}
fn data_fin(seg: &Segment) -> bool {
    mpc(seg.options)
        .iter()
        .any(|o| matches!(mptcp::parse(o), Ok(MptcpOption::Dss(d)) if d.data_fin))
}
fn infinite_mapping(seg: &Segment) -> bool {
    mpc(seg.options).iter().any(|o| {
        matches!(mptcp::parse(o), Ok(MptcpOption::Dss(d)) if d.mapping.is_some_and(|m| m.data_len == 0))
    })
}
fn big(b: bool) -> Box<dyn CongestionControl> {
    Box::new(FixedPacing {
        rate: None,
        cwnd: 256 << 10,
        b,
    })
}
fn big_a() -> Box<dyn CongestionControl> {
    big(false)
}
fn big_b() -> Box<dyn CongestionControl> {
    big(true)
}
fn recording_b() -> Box<dyn CongestionControl> {
    Box::new(FixedPacing {
        rate: None,
        cwnd: 64 << 10,
        b: true,
    })
}
fn clear_samples() {
    SAMPLES.with(|s| s.borrow_mut().clear());
    SAMPLES_B.with(|s| s.borrow_mut().clear());
}
fn sample_flags(b: bool) -> Vec<bool> {
    let sink = if b { &SAMPLES_B } else { &SAMPLES };
    sink.with(|s| s.borrow().iter().map(|a| a.app_limited).collect())
}

/// A peer behind one path per subflow: it takes every data segment at once and answers it
/// `rtt` later at both levels (the TCP ACK of its subflow, the contiguous DATA_ACK) with
/// window field 65535. A `strip`ped path's ACKs carry no option and its data is not placed (no
/// mapping reaches the peer); a `drop`ped path loses everything both ways (answers due on it
/// are lost when they fall due); a path we reset is ignored afterwards. A copy of octets it
/// already holds must match them and counts in `dups`. A `lose` entry `(path, dsn, acked)`
/// loses the next data segment starting at `dsn` on that path once: entirely, or (`acked`)
/// after the peer's TCP took it, which the peer then ACKs without placing it. `feed` is what
/// the application still writes, as the store takes it.
struct Peer {
    syns: Vec<Segment<'static>>,
    rtts: Vec<Duration>,
    strip: Vec<bool>,
    drop: Vec<bool>,
    lose: Vec<(usize, u64, bool)>,
    feed: Vec<u8>,
    dups: usize,
    reset: Vec<bool>,
    next: Vec<SeqNum>,
    head: u64,
    got: Vec<Option<u8>>,
    /// Due answers: time, path, TCP ACK, DATA_ACK.
    acks: Vec<(Instant, usize, SeqNum, u64)>,
    /// Placed data segments: time, path, DSN.
    log: Vec<(Instant, usize, u64)>,
    /// Every segment we sent, by path.
    sent: Vec<(usize, Segment<'static>)>,
}
impl Peer {
    fn new(head: u64, n: usize, paths: &[(&Segment<'static>, u64)]) -> Self {
        Self {
            syns: paths.iter().map(|p| p.0.clone()).collect(),
            rtts: paths.iter().map(|p| Duration::from_millis(p.1)).collect(),
            strip: vec![false; paths.len()],
            drop: vec![false; paths.len()],
            lose: Vec::new(),
            feed: Vec::new(),
            dups: 0,
            reset: vec![false; paths.len()],
            next: paths.iter().map(|p| p.0.seq.wrapping_add(1)).collect(),
            head,
            got: vec![None; n],
            acks: Vec::new(),
            log: Vec::new(),
            sent: Vec::new(),
        }
    }
    fn dack(&self) -> u64 {
        self.head + self.got.iter().take_while(|b| b.is_some()).count() as u64
    }
    fn received(&self) -> Vec<u8> {
        self.got.iter().map(|b| b.expect("every octet")).collect()
    }
    fn take(&mut self, now: Instant, seg: Segment<'static>) {
        let Some(i) = self.syns.iter().position(|s| s.src == seg.src) else {
            return;
        };
        self.sent.push((i, seg.clone()));
        if self.drop[i] {
            return;
        }
        self.reset[i] |= seg.flags.contains(TcpFlags::RST);
        if self.reset[i] || seg.payload.is_empty() {
            return;
        }
        let dsn = dsn_of(&seg, self.syns[i].seq).map(|(dsn, _)| dsn);
        let lost = (self.lose.iter()).position(|&(p, d, _)| p == i && Some(d) == dsn);
        let acked_only = lost.is_some_and(|k| self.lose.remove(k).2);
        if lost.is_some() && !acked_only {
            return;
        }
        if end(&seg).gt(self.next[i]) {
            self.next[i] = end(&seg);
        }
        if !self.strip[i] && !acked_only {
            let (dsn, _) = dsn_of(&seg, self.syns[i].seq).expect("mapped");
            self.log.push((now, i, dsn));
            for (k, &b) in seg.payload.iter().enumerate() {
                let slot = &mut self.got[(dsn - self.head) as usize + k];
                if let Some(old) = slot.replace(b) {
                    assert_eq!(old, b, "a copy of DSN {} differs", dsn + k as u64);
                    self.dups += 1;
                }
            }
        }
        let dack = self.dack();
        self.acks.push((now + self.rtts[i], i, self.next[i], dack));
    }
    /// Runs until everything is DATA_ACKed or `until`; returns the time reached.
    fn run(
        &mut self,
        ep: &mut Endpoint<ChaCha20Rng>,
        h: ConnectionHandle,
        mut now: Instant,
        until: Instant,
    ) -> Instant {
        for _ in 0..1_000_000 {
            if !self.feed.is_empty() {
                let n = ep.connection(h).unwrap().write(&self.feed).unwrap();
                self.feed.drain(..n);
            }
            for p in drain(ep, now) {
                self.take(now, leak(p));
            }
            if una(ep, h) == self.head + self.got.len() as u64 {
                return now;
            }
            let next = self.acks.iter().map(|a| a.0).chain(ep.poll_timeout()).min();
            match next {
                Some(t) if t <= until => now = t.max(now),
                _ => return now,
            }
            self.acks.sort_by_key(|a| a.0);
            while self.acks.first().is_some_and(|a| a.0 <= now) {
                let (_, i, ack, dack) = self.acks.remove(0);
                if self.reset[i] || self.drop[i] {
                    continue;
                }
                if self.strip[i] {
                    let seg = Segment {
                        ack,
                        wnd: 65535,
                        ..peer_data(&self.syns[i], 5001, &[], &[])
                    };
                    input_at(ep, &seg, now);
                } else {
                    peer_ack(ep, &self.syns[i], now, ack, dack, 65535);
                }
            }
            if ep.poll_timeout().is_some_and(|t| t <= now) {
                ep.handle_timeout(now);
            }
        }
        panic!("no progress")
    }
}

#[test]
fn per_subflow_mtu_bounds_new_and_reinjected_segments() {
    for (mtu1, mss1) in [(1280u16, 1400u16), (1500, 1200)] {
        let seg1 = usize::from(mss1.min(mtu1 - 40)) - 28;
        // A range first sent on subflow `from`, then reinjected on the other.
        for from in [0, 1] {
            let (mut ep, h, syn, _) = confirmed_cc(reno);
            let (id1, jsyn) = joined_mss(&mut ep, h, ms(10), JOIN_IP, mtu1, 7, mss1);
            let head = una(&ep, h);
            peer_ack(&mut ep, &jsyn, ms(10), jsyn.seq.wrapping_add(1), head, 1000);
            let paths = [
                (&syn, SubflowId(0), 1500, 1432),
                (&jsyn, id1, usize::from(mtu1), seg1),
            ];
            let check = |out: &[Vec<u8>], to: usize| {
                let (s, _, mtu, seg) = paths[to];
                assert!(
                    out.iter().all(|p| leak(p.clone()).src == s.src),
                    "all on {to}"
                );
                assert!(
                    out.iter().all(|p| p.len() <= mtu),
                    "IP packet within MTU {mtu}"
                );
                let data = data_on(out, s);
                assert!(data.iter().all(|d| d.payload.len() <= seg));
                assert!(data.iter().any(|d| d.payload.len() == seg), "full segments");
                data.iter().map(|d| d.payload.len()).sum::<usize>()
            };
            let now = ms(20);
            let head = una(&ep, h);
            // Whole segments within the initial window, so that Nagle holds nothing back.
            let n = 2 * paths[from].3;
            pin(&mut ep, h, Some(paths[from].1));
            ep.connection(h).unwrap().write(&vec![1; n]).unwrap();
            let out = drain(&mut ep, now);
            assert_eq!(check(&out, from), n, "new data on {from}");
            // Subflow-ACKed, not DATA_ACKed: reinjected on the other subflow.
            let last = data_on(&out, paths[from].0).pop().unwrap();
            peer_ack(&mut ep, paths[from].0, now, end(&last), head, 1000);
            queue_reinject(&mut ep, h, head, n as u64);
            pin(&mut ep, h, Some(paths[1 - from].1));
            let out = drain(&mut ep, now);
            assert_eq!(check(&out, 1 - from), n, "reinjected on {}", 1 - from);
        }
    }
}

#[test]
fn connection_window_uses_receiving_subflow_scale() {
    let (mut ep, h, syn, _) = confirmed_cc(reno);
    let (_, jsyn) = joined(&mut ep, h, ms(10), JOIN_IP, 1500, 0);
    let head = una(&ep, h);
    set_edge(&mut ep, h, head);
    peer_ack(&mut ep, &jsyn, ms(20), jsyn.seq.wrapping_add(1), head, 1000);
    assert_eq!(edge(&ep, h), Some(head + 1000), "subflow 1's scale 0");
    ep.connection(h).unwrap().write(&[5; 1000 + 2864]).unwrap();
    let sent =
        |out: Vec<Vec<u8>>| -> usize { out.iter().map(|p| leak(p.clone()).payload.len()).sum() };
    let out = drain(&mut ep, ms(20));
    let dsns = |syn: &Segment| {
        data_on(&out, syn)
            .iter()
            .map(|s| dsn_of(s, syn.seq).unwrap())
            .collect::<Vec<_>>()
    };
    // Capped at the right edge; with data waiting beyond it, the run at the head is also
    // copied to the other subflow (M3 §2.2 window branch).
    assert_eq!(
        [dsns(&syn), dsns(&jsyn)].concat(),
        [(head, 1000), (head, 1000)],
        "capped at the right edge"
    );
    assert_eq!(sent(out), 2000);
    peer_ack(&mut ep, &syn, ms(30), syn.seq.wrapping_add(1), head, 1000);
    assert_eq!(edge(&ep, h), Some(head + 128_000), "subflow 0's scale 7");
    // Subflow 0 was penalized for the copy (M3 §2.5): Reno cwnd 4380 → 2920, 1000 in flight.
    assert_eq!(sent(drain(&mut ep, ms(30))), 1432);
    assert_eq!(ep.connection(h).unwrap().debug_stats().penalties, 1);
}

#[test]
fn two_subflows_split_by_minrtt() {
    let (mut ep, h, syn, jsyn) = two_paths(reno, reno);
    // Subflow 1 is the 10 ms path, subflow 0 the 30 ms one.
    let (t, _) = prime(&mut ep, h, &syn, SubflowId(0), ms(20), 30);
    let (t, _) = prime(&mut ep, h, &jsyn, SubflowId(1), t, 10);
    let n = 400_000;
    let data: Vec<u8> = (0..n).map(|i| (i % 251) as u8).collect();
    let head = una(&ep, h);
    assert_eq!(ep.connection(h).unwrap().write(&data), Ok(n));
    let mut peer = Peer::new(head, n, &[(&syn, 30), (&jsyn, 10)]);
    peer.run(&mut ep, h, t, t + Duration::from_secs(30));
    assert_eq!(una(&ep, h), head + n as u64);
    assert_eq!(peer.received(), data);
    // Both carry mappings; at the first step both have budget and the 10 ms one fills first.
    let first: Vec<usize> = (peer.log.iter())
        .filter(|l| l.0 == t)
        .map(|l| l.1)
        .collect();
    assert_eq!(first[0], 1, "the 10 ms subflow first");
    assert!(first.contains(&0), "then the 30 ms one in the same pass");
    let k = first.iter().position(|&p| p == 0).unwrap();
    assert!(first[k..].iter().all(|&p| p == 0), "{first:?}");
}

#[test]
fn receive_interleaved_across_subflows() {
    let (mut ep, h, syn, dsn) = confirmed();
    let (_, jsyn) = joined(&mut ep, h, ms(10), JOIN_IP, 1500, 7);
    // DSN chunk k of 500 octets goes on subflow k % 2, at that subflow's SSN for it.
    let data: Vec<u8> = (0..4000).map(|i| (i % 251) as u8).collect();
    let mut have = [false; 8];
    let mut now = ms(20);
    let mut acked_on = [0, 0];
    for k in [3, 1, 6, 2, 7, 0, 5, 4] {
        let sf = [&syn, &jsyn][k % 2];
        let ssn = 1 + (k / 2 * 500) as u32;
        let opts = mapping(ssn, dsn + (k * 500) as u64, 500);
        let seg = peer_data(sf, 5000 + ssn, &opts, &data[k * 500..][..500]);
        input_at(&mut ep, &seg, now);
        have[k] = true;
        let prefix = dsn + 500 * have.iter().take_while(|&&b| b).count() as u64;
        for s in drain_until(&mut ep, now, now + Duration::from_millis(500))
            .into_iter()
            .map(leak)
        {
            assert_eq!(dack(&s), prefix, "DATA_ACK: the contiguous prefix");
            acked_on[usize::from(s.src == jsyn.src)] += 1;
        }
        now = now + Duration::from_millis(500);
    }
    assert!(acked_on.iter().all(|&n| n > 0), "{acked_on:?}");
    // Subflow 1's next ACK (here drawn by a probe) carries the whole prefix too.
    let probe = peer_data(&jsyn, 5000 + 2000, &[], &[]);
    input_at(&mut ep, &probe, now);
    let ack = on(&drain(&mut ep, now), &jsyn).pop().expect("ACK");
    assert_eq!(dack(&ack), dsn + 4000);
    let mut out = vec![0; 8000];
    assert_eq!(ep.connection(h).unwrap().read(&mut out), Ok(4000));
    assert_eq!(&out[..4000], &data[..]);
}

/// Records each subflow's latest (TCP ACK, DATA_ACK).
fn note(last: &mut [Option<(SeqNum, u64)>; 2], acks: Vec<(usize, SeqNum, u64)>) {
    for (i, ack, d) in acks {
        last[i] = Some((ack, d));
    }
}
/// Peer data chunk `k` (100 octets at DSN `dsn + 100k`) on subflow `i`, at its next SSN.
fn chunk(
    ep: &mut Endpoint<ChaCha20Rng>,
    syns: [&Segment; 2],
    ssn: &mut [u32; 2],
    (i, k): (usize, usize),
    dsn: u64,
    data: &[u8],
    now: Instant,
) {
    let opts = mapping(ssn[i], dsn + 100 * k as u64, 100);
    let seg = peer_data(syns[i], 5000 + ssn[i], &opts, &data[k * 100..][..100]);
    input_at(ep, &seg, now);
    ssn[i] += 100;
}

#[test]
fn fast_path_runs_ahead_under_range_cap() {
    // Review Focus 5: the fast subflow 1 runs ahead of the slow subflow 0, which holds the
    // head, until the 64-range cap discards its data (subflow-ACKed, not DATA_ACKed).
    let (mut ep, h, syn, dsn) = connected_scaled(32 << 10);
    open_window(&mut ep, &syn, h);
    let (_, fast) = joined(&mut ep, h, ms(10), JOIN_IP, 1500, 7);
    let syns = [&syn, &fast];
    let data: Vec<u8> = (0..20_000).map(|i| (i % 251) as u8).collect();
    let mut ssn = [1, 1];
    let mut now = ms(20);
    let mut last = [None, None];
    let step = |ep: &mut Endpoint<ChaCha20Rng>, ssn: &mut [u32; 2], ik, now: &mut Instant| {
        chunk(ep, syns, ssn, ik, dsn, &data, *now);
        let out = drain_until(ep, *now, *now + Duration::from_millis(300));
        *now = *now + Duration::from_millis(300);
        let acks = out.into_iter().map(leak);
        acks.map(|s| (usize::from(s.src == fast.src), s.ack, dack(&s)))
            .collect::<Vec<_>>()
    };
    for k in (1..200).step_by(2) {
        note(&mut last, step(&mut ep, &mut ssn, (1, k), &mut now));
    }
    let (ack, dack1) = last[1].unwrap();
    assert_eq!(
        ack,
        SeqNum(5001 + 100 * 100),
        "every fast octet subflow-ACKed"
    );
    assert_eq!(dack1, dsn, "the head is missing");
    for k in (0..200).step_by(2) {
        note(&mut last, step(&mut ep, &mut ssn, (0, k), &mut now));
    }
    // Odd chunks 1..=127 were held (64 ranges); 129 and later were discarded.
    assert_eq!(
        last[0].unwrap().1,
        dsn + 12_900,
        "progress up to the first discard"
    );
    // The peer's connection-level retransmission of the discarded chunks, on the fast path.
    for k in (129..200).step_by(2) {
        note(&mut last, step(&mut ep, &mut ssn, (1, k), &mut now));
    }
    assert_eq!(last[1].unwrap().1, dsn + 20_000);
    let mut out = vec![0; 40_000];
    assert_eq!(ep.connection(h).unwrap().read(&mut out), Ok(20_000));
    assert_eq!(&out[..20_000], &data[..]);
}

#[test]
fn standalone_data_fin_moves_to_surviving_subflow() {
    let (mut ep, h, syn, jsyn) = two_paths(reno, reno);
    let (t, _) = prime(&mut ep, h, &syn, SubflowId(0), ms(20), 30);
    let (t, _) = prime(&mut ep, h, &jsyn, SubflowId(1), t, 10);
    drain(&mut ep, t);
    ep.connection(h).unwrap().close();
    let fins = |out: &[Vec<u8>]| -> Vec<Segment<'static>> {
        let all = out.iter().map(|p| leak(p.clone()));
        all.filter(data_fin).collect()
    };
    let fin = fins(&drain(&mut ep, t));
    assert_eq!(fin.len(), 1);
    assert_eq!(
        fin[0].src, jsyn.src,
        "standalone DATA_FIN on the lowest-RTT subflow"
    );
    assert!(fin[0].payload.is_empty());
    // The peer resets subflow 1 before acknowledging it: the resend goes out on subflow 0.
    let rst = Segment {
        flags: TcpFlags::RST | TcpFlags::ACK,
        ..peer_data(&jsyn, 5001, &[], &[])
    };
    let t1 = t + Duration::from_millis(1);
    input_at(&mut ep, &rst, t1);
    assert!(events(&mut ep).contains(&Event::SubflowDown {
        subflow: SubflowId(1),
        reason: CloseReason::Reset,
        rst: None
    }));
    let mut resent = Vec::new();
    while let Some(due) = ep
        .poll_timeout()
        .filter(|&d| d < t + Duration::from_secs(10))
    {
        ep.handle_timeout(due);
        resent.extend(fins(&drain(&mut ep, due)));
        if !resent.is_empty() {
            break;
        }
    }
    assert_eq!(resent.len(), 1);
    assert_eq!(resent[0].src, syn.src, "resent on the surviving subflow");
}

#[test]
fn zero_window_probe_demand_per_subflow() {
    let (mut ep, h, syn, jsyn) = two_paths(reno, reno);
    let (t, una0) = prime(&mut ep, h, &syn, SubflowId(0), ms(20), 30);
    let (t, una1) = prime(&mut ep, h, &jsyn, SubflowId(1), t, 10);
    // Payload-free segments one below the subflow's SND.UNA.
    let probes = |out: &[Vec<u8>], syn: &Segment, una: SeqNum| {
        let all = on(out, syn).into_iter();
        all.filter(|s| s.payload.is_empty() && s.seq == una.wrapping_add(u32::MAX))
            .count()
    };
    // The connection window is closed, both subflow windows open, both subflows idle.
    let next = ep.conns[&h].hooks.data.as_ref().unwrap().send.next;
    set_edge(&mut ep, h, next);
    ep.connection(h).unwrap().write(&[1; 5000]).unwrap();
    let t2 = t + Duration::from_secs(5);
    let out = drain_until(&mut ep, t, t2);
    assert!(out.iter().all(|p| leak(p.clone()).payload.is_empty()));
    assert_eq!(probes(&out, &syn, una0), 0, "one probe suffices");
    assert!(
        probes(&out, &jsyn, una1) > 0,
        "the lowest-RTT idle subflow probes"
    );
    // The connection window opens, but each subflow's own window is zero: each probes.
    set_edge(&mut ep, h, next + (1 << 20));
    let head = una(&ep, h);
    peer_ack(&mut ep, &syn, t2, una0, head, 0);
    peer_ack(&mut ep, &jsyn, t2, una1, head, 0);
    let out = drain_until(&mut ep, t2, t2 + Duration::from_secs(5));
    assert!(out.iter().all(|p| leak(p.clone()).payload.is_empty()));
    assert!(
        probes(&out, &syn, una0) > 0,
        "subflow 0 probes its own window"
    );
    assert!(
        probes(&out, &jsyn, una1) > 0,
        "subflow 1 probes its own window"
    );
}

#[test]
fn joined_subflow_stripping_resets_only_it() {
    let (mut ep, h, syn, jsyn) = two_paths(reno, reno);
    let head = una(&ep, h);
    let n = 100_000;
    let data: Vec<u8> = (0..n).map(|i| (i % 251) as u8).collect();
    assert_eq!(ep.connection(h).unwrap().write(&data), Ok(n));
    // The first flight goes on subflow 1, whose path strips options.
    pin(&mut ep, h, Some(SubflowId(1)));
    let now = ms(20);
    let first = drain(&mut ep, now);
    assert!(!data_on(&first, &jsyn).is_empty() && data_on(&first, &syn).is_empty());
    pin(&mut ep, h, None);
    let mut peer = Peer::new(head, n, &[(&syn, 30), (&jsyn, 10)]);
    peer.strip[1] = true;
    for p in first {
        peer.take(now, leak(p));
    }
    peer.run(&mut ep, h, now, now + Duration::from_secs(120));
    assert_eq!(
        una(&ep, h),
        head + n as u64,
        "the transfer completes on subflow 0"
    );
    assert_eq!(peer.received(), data);
    let ev = events(&mut ep);
    assert!(ev.contains(&Event::SubflowDown {
        subflow: SubflowId(1),
        reason: CloseReason::Reset,
        rst: None
    }));
    assert!(!ev.contains(&Event::FellBack), "{ev:?}");
    assert_eq!(state(&ep, h), State::Confirmed);
    let rst = (peer.sent.iter())
        .position(|(_, s)| s.flags.contains(TcpFlags::RST))
        .expect("RST");
    assert!(
        peer.sent
            .iter()
            .all(|(i, s)| !s.flags.contains(TcpFlags::RST) || *i == 1)
    );
    assert!(
        peer.sent[rst..]
            .iter()
            .all(|(i, s)| s.payload.is_empty() || *i == 0)
    );
    assert!(
        !peer.sent.iter().any(|(_, s)| infinite_mapping(s)),
        "no infinite mapping"
    );
    // Subflow 1's first stripped ACK resets it; what it had in flight goes out on subflow 0
    // at that moment, not after a rule-5 timeout.
    assert_eq!(moved_at(&peer, 1, 0), Some(now + Duration::from_millis(10)));
}

#[test]
fn full_mapping_slots_exclude_subflow() {
    let (mut ep, h, syn, jsyn) = two_paths(reno, reno);
    let (t, _) = prime(&mut ep, h, &syn, SubflowId(0), ms(20), 10);
    let (t, _) = prime(&mut ep, h, &jsyn, SubflowId(1), t, 30);
    ep.connection(h).unwrap().set_nodelay(true);
    // The pending reinjection: a range subflow-ACKed on subflow 1, not DATA_ACKed.
    let head = una(&ep, h);
    pin(&mut ep, h, Some(SubflowId(1)));
    ep.connection(h).unwrap().write(&[8; 100]).unwrap();
    let r = data_on(&drain(&mut ep, t), &jsyn).pop().unwrap();
    peer_ack(&mut ep, &jsyn, t, end(&r), head, 65535);
    // MinRTT fills the lowest-RTT subflow 0's mapping slots.
    let (log, _) = install_probe(&mut ep, h);
    for i in 0..1024u32 {
        ep.connection(h).unwrap().write(&[i as u8]).unwrap();
        assert_eq!(data_on(&drain(&mut ep, t), &syn).len(), 1);
    }
    assert!(ep.conns[&h].subflows[0].mp.tx.is_full());
    queue_reinject(&mut ep, h, head, 100);
    ep.connection(h).unwrap().write(&[9; 100]).unwrap();
    let out = drain(&mut ep, t);
    assert!(data_on(&out, &syn).is_empty(), "no slot on subflow 0");
    let on1 = data_on(&out, &jsyn);
    assert_eq!(
        dsn_of(&on1[0], jsyn.seq),
        Some((head, 100)),
        "the reinjection"
    );
    assert_eq!(on1[1].payload, [9; 100], "the new data");
    let log = log.lock().unwrap();
    let n = log.assigned.len();
    assert_eq!(
        log.assigned[n - 2..],
        [(SubflowId(1), 100, true), (SubflowId(1), 100, false)]
    );
    assert_eq!(ep.conns[&h].hooks.assign_failures, 0);
}

#[test]
fn all_subflows_full_resume_on_ack() {
    let (mut ep, h, syn, jsyn) = two_paths(reno, reno);
    let (t, _) = prime(&mut ep, h, &syn, SubflowId(0), ms(20), 10);
    let (t, _) = prime(&mut ep, h, &jsyn, SubflowId(1), t, 30);
    ep.connection(h).unwrap().set_nodelay(true);
    let (log, _) = install_probe(&mut ep, h);
    let mut first1 = None;
    for i in 0..2048u32 {
        ep.connection(h).unwrap().write(&[i as u8]).unwrap();
        let out = drain(&mut ep, t);
        assert_eq!(data_on(&out, &syn).len() + data_on(&out, &jsyn).len(), 1);
        first1 = first1.or(data_on(&out, &jsyn).first().map(|s| s.seq));
    }
    let c = &ep.conns[&h];
    assert!(c.subflows.iter().all(|sf| sf.mp.tx.is_full()));
    ep.connection(h).unwrap().write(&[9; 100]).unwrap();
    let plans = log.lock().unwrap().plans.len();
    assert!(drain(&mut ep, t).is_empty(), "nothing emitted");
    assert_eq!(log.lock().unwrap().plans.len(), plans, "plan is not called");
    assert_eq!(ep.conns[&h].hooks.assign_failures, 0);
    // A TCP ACK frees one slot on subflow 1: assignment resumes there.
    let head = una(&ep, h);
    peer_ack(
        &mut ep,
        &jsyn,
        t,
        first1.unwrap().wrapping_add(1),
        head,
        65535,
    );
    let out = data_on(&drain(&mut ep, t), &jsyn);
    assert_eq!(out.last().unwrap().payload, [9; 100]);
    assert_eq!(
        log.lock().unwrap().assigned.last(),
        Some(&(SubflowId(1), 100, false))
    );
    assert_eq!(ep.conns[&h].hooks.assign_failures, 0);
}

#[test]
fn connection_window_exhausted_is_not_app_limited_two_subflows() {
    clear_samples();
    let n = 50_000;
    let (mut ep, h, syn, jsyn, head, data) = two_paths_queued(recording, recording_b, n);
    // Both subflows have budget; the connection window admits two segments.
    set_edge(&mut ep, h, head + 2864);
    let now = ms(20);
    let mut buf = [0; 1500];
    let k = ep.poll_transmit(now, &mut buf).expect("first segment");
    let mut sent = vec![buf[..k].to_vec()];
    assert_eq!(
        ep.conns[&h].hooks.data.as_ref().unwrap().send.next,
        head + 2864
    );
    assert!(ep.conns[&h].subflows[1].mp.offered_unused, "B passed over");
    // The next step has zero budgets: receiver-limited, so B is not marked.
    sent.extend(drain(&mut ep, now));
    for sf in &ep.conns[&h].subflows {
        assert!(!sf.mp.offered_unused, "flag cleared");
        assert_eq!(sf.tcb.app_limited(), None);
    }
    // From here on the transfer is window- or cwnd-limited: no sample is app-limited.
    let mut peer = Peer::new(head, n, &[(&syn, 10), (&jsyn, 30)]);
    for p in sent {
        peer.take(now, leak(p));
    }
    peer.run(&mut ep, h, now, now + Duration::from_secs(30));
    assert_eq!(peer.received(), data);
    let (a, b) = (sample_flags(false), sample_flags(true));
    assert!(!a.is_empty() && !b.is_empty(), "both subflows carried data");
    assert!(a.iter().chain(&b).all(|&f| !f), "{a:?} {b:?}");
}

/// Acknowledges at both levels everything `out` carried on `syn`'s subflow.
fn ack_all(ep: &mut Endpoint<ChaCha20Rng>, syn: &Segment, out: &[Vec<u8>], now: Instant) {
    let last = data_on(out, syn).pop().unwrap();
    let (dsn, _) = dsn_of(&last, syn.seq).unwrap();
    peer_ack(
        ep,
        syn,
        now,
        end(&last),
        dsn + last.payload.len() as u64,
        65535,
    );
}

#[test]
fn unchosen_subflow_marked_while_other_sends() {
    clear_samples();
    let (mut ep, h, syn, jsyn, _, _) = two_paths_queued(big_a, big_b, 4 << 20);
    let (log, rogue) = install_probe(&mut ep, h);
    *rogue.lock().unwrap() = Some(Rogue::Pin(SubflowId(0)));
    let mut now = ms(20);
    for _ in 0..3 {
        let before = log.lock().unwrap().assigned.len();
        let out = drain(&mut ep, now);
        let assigned = log.lock().unwrap().assigned[before..].to_vec();
        assert!(assigned.len() >= 2, "several plans: {assigned:?}");
        assert!(assigned.iter().all(|a| a.0 == SubflowId(0)));
        let c = &ep.conns[&h];
        assert_eq!(
            c.subflows[0].tcb.app_limited(),
            None,
            "A had no opportunity left"
        );
        assert_eq!(
            c.subflows[1].tcb.app_limited(),
            Some(AppLimited::NotScheduled)
        );
        now = now + Duration::from_millis(10);
        ack_all(&mut ep, &syn, &out, now);
    }
    assert_eq!(ep.conns[&h].hooks.rejected_plans, 0);
    // B sends while still marked: its ACK sample is app-limited; A's never were.
    *rogue.lock().unwrap() = Some(Rogue::Pin(SubflowId(1)));
    let out = drain(&mut ep, now);
    ack_all(&mut ep, &jsyn, &out, now + Duration::from_millis(10));
    let (a, b) = (sample_flags(false), sample_flags(true));
    assert!(!a.is_empty() && a.iter().all(|&f| !f), "{a:?}");
    assert!(b.contains(&true), "{b:?}");
}

fn sampler_marked(ep: &Endpoint<ChaCha20Rng>, h: ConnectionHandle, k: usize) -> bool {
    ep.conns[&h].subflows[k].tcb.sampler().is_app_limited()
}

/// Spec §1.6: a subflow offered data and given none (`AppLimited::NotScheduled`) is
/// app-limited for its own sampler.
#[test]
fn not_scheduled_marks_app_limited() {
    // MinRTT prefers A (the first on equal RTTs) and gives it all the data; B is passed over.
    let (mut ep, h, syn, jsyn, _, _) = two_paths_queued(recording, recording_b, 1000);
    assert!(!sampler_marked(&ep, h, 1));
    let out = drain(&mut ep, ms(20));
    assert_eq!(data_on(&out, &syn).len(), 1);
    assert!(data_on(&out, &jsyn).is_empty());
    assert!(sampler_marked(&ep, h, 1));
    // Pinned to A with data still queued for the connection: only being passed over marks B.
    let (mut ep, h, ..) = two_paths_queued(big_a, big_b, 4 << 20);
    let (_, rogue) = install_probe(&mut ep, h);
    *rogue.lock().unwrap() = Some(Rogue::Pin(SubflowId(0)));
    assert!(!sampler_marked(&ep, h, 1));
    drain(&mut ep, ms(20));
    let d = ep.conns[&h].hooks.data.as_ref().unwrap();
    assert!(d.send.next != d.send.end, "data still queued");
    assert!(sampler_marked(&ep, h, 1));
}

/// A pass interrupted by an input is not over: a subflow passed over in its last step may be
/// filled in the next one (MinRTT moves on once A's budget is spent), so nothing is marked
/// mid-pass. Marking there froze path B's CUBIC cwnd under the TUN client (Task 9c).
#[test]
fn interrupted_pass_marks_no_subflow() {
    for pinned in [true, false] {
        clear_samples();
        let (mut ep, h, syn, jsyn, _, _) = two_paths_queued(recording, recording_b, 1 << 20);
        let (_, rogue) = install_probe(&mut ep, h);
        *rogue.lock().unwrap() = pinned.then_some(Rogue::Pin(SubflowId(0)));
        let mut now = ms(20);
        let mut buf = [0; 1500];
        // As the TUN client does: one `poll_transmit`, then the next input.
        for i in 0..40 {
            let k = ep.poll_transmit(now, &mut buf).expect("A has budget");
            let seg = leak(buf[..k].to_vec());
            assert_eq!(seg.src, syn.src);
            let (dsn, _) = dsn_of(&seg, syn.seq).unwrap();
            now = now + Duration::from_millis(1);
            peer_ack(
                &mut ep,
                &syn,
                now,
                end(&seg),
                dsn + seg.payload.len() as u64,
                65535,
            );
            let c = &ep.conns[&h];
            assert_eq!(c.subflows[0].tcb.app_limited(), None, "A, step {i}");
            assert_eq!(c.subflows[1].tcb.app_limited(), None, "B, step {i}");
            assert!(c.subflows[1].mp.offered_unused, "B passed over, step {i}");
        }
        // The pass runs to its end: MinRTT fills B once A's cwnd is full, so B's sends and
        // their ACK samples are not app-limited; pinned to A, B is passed over at the end.
        let out = drain(&mut ep, now);
        let b = ep.conns[&h].subflows[1].tcb.app_limited();
        if pinned {
            assert_eq!(b, Some(AppLimited::NotScheduled));
        } else {
            assert_eq!(b, None);
            ack_all(&mut ep, &jsyn, &out, now + Duration::from_millis(30));
            let b = sample_flags(true);
            assert!(!b.is_empty() && b.iter().all(|&f| !f), "{b:?}");
        }
    }
}

#[test]
fn minrtt_filling_second_subflow_in_same_pass_not_marked() {
    clear_samples();
    let (mut ep, h, syn, jsyn, head, _) = two_paths_queued(recording, recording_b, 1 << 20);
    let now = ms(20);
    let out = drain(&mut ep, now);
    let (a, b) = (data_on(&out, &syn), data_on(&out, &jsyn));
    assert!(!a.is_empty() && !b.is_empty(), "both filled in one pass");
    assert_eq!(dsn_of(&a[0], syn.seq).unwrap().0, head, "A first");
    let a_end = dsn_of(a.last().unwrap(), syn.seq).unwrap().0;
    assert!(
        b.iter().all(|s| dsn_of(s, jsyn.seq).unwrap().0 > a_end),
        "then B"
    );
    for sf in &ep.conns[&h].subflows {
        assert_eq!(sf.tcb.app_limited(), None);
        assert!(!sf.mp.offered_unused);
    }
    let t1 = now + Duration::from_millis(10);
    ack_all(&mut ep, &syn, &out, t1);
    ack_all(&mut ep, &jsyn, &out, t1);
    let (a, b) = (sample_flags(false), sample_flags(true));
    assert!(!a.is_empty() && !b.is_empty());
    assert!(a.iter().chain(&b).all(|&f| !f), "{a:?} {b:?}");
}

#[test]
fn set_nodelay_reaches_every_subflow() {
    let (mut ep, h, _, _) = confirmed();
    joined(&mut ep, h, ms(10), JOIN_IP, 1500, 7);
    ep.connection(h).unwrap().set_nodelay(true);
    joined(&mut ep, h, ms(10), "10.0.2.1", 1500, 7);
    let c = &ep.conns[&h];
    assert_eq!(c.subflows.len(), 3);
    for sf in &c.subflows {
        assert!(
            format!("{:?}", sf.tcb).contains("nodelay: true"),
            "{:?}",
            sf.id
        );
    }
}

#[test]
fn rule5_counts_copies_on_every_active_subflow() {
    let (mut ep, h, syn, jsyn) = two_paths(reno, reno);
    let head = una(&ep, h);
    let now = ms(20);
    // A = one segment on subflow 0, subflow-ACKed there without DATA_ACK.
    pin(&mut ep, h, Some(SubflowId(0)));
    ep.connection(h).unwrap().write(&[1; 1432]).unwrap();
    let a = data_on(&drain(&mut ep, now), &syn).pop().unwrap();
    peer_ack(&mut ep, &syn, now, end(&a), head, 1000);
    // A's reinjected copy, in flight on subflow 1, covers the head: no rule-5 timer.
    queue_reinject(&mut ep, h, head, 1432);
    pin(&mut ep, h, Some(SubflowId(1)));
    let copy = data_on(&drain(&mut ep, now), &jsyn).pop().unwrap();
    assert_eq!(dsn_of(&copy, jsyn.seq), Some((head, 1432)));
    peer_ack(&mut ep, &syn, now, end(&a), head, 1000);
    drain(&mut ep, now);
    assert_eq!(
        ep.conns[&h].hooks.recovery_deadline(),
        None,
        "a copy is in flight"
    );
    // B in flight on subflow 1; the copy of A subflow-ACKed there.
    ep.connection(h).unwrap().write(&[2; 1432]).unwrap();
    assert_eq!(data_on(&drain(&mut ep, now), &jsyn).len(), 1);
    let t1 = now + Duration::from_millis(10);
    peer_ack(&mut ep, &jsyn, t1, end(&copy), head, 1000);
    let due = ep.conns[&h]
        .hooks
        .recovery_deadline()
        .expect("head uncovered");
    // Inputs on either subflow and polls do not move the deadline.
    for (i, s) in [&syn, &jsyn, &syn].into_iter().enumerate() {
        let t = t1 + Duration::from_millis(1 + i as u64);
        let ack = if s.src == syn.src {
            end(&a)
        } else {
            end(&copy)
        };
        peer_ack(&mut ep, s, t, ack, head, 1000);
        drain(&mut ep, t);
        assert_eq!(ep.conns[&h].hooks.recovery_deadline(), Some(due));
    }
    // At expiry only the uncovered head run is queued, not B's live copy.
    ep.handle_timeout(due);
    assert_eq!(queue_first(&ep, h), Some((head, 1432)));
}

#[test]
fn read_window_update_on_lowest_rtt_subflow_with_largest_mss() {
    let (mut ep, h, syn, dsn) = connected_scaled_cc(8192, Some(reno));
    open_window(&mut ep, &syn, h);
    // Subflow 1's effective MSS is 1240 (MTU 1280), subflow 0's 1460.
    let (_, jsyn) = joined(&mut ep, h, ms(10), JOIN_IP, 1280, 7);
    let (t, _) = prime(&mut ep, h, &syn, SubflowId(0), ms(20), 30);
    let (t, _) = prime(&mut ep, h, &jsyn, SubflowId(1), t, 10);
    // The peer fills the 8 KiB receive buffer on subflow 0.
    for k in 0..8u32 {
        let opts = mapping(1 + k * 1024, dsn + u64::from(k) * 1024, 1024);
        let payload = [k as u8; 1024];
        let seg = peer_data(&syn, 5001 + k * 1024, &opts, &payload);
        input_at(&mut ep, &seg, t);
    }
    let t0 = t;
    let t = t + Duration::from_secs(1);
    let acks = on(&drain_until(&mut ep, t0, t), &syn);
    assert_eq!(acks.last().unwrap().wnd, 0, "window closed");
    let mut buf = [0; 1500];
    assert_eq!(ep.connection(h).unwrap().read(&mut buf[..1300]), Ok(1300));
    assert!(
        drain(&mut ep, t).is_empty(),
        "1300 freed: below the largest effective MSS 1460"
    );
    assert_eq!(ep.connection(h).unwrap().read(&mut buf[..200]), Ok(200));
    let out = drain(&mut ep, t);
    assert_eq!(out.len(), 1);
    let update = leak(out[0].clone());
    assert_eq!(update.src, jsyn.src, "on the lowest-RTT subflow");
    assert!(update.wnd > 0);
}

// M2 Task 6: health, Stale and reinjection on subflow loss.

/// Two Reno subflows with RTT samples (subflow 0: 30 ms, subflow 1: 10 ms) and subflow 1's
/// data R2 `r2`; the peer models both paths for `n` octets from the head, written by the
/// test. Returns the time the samples end, the head and the data.
fn two_paths_primed(
    r2: Duration,
    n: usize,
) -> (
    Endpoint<ChaCha20Rng>,
    ConnectionHandle,
    Peer,
    Instant,
    u64,
    Vec<u8>,
) {
    let (mut ep, h, syn, _) = confirmed_cc(reno);
    ep.conns.get_mut(&h).unwrap().cfg.r2_data = r2;
    ep.cc = Some(reno);
    let (_, jsyn) = joined(&mut ep, h, ms(10), JOIN_IP, 1500, 7);
    let (t, _) = prime(&mut ep, h, &syn, SubflowId(0), ms(20), 30);
    let (t, _) = prime(&mut ep, h, &jsyn, SubflowId(1), t, 10);
    events(&mut ep);
    let head = una(&ep, h);
    let data = (0..n).map(|i| (i % 251) as u8).collect();
    (
        ep,
        h,
        Peer::new(head, n, &[(&syn, 30), (&jsyn, 10)]),
        t,
        head,
        data,
    )
}
/// The earliest time the peer placed, from path `to`, an octet first sent on path `from`.
fn moved_at(peer: &Peer, from: usize, to: usize) -> Option<Instant> {
    let sent: Vec<(u64, u64)> = (peer.sent.iter())
        .filter(|(i, s)| *i == from && !s.payload.is_empty())
        .map(|(_, s)| {
            let (dsn, _) = dsn_of(s, peer.syns[from].seq).unwrap();
            (dsn, s.payload.len() as u64)
        })
        .collect();
    (peer.log.iter())
        .filter(|l| l.1 == to && sent.iter().any(|&(d, n)| l.2.wrapping_sub(d) < n))
        .map(|l| l.0)
        .min()
}
fn count(ev: &[Event], e: Event) -> usize {
    ev.iter().filter(|&&x| x == e).count()
}
const STALE1: Event = Event::SubflowStale {
    subflow: SubflowId(1),
};
const R100: Duration = Duration::from_secs(100);

#[test]
fn blackholed_subflow_goes_stale_and_data_reinjected() {
    let n = 200_000;
    let (mut ep, h, mut peer, t, head, data) = two_paths_primed(R100, n);
    peer.drop[1] = true;
    assert_eq!(ep.connection(h).unwrap().write(&data), Ok(n));
    // RTOs (1 s minimum) at t + 1, 3 and 7 s; the third makes subflow 1 Stale.
    let now = peer.run(&mut ep, h, t, t + Duration::from_millis(6999));
    let mut ev = events(&mut ep);
    assert_eq!(count(&ev, STALE1), 0, "{ev:?}");
    assert!(una(&ep, h) < head + n as u64, "subflow 1 holds a hole");
    assert_eq!(moved_at(&peer, 1, 0), None);
    let now = peer.run(&mut ep, h, now, t + Duration::from_secs(30));
    ev.extend(events(&mut ep));
    assert_eq!(ev, vec![STALE1], "Stale once, nothing else");
    assert_eq!(ep.conns[&h].subflows[1].state, SubflowState::Stale);
    assert_eq!(
        moved_at(&peer, 1, 0),
        Some(t + Duration::from_secs(7)),
        "re-sent on subflow 0 at the third RTO"
    );
    assert!(now < t + Duration::from_secs(8));
    assert_eq!(una(&ep, h), head + n as u64);
    assert_eq!(peer.received(), data, "byte-exact");
    assert_eq!(peer.dups, 0, "no octet reached the peer twice");
}

#[test]
fn stale_subflow_recovers_on_progress() {
    let (n1, n) = (200_000, 400_000);
    let (mut ep, h, mut peer, t, head, data) = two_paths_primed(R100, n);
    peer.drop[1] = true;
    assert_eq!(ep.connection(h).unwrap().write(&data[..n1]), Ok(n1));
    let now = peer.run(&mut ep, h, t, t + Duration::from_millis(7500));
    assert_eq!(events(&mut ep), vec![STALE1]);
    assert_eq!(
        una(&ep, h),
        head + n1 as u64,
        "the first part went via subflow 0"
    );
    // Traffic restored: subflow 1's own retransmission at t + 15 s (RTO 8 s) gets through.
    peer.drop[1] = false;
    let now = peer.run(&mut ep, h, now, t + Duration::from_secs(16));
    let recovered = Event::SubflowRecovered {
        subflow: SubflowId(1),
    };
    assert_eq!(events(&mut ep), vec![recovered]);
    assert_eq!(ep.conns[&h].subflows[1].state, SubflowState::Active);
    assert!(
        peer.dups > 0,
        "its copies of re-sent data arrived as duplicates"
    );
    // Scheduled again: the lowest-RTT subflow takes the first new mapping.
    assert_eq!(ep.connection(h).unwrap().write(&data[n1..]), Ok(n - n1));
    peer.run(&mut ep, h, now, t + Duration::from_secs(60));
    assert_eq!(peer.received(), data, "byte-exact, no corruption");
    let first = (peer.log.iter()).find(|l| l.2 >= head + n1 as u64).unwrap();
    assert_eq!(first.1, 1, "new data on subflow 1 again");
    assert!(events(&mut ep).is_empty());
}

#[test]
fn r2_teardown_reinjects() {
    let n = 200_000;
    let (mut ep, h, mut peer, t, head, data) = two_paths_primed(Duration::from_secs(3), n);
    peer.drop[1] = true;
    assert_eq!(ep.connection(h).unwrap().write(&data), Ok(n));
    let r2 = t + Duration::from_secs(3);
    peer.run(&mut ep, h, t, t + Duration::from_secs(30));
    let ev = events(&mut ep);
    let down = Event::SubflowDown {
        subflow: SubflowId(1),
        reason: CloseReason::Timeout,
        rst: None,
    };
    assert_eq!(ev, vec![down], "R2 before R1: no Stale");
    let rst = |p: &(usize, Segment)| p.0 == 1 && p.1.flags.contains(TcpFlags::RST);
    assert!(peer.sent.iter().any(rst), "subflow 1 reset");
    assert_eq!(
        moved_at(&peer, 1, 0),
        Some(r2),
        "re-sent on subflow 0 at R2, before any rule-5 timer"
    );
    assert_eq!(una(&ep, h), head + n as u64);
    assert_eq!(peer.received(), data);
}

#[test]
fn both_subflows_stale_bounded() {
    // Review Focus 4.
    let n = 200_000;
    let (mut ep, h, mut peer, t, head, data) = two_paths_primed(R100, n);
    peer.drop = vec![true, true];
    assert_eq!(ep.connection(h).unwrap().write(&data), Ok(n));
    let bounded = |ep: &Endpoint<ChaCha20Rng>| {
        let d = ep.conns[&h].hooks.data.as_ref().unwrap();
        let queued = d.reinject.total_len();
        assert!(queued <= d.send.next - d.send.una, "{queued} queued");
    };
    let mut buf = [0; 1500];
    let mut now = t;
    let mut steps = 0;
    while now < t + Duration::from_secs(30) {
        // Every pass ends: `poll_transmit` returns `None` within a few calls.
        let mut calls = 0;
        while let Some(k) = ep.poll_transmit(now, &mut buf) {
            peer.take(now, leak(buf[..k].to_vec()));
            calls += 1;
            assert!(calls < 64, "poll_transmit spins at {now:?}");
        }
        bounded(&ep);
        let next = ep.poll_timeout().expect("a timer runs");
        assert!(next > now || steps == 0, "timer stuck at {now:?}");
        now = next;
        ep.handle_timeout(now);
        bounded(&ep);
        steps += 1;
        assert!(steps < 200, "too many wake-ups");
    }
    let ev = events(&mut ep);
    let stale0 = Event::SubflowStale {
        subflow: SubflowId(0),
    };
    assert_eq!((count(&ev, stale0), count(&ev, STALE1)), (1, 1), "{ev:?}");
    // Path 0 returns: the transfer completes.
    peer.drop[0] = false;
    peer.run(&mut ep, h, now, t + Duration::from_secs(120));
    bounded(&ep);
    let recovered = Event::SubflowRecovered {
        subflow: SubflowId(0),
    };
    assert!(events(&mut ep).contains(&recovered));
    assert_eq!(una(&ep, h), head + n as u64);
    assert_eq!(peer.received(), data);
}

#[test]
fn reinjection_dedup_against_inflight_copy() {
    let (mut ep, h, peer, t, head, _) = two_paths_primed(R100, 0);
    let (syn, jsyn) = (&peer.syns[0], &peer.syns[1]);
    // Two segments on the 10 ms subflow 1, lost; it goes Stale at t + 7 s and both ranges are
    // re-sent on subflow 0, where the copies are still in flight ...
    ep.connection(h).unwrap().write(&[1; 2 * 1432]).unwrap();
    assert_eq!(data_on(&drain(&mut ep, t), jsyn).len(), 2);
    let stale = t + Duration::from_secs(7);
    let copies = data_on(
        &drain_until(&mut ep, t, stale + Duration::from_millis(1)),
        syn,
    );
    assert_eq!(events(&mut ep), vec![STALE1]);
    let dsns: Vec<_> = (copies.iter())
        .map(|s| (dsn_of(s, syn.seq).unwrap().0, s.payload.len()))
        .collect();
    assert_eq!(dsns, [(head, 1432), (head + 1432, 1432)]);
    assert_eq!(queue_first(&ep, h), None);
    // ... when the peer resets subflow 1: its teardown queues nothing.
    let rst = Segment {
        flags: TcpFlags::RST | TcpFlags::ACK,
        ..peer_data(jsyn, 5001, &[], &[])
    };
    input_at(&mut ep, &rst, stale + Duration::from_millis(1));
    assert!(events(&mut ep).contains(&Event::SubflowDown {
        subflow: SubflowId(1),
        reason: CloseReason::Reset,
        rst: None
    }));
    let d = ep.conns[&h].hooks.data.as_ref().unwrap();
    assert_eq!(d.reinject.total_len(), 0, "not queued twice");
}

#[test]
fn joined_subflow_stripping_via_dup_ack_resets_only_it() {
    let (mut ep, h, syn, jsyn) = two_paths(reno, reno);
    let head = una(&ep, h);
    let n = 20_000;
    let data: Vec<u8> = (0..n).map(|i| (i % 251) as u8).collect();
    assert_eq!(ep.connection(h).unwrap().write(&data), Ok(n));
    pin(&mut ep, h, Some(SubflowId(1)));
    let now = ms(20);
    let first = drain(&mut ep, now);
    let segs = data_on(&first, &jsyn);
    assert!(segs.len() > 1 && data_on(&first, &syn).is_empty());
    pin(&mut ep, h, None);
    // The first segment is TCP-ACKed with a DATA_ACK that releases nothing (beyond SND.NXT) ...
    let t1 = now + Duration::from_millis(10);
    peer_ack(&mut ep, &jsyn, t1, end(&segs[0]), head + (1 << 40), 65535);
    // ... then a duplicate ACK without any MPTCP option: the path strips options.
    let dup = Segment {
        ack: end(&segs[0]),
        wnd: 65535,
        ..peer_data(&jsyn, 5001, &[], &[])
    };
    input_at(&mut ep, &dup, t1);
    let out = drain(&mut ep, t1);
    let ev = events(&mut ep);
    assert!(ev.contains(&Event::SubflowDown {
        subflow: SubflowId(1),
        reason: CloseReason::Reset,
        rst: None
    }));
    assert!(!ev.contains(&Event::FellBack), "{ev:?}");
    assert_eq!(state(&ep, h), State::Confirmed);
    let all: Vec<_> = out.iter().map(|p| leak(p.clone())).collect();
    assert!(
        all.iter()
            .any(|s| s.src == jsyn.src && s.flags.contains(TcpFlags::RST))
    );
    assert!(!all.iter().any(infinite_mapping), "no infinite mapping");
    // Subflow 1's in-flight data goes out on subflow 0 at once, without an RTO wait.
    let (dsn1, _) = dsn_of(&segs[1], jsyn.seq).unwrap();
    assert!(
        (data_on(&out, &syn).iter()).any(|s| dsn_of(s, syn.seq).unwrap().0 == dsn1),
        "reinjected at the reset"
    );
    let mut peer = Peer::new(head, n, &[(&syn, 30), (&jsyn, 10)]);
    peer.reset[1] = true;
    for s in all {
        peer.take(t1, s);
    }
    peer.run(&mut ep, h, t1, t1 + Duration::from_secs(30));
    assert_eq!(
        una(&ep, h),
        head + n as u64,
        "the transfer continues on subflow 0"
    );
    assert_eq!(peer.received(), data);
    assert!(!events(&mut ep).contains(&Event::FellBack));
}

#[test]
fn rule5_uses_unbacked_off_rto_of_healthy_subflow() {
    // Carried ruling R15.
    let (mut ep, h, syn, jsyn) = two_paths(reno, reno);
    let (t, una0) = prime(&mut ep, h, &syn, SubflowId(0), ms(20), 30);
    let (t, _) = prime(&mut ep, h, &jsyn, SubflowId(1), t, 10);
    let head = una(&ep, h);
    // B on subflow 1: the peer gets it and DATA_ACKs it on subflow 0; subflow 1's ACKs are lost.
    pin(&mut ep, h, Some(SubflowId(1)));
    ep.connection(h).unwrap().write(&[1; 100]).unwrap();
    assert_eq!(data_on(&drain(&mut ep, t), &jsyn).len(), 1);
    peer_ack(
        &mut ep,
        &syn,
        t + Duration::from_millis(10),
        una0,
        head + 100,
        65535,
    );
    // Two RTOs on subflow 1 (t + 1 s, t + 3 s): backed off to 4 s, still Active.
    let t2 = t + Duration::from_millis(3500);
    drain_until(&mut ep, t, t2);
    let sf1 = &ep.conns[&h].subflows[1];
    assert_eq!(sf1.tcb.retransmission_timeout(), Duration::from_secs(4));
    assert!(sf1.is(SubflowState::Active));
    // A on subflow 0, subflow-ACKed without DATA_ACK: the rule-5 timer runs on the largest
    // un-backed-off RTO (1 s on both), not subflow 1's 4 s.
    pin(&mut ep, h, Some(SubflowId(0)));
    ep.connection(h).unwrap().write(&[2; 100]).unwrap();
    let a = data_on(&drain(&mut ep, t2), &syn).pop().unwrap();
    let t3 = t2 + Duration::from_millis(10);
    peer_ack(&mut ep, &syn, t3, end(&a), head + 100, 65535);
    let due = t3 + Duration::from_secs(1);
    assert_eq!(ep.conns[&h].hooks.recovery_deadline(), Some(due));
    ep.handle_timeout(due);
    assert_eq!(queue_first(&ep, h), Some((head + 100, 100)));
}

#[test]
fn bare_fin_makes_subflow_closing_without_reinjection() {
    let (mut ep, h, syn, jsyn) = two_paths(reno, reno);
    let fin = Segment {
        flags: TcpFlags::ACK | TcpFlags::FIN,
        ..peer_data(&jsyn, 5001, &[], &[])
    };
    input_at(&mut ep, &fin, ms(20));
    assert_eq!(ep.conns[&h].subflows[1].state, SubflowState::Closing);
    ep.connection(h).unwrap().write(&[3; 5000]).unwrap();
    let out = drain(&mut ep, ms(20));
    assert!(
        data_on(&out, &jsyn).is_empty(),
        "no new data on a Closing subflow"
    );
    assert!(!data_on(&out, &syn).is_empty());
    assert_eq!(queue_first(&ep, h), None);
}

// M2 Task 7: close and fallback across subflows.

fn peer_dsn() -> u64 {
    crate::crypto::key_token_idsn(PEER_KEY).1.wrapping_add(1)
}
fn rst_on(syn: &Segment) -> Segment<'static> {
    Segment {
        flags: TcpFlags::RST | TcpFlags::ACK,
        ..peer_data(syn, 5001, &[], &[])
    }
}
fn rst_from(out: &[Vec<u8>], syn: &Segment) -> bool {
    on(out, syn).iter().any(|s| s.flags.contains(TcpFlags::RST))
}
/// The DSS mapping `(ssn, dsn, data_len)` of `seg`, if any.
fn dss_map(seg: &Segment) -> Option<(u32, u64, u16)> {
    let raw = *mpc(seg.options).first()?;
    let Ok(MptcpOption::Dss(d)) = mptcp::parse(raw) else {
        return None;
    };
    let m = d.mapping?;
    let mptcp::Dsn::Dsn64(dsn) = m.dsn else {
        panic!("64-bit DSNs only")
    };
    Some((m.ssn, dsn, m.data_len))
}
/// The infinite mapping that arrives on subflow `syn` with the peer's 5 octets "reply".
fn peer_infinite_mapping(ep: &mut Endpoint<ChaCha20Rng>, syn: &Segment, now: Instant) {
    let inf = mapping(1, peer_dsn(), 0);
    input_at(ep, &peer_data(syn, 5001, &inf, b"reply"), now);
}
/// The fallen-back peer behind subflow `syn` (its own next sequence number 5006): places every
/// payload octet by the segment's finite DSS mapping, which only segments below our infinite
/// mapping may carry, else (no MPTCP option) by our infinite mapping; ACKs at TCP level only.
/// Takes `first` (already sent), then runs until `n` octets from `head` are acknowledged.
/// Returns them and our infinite mapping `(ssn, dsn)`.
fn fallen_back_peer(
    ep: &mut Endpoint<ChaCha20Rng>,
    h: ConnectionHandle,
    syn: &Segment,
    mut now: Instant,
    head: u64,
    n: usize,
    first: Vec<Segment<'static>>,
) -> (Vec<u8>, (u32, u64)) {
    let mut got = vec![None; n];
    let (mut inf, mut acked, mut segs) = (None, syn.seq.wrapping_add(1), first);
    for _ in 0..10_000 {
        for s in segs.drain(..).filter(|s| s.src == syn.src) {
            let rel = s.seq.0.wrapping_sub(syn.seq.0);
            let dsn = match dss_map(&s) {
                Some((ssn, dsn, 0)) => {
                    // One mapping, repeated on the data it maps until acknowledged.
                    assert!(inf.is_none_or(|i| i == (ssn, dsn)), "one infinite mapping");
                    inf = Some((ssn, dsn));
                    dsn.wrapping_add(u64::from(rel.wrapping_sub(ssn)))
                }
                Some((ssn, dsn, _)) => {
                    let (start, _) = inf.unwrap_or((u32::MAX, 0));
                    assert!(inf.is_none() || (rel.wrapping_sub(start) as i32) < 0);
                    dsn.wrapping_add(u64::from(rel.wrapping_sub(ssn)))
                }
                None => {
                    assert!(mpc(s.options).is_empty());
                    let (ssn, dsn) = inf.expect("payload after our infinite mapping");
                    dsn.wrapping_add(u64::from(rel.wrapping_sub(ssn)))
                }
            };
            for (k, &b) in s.payload.iter().enumerate() {
                got[(dsn - head) as usize + k] = Some(b);
            }
            if end(&s).gt(acked) {
                acked = end(&s);
            }
        }
        if una(ep, h) == head + n as u64 {
            let got = got.into_iter().map(|b| b.expect("every octet")).collect();
            return (got, inf.expect("infinite mapping"));
        }
        now = now + Duration::from_millis(1);
        let ack = Segment {
            ack: acked,
            wnd: 65535,
            ..peer_data(syn, 5006, &[], &[])
        };
        input_at(ep, &ack, now);
        if ep.poll_timeout().is_some_and(|t| t <= now) {
            ep.handle_timeout(now);
        }
        segs = drain(ep, now).into_iter().map(leak).collect();
    }
    panic!("no progress")
}

#[test]
fn close_two_subflows_fin_fin() {
    let (mut ep, h, syn, jsyn) = two_paths(reno, reno);
    let (t, una0) = prime(&mut ep, h, &syn, SubflowId(0), ms(20), 30);
    let (t, una1) = prime(&mut ep, h, &jsyn, SubflowId(1), t, 10);
    events(&mut ep);
    let head = una(&ep, h);
    ep.connection(h).unwrap().close();
    let out = drain(&mut ep, t);
    let all: Vec<_> = out.iter().map(|p| leak(p.clone())).collect();
    assert!(all.iter().all(|s| !s.flags.contains(TcpFlags::FIN)));
    assert_eq!(
        (all.iter().filter(|s| data_fin(s)).map(|s| s.src)).collect::<Vec<_>>(),
        vec![jsyn.src]
    );
    // The peer DATA_ACKs our DATA_FIN and sends its own on subflow 1.
    let t = t + Duration::from_millis(10);
    let opts = fin_option(peer_dsn(), 0, 1, Some(head + 1));
    let seg = Segment {
        ack: una1,
        wnd: 65535,
        ..peer_data(&jsyn, 5001, &opts, &[])
    };
    input_at(&mut ep, &seg, t);
    // Every subflow starts its FIN; the peer's DATA_FIN is DATA_ACKed.
    let out = drain(&mut ep, t);
    let fin = |s: &Segment| s.flags.contains(TcpFlags::FIN);
    let fin0 = on(&out, &syn)
        .into_iter()
        .find(fin)
        .expect("FIN on subflow 0");
    let fin1 = on(&out, &jsyn)
        .into_iter()
        .find(fin)
        .expect("FIN on subflow 1");
    assert_eq!((fin0.seq, fin1.seq), (una0, una1));
    let all: Vec<_> = out.iter().map(|p| leak(p.clone())).collect();
    assert!(all.iter().any(|s| {
        mpc(s.options)
            .first()
            .is_some_and(|_| dack(s) == peer_dsn() + 1)
    }));
    assert_eq!(ep.connection(h).unwrap().read(&mut [0; 1]), Ok(0));
    // The peer ACKs both FINs and sends its own: both subflows enter TIME-WAIT.
    let t = t + Duration::from_millis(10);
    let opts = data_ack(head + 1);
    for (s, f) in [(&syn, &fin0), (&jsyn, &fin1)] {
        let seg = Segment {
            flags: TcpFlags::ACK | TcpFlags::FIN,
            ack: f.seq.wrapping_add(1),
            wnd: 65535,
            ..peer_data(s, 5001, &opts, &[])
        };
        input_at(&mut ep, &seg, t);
    }
    drain(&mut ep, t);
    let mut ev = events(&mut ep);
    assert!(
        !ev.iter().any(|e| matches!(e, Event::Closed { .. })),
        "{ev:?}"
    );
    assert!(
        ep.connection(h).is_some(),
        "token and ports kept in TIME-WAIT"
    );
    while let Some(at) = ep.poll_timeout() {
        assert!(at < t + Duration::from_secs(300));
        ep.handle_timeout(at);
        drain(&mut ep, at);
    }
    ev.extend(events(&mut ep));
    let closed = Event::Closed {
        reason: CloseReason::Normal,
    };
    assert_eq!(count(&ev, closed), 1, "{ev:?}");
    assert!(ep.connection(h).is_none());
    assert!(ep.demux.is_empty(), "ports released");
    assert!(ep.conns.is_empty(), "token released");
}

/// The interop flake (2026-10-10): the peer's FIN on subflow 0 DATA_ACKs our DATA_FIN, so both
/// subflows send their FIN before the peer's FIN on subflow 1 is read. Subflow 0 ends from
/// LAST-ACK while subflow 1 is CLOSING (a simultaneous close), then subflow 1 enters TIME-WAIT
/// as the last open subflow: `Closed` follows that TIME-WAIT, with `poll_timeout` its deadline.
#[test]
fn simultaneous_close_on_last_subflow_closes_after_its_time_wait() {
    let (mut ep, h, syn, jsyn) = two_paths(reno, reno);
    let (t, una0) = prime(&mut ep, h, &syn, SubflowId(0), ms(20), 30);
    let (t, una1) = prime(&mut ep, h, &jsyn, SubflowId(1), t, 10);
    events(&mut ep);
    let head = una(&ep, h);
    ep.connection(h).unwrap().close();
    drain(&mut ep, t);
    let t = t + ms_d(10);
    let fin_seg = |s: &Segment<'static>, opts: &'static [u8], ack| Segment {
        flags: TcpFlags::ACK | TcpFlags::FIN,
        ack,
        wnd: 65535,
        ..peer_data(s, 5001, opts, &[])
    };
    let opts = fin_option(peer_dsn(), 0, 1, Some(head + 1)).leak();
    input_at(&mut ep, &fin_seg(&syn, opts, una0), t);
    let out = drain(&mut ep, t);
    let fin = |s: &Segment| s.flags.contains(TcpFlags::FIN);
    let fin0 = (on(&out, &syn).into_iter()).find(fin).expect("FIN 0");
    let fin1 = (on(&out, &jsyn).into_iter()).find(fin).expect("FIN 1");
    let dack = data_ack(head + 1).leak();
    input_at(&mut ep, &fin_seg(&jsyn, dack, una1), t);
    drain(&mut ep, t);
    assert_eq!(ep.conns[&h].subflows[1].tcb.state(), TcpState::Closing);
    for (s, f) in [(&syn, &fin0), (&jsyn, &fin1)] {
        let seg = Segment {
            ack: f.seq.wrapping_add(1),
            wnd: 65535,
            ..peer_data(s, 5002, dack, &[])
        };
        input_at(&mut ep, &seg, t);
    }
    drain(&mut ep, t);
    assert_eq!(ep.conns[&h].subflows[1].tcb.state(), TcpState::TimeWait);
    let down = |i| Event::SubflowDown {
        subflow: SubflowId(i),
        reason: CloseReason::Normal,
        rst: None,
    };
    assert_eq!(events(&mut ep), [down(0), down(1)]);
    let closed = Event::Closed {
        reason: CloseReason::Normal,
    };
    let (mut ev, mut at) = (Vec::new(), t);
    for _ in 0..10 {
        at = ep.poll_timeout().expect("a deadline until Closed");
        ep.handle_timeout(at);
        drain(&mut ep, at);
        ev.extend(events(&mut ep));
        if ev.contains(&closed) {
            break;
        }
    }
    assert_eq!(count(&ev, closed), 1, "{ev:?}");
    assert_eq!(at, t + Duration::from_secs(120), "2·MSL");
}

/// The reverse order (ruling R31): subflow 1 enters TIME-WAIT first (active close), then
/// subflow 0 ends from LAST-ACK (passive close). Every subflow must be closed, TIME-WAIT
/// included, before `Closed`: it follows subflow 1's TIME-WAIT, as in the order above.
#[test]
fn passive_close_after_time_wait_closes_after_that_time_wait() {
    let (mut ep, h, syn, jsyn) = two_paths(reno, reno);
    let (t, una0) = prime(&mut ep, h, &syn, SubflowId(0), ms(20), 30);
    let (t, _) = prime(&mut ep, h, &jsyn, SubflowId(1), t, 10);
    events(&mut ep);
    let head = una(&ep, h);
    ep.connection(h).unwrap().close();
    drain(&mut ep, t);
    let t = t + ms_d(10);
    let fin_seg = |s: &Segment<'static>, opts: &'static [u8], ack| Segment {
        flags: TcpFlags::ACK | TcpFlags::FIN,
        ack,
        wnd: 65535,
        ..peer_data(s, 5001, opts, &[])
    };
    // The peer's FIN on subflow 0 DATA_ACKs our DATA_FIN: subflow 0 answers with its FIN
    // (LAST-ACK), subflow 1 sends its FIN first (FIN-WAIT-1).
    let opts = fin_option(peer_dsn(), 0, 1, Some(head + 1)).leak();
    input_at(&mut ep, &fin_seg(&syn, opts, una0), t);
    let out = drain(&mut ep, t);
    let fin = |s: &Segment| s.flags.contains(TcpFlags::FIN);
    let fin0 = (on(&out, &syn).into_iter()).find(fin).expect("FIN 0");
    let fin1 = (on(&out, &jsyn).into_iter()).find(fin).expect("FIN 1");
    let dack = data_ack(head + 1).leak();
    input_at(&mut ep, &fin_seg(&jsyn, dack, fin1.seq.wrapping_add(1)), t);
    drain(&mut ep, t);
    assert_eq!(ep.conns[&h].subflows[1].tcb.state(), TcpState::TimeWait);
    let seg = Segment {
        ack: fin0.seq.wrapping_add(1),
        wnd: 65535,
        ..peer_data(&syn, 5002, dack, &[])
    };
    input_at(&mut ep, &seg, t);
    drain(&mut ep, t);
    assert_eq!(ep.conns[&h].subflows[0].tcb.state(), TcpState::Closed);
    let down = Event::SubflowDown {
        subflow: SubflowId(1),
        reason: CloseReason::Normal,
        rst: None,
    };
    assert_eq!(events(&mut ep), [down], "no Closed while in TIME-WAIT");
    let at = t + Duration::from_secs(120);
    assert_eq!(ep.poll_timeout(), Some(at), "the TIME-WAIT's 2·MSL");
    ep.handle_timeout(t + Duration::from_secs(119));
    assert_eq!(events(&mut ep), []);
    ep.handle_timeout(at);
    let closed = Event::Closed {
        reason: CloseReason::Normal,
    };
    assert_eq!(events(&mut ep), [closed]);
    assert!(ep.connection(h).is_none());
    assert!(ep.conns.is_empty() && ep.demux.is_empty());
}

/// Both DATA_FINs are DATA_ACKed and both subflows send their FIN. The peer answers subflow
/// `1 - k` at once (TIME-WAIT); subflow `k`'s FIN goes unanswered through R1 = 3 RTOs
/// (`SubflowStale`), then the peer's ACK+FIN puts it in TIME-WAIT: `SubflowDown { Normal }`
/// and no `SubflowRecovered` after it (a subflow whose FIN is ACKed carries no data again). For
/// the initial subflow (`k` 0) nothing: the other one is in TIME-WAIT, so it is the last open
/// subflow ending after both DATA_FINs (`Closed` follows its TIME-WAIT).
fn stale_fin_then_time_wait(k: usize) -> (Endpoint<ChaCha20Rng>, ConnectionHandle, SubflowId) {
    let (mut ep, h, syn, jsyn) = two_paths(reno, reno);
    let (t, _) = prime(&mut ep, h, &syn, SubflowId(0), ms(20), 30);
    let (t, una1) = prime(&mut ep, h, &jsyn, SubflowId(1), t, 10);
    let head = una(&ep, h);
    ep.connection(h).unwrap().close();
    drain(&mut ep, t);
    let t = t + Duration::from_millis(10);
    let opts = fin_option(peer_dsn(), 0, 1, Some(head + 1));
    let seg = Segment {
        ack: una1,
        wnd: 65535,
        ..peer_data(&jsyn, 5001, &opts, &[])
    };
    input_at(&mut ep, &seg, t);
    let out = drain(&mut ep, t);
    let syns = [&syn, &jsyn];
    let fins: Vec<_> = (syns.iter())
        .map(|s| {
            (on(&out, s).into_iter())
                .find(|s| s.flags.contains(TcpFlags::FIN))
                .expect("our FIN")
        })
        .collect();
    let opts = data_ack(head + 1);
    let answer = |ep: &mut Endpoint<ChaCha20Rng>, i: usize, at: Instant| {
        let seg = Segment {
            flags: TcpFlags::ACK | TcpFlags::FIN,
            ack: fins[i].seq.wrapping_add(1),
            wnd: 65535,
            ..peer_data(syns[i], 5001, &opts, &[])
        };
        input_at(ep, &seg, at);
    };
    answer(&mut ep, 1 - k, t);
    drain(&mut ep, t);
    events(&mut ep);
    let id = SubflowId(k as u32);
    let mut t = t;
    for _ in 0..10 {
        if ep.conns[&h].subflows[k].state == SubflowState::Stale {
            break;
        }
        t = ep.poll_timeout().expect("the FIN's RTO");
        ep.handle_timeout(t);
        drain(&mut ep, t);
    }
    assert_eq!(events(&mut ep), vec![Event::SubflowStale { subflow: id }]);
    answer(&mut ep, k, t);
    drain(&mut ep, t);
    let reason = CloseReason::Normal;
    let down = Event::SubflowDown {
        subflow: id,
        reason,
        rst: None,
    };
    assert_eq!(events(&mut ep), if k == 0 { vec![] } else { vec![down] });
    (ep, h, id)
}

#[test]
fn stale_joined_subflow_fin_acked_is_not_recovered() {
    stale_fin_then_time_wait(1);
}

#[test]
fn stale_initial_subflow_fin_acked_is_not_recovered() {
    stale_fin_then_time_wait(0);
}

#[test]
fn fastclose_resets_all_subflows() {
    let (mut ep, h, syn, jsyn) = two_paths(reno, reno);
    let mut opts = [0; 40];
    let n = mptcp::encode(
        &MptcpOption::FastClose {
            receiver_key: local_key(&ep, h),
        },
        &mut opts,
    )
    .unwrap();
    input_at(&mut ep, &peer_data(&syn, 5001, &opts[..n], &[]), ms(20));
    let reset = Event::Closed {
        reason: CloseReason::Reset,
    };
    assert_eq!(events(&mut ep), vec![reset]);
    let out = drain(&mut ep, ms(20));
    assert!(
        rst_from(&out, &syn) && rst_from(&out, &jsyn),
        "RST on every subflow"
    );
    ep.handle_timeout(ms(21));
    assert!(ep.connection(h).is_none());
    assert!(ep.demux.is_empty());
}

/// MP_FASTCLOSE on the joined subflow: the same single `Closed { Reset }` as on subflow 0.
#[test]
fn fastclose_on_joined_subflow_resets_all_subflows() {
    let (mut ep, h, syn, jsyn) = two_paths(reno, reno);
    let mut opts = [0; 40];
    let n = mptcp::encode(
        &MptcpOption::FastClose {
            receiver_key: local_key(&ep, h),
        },
        &mut opts,
    )
    .unwrap();
    input_at(&mut ep, &peer_data(&jsyn, 5001, &opts[..n], &[]), ms(20));
    let reset = Event::Closed {
        reason: CloseReason::Reset,
    };
    assert_eq!(events(&mut ep), vec![reset]);
    let out = drain(&mut ep, ms(20));
    assert!(rst_from(&out, &syn) && rst_from(&out, &jsyn));
}

/// The peer resets the initial subflow while subflow 1 lives: `SubflowDown` for it, and the
/// transfer goes on byte-exact on subflow 1. The dead subflow's snapshot is not Active.
#[test]
fn initial_subflow_rst_is_subflow_down() {
    let n = 50_000;
    let (mut ep, h, mut peer, t, head, data) = two_paths_primed(R100, n);
    input_at(&mut ep, &rst_on(&peer.syns[0]), t);
    let down = Event::SubflowDown {
        subflow: SubflowId::INITIAL,
        reason: CloseReason::Reset,
        rst: None,
    };
    assert_eq!(events(&mut ep), vec![down]);
    peer.reset[0] = true;
    assert_eq!(ep.connection(h).unwrap().write(&data), Ok(n));
    peer.run(&mut ep, h, t, t + Duration::from_secs(30));
    assert_eq!(una(&ep, h), head + n as u64);
    assert_eq!(peer.received(), data);
    assert!(peer.log.iter().all(|l| l.1 == 1), "data only on subflow 1");
    assert!(events(&mut ep).is_empty());
    let s = ep.conns[&h].snapshots();
    assert_eq!(
        (s[0].state, s[1].state),
        (SubflowState::Closing, SubflowState::Active)
    );
}

#[test]
fn infinite_mapping_with_join_keeps_one_subflow() {
    let (mut ep, h, syn, jsyn) = two_paths(reno, reno);
    let head = una(&ep, h);
    peer_infinite_mapping(&mut ep, &jsyn, ms(20));
    assert_eq!(events(&mut ep), vec![Event::FellBack]);
    assert_eq!(state(&ep, h), State::FellBack);
    let out = drain(&mut ep, ms(20));
    assert!(rst_from(&out, &syn), "the other subflow is reset");
    assert!(!rst_from(&out, &jsyn));
    let n = 50_000;
    let data: Vec<u8> = (0..n).map(|i| (i % 251) as u8).collect();
    assert_eq!(ep.connection(h).unwrap().write(&data), Ok(n));
    let first = out.into_iter().map(leak).collect();
    let (got, inf) = fallen_back_peer(&mut ep, h, &jsyn, ms(20), head, n, first);
    assert_eq!(inf, (1, head), "survivor-relative: SSN 1 at DSN send.next");
    assert_eq!(got, data, "the transfer continues byte-exact on subflow 1");
    let mut buf = [0; 16];
    assert_eq!(ep.connection(h).unwrap().read(&mut buf), Ok(5));
    assert_eq!(&buf[..5], b"reply");
    assert!(events(&mut ep).is_empty());
    // The connection is plain TCP on subflow 1 now: `close` sends its FIN there.
    ep.connection(h).unwrap().close();
    let out = drain(&mut ep, ms(5000));
    assert!(
        on(&out, &jsyn)
            .iter()
            .any(|s| s.flags.contains(TcpFlags::FIN))
    );
}

/// The infinite mapping arrives on the ACK that completes the join (the fourth ACK, nothing
/// outstanding on subflow 0): the survivor is promoted to Active before it becomes
/// `subflows[0]`, with `FellBack` and no `SubflowUp`, and carries later writes.
#[test]
fn infinite_mapping_on_join_confirming_ack_survivor_sends() {
    let (mut ep, h, syn, _) = confirmed();
    let (_, jsyn) = join_syn(&mut ep, h, ms(10), JOIN_IP, 1500);
    let opts = synack_opts(&ep, h, &jsyn, 7, None);
    synack(&mut ep, &jsyn, &opts, ms(20));
    let ack = from(&drain(&mut ep, ms(20)), JOIN_IP)
        .pop()
        .expect("third ACK");
    assert_third_ack(&ep, h, &jsyn, &ack);
    let head = una(&ep, h);
    peer_infinite_mapping(&mut ep, &jsyn, ms(30));
    assert_eq!(events(&mut ep), vec![Event::FellBack]);
    assert_eq!(ep.conns[&h].subflows[0].state, SubflowState::Active);
    let out = drain(&mut ep, ms(30));
    assert!(rst_from(&out, &syn), "the other subflow is reset");
    let n = 5000;
    let data: Vec<u8> = (0..n).map(|i| (i % 251) as u8).collect();
    assert_eq!(ep.connection(h).unwrap().write(&data), Ok(n));
    let first = out.into_iter().map(leak).collect();
    let (got, _) = fallen_back_peer(&mut ep, h, &jsyn, ms(30), head, n, first);
    assert_eq!(got, data, "the survivor carries the writes");
}

#[test]
fn infinite_mapping_with_join_after_nonzero_prefix() {
    let (mut ep, h, syn, jsyn) = two_paths(reno, reno);
    let head = una(&ep, h);
    let n = 30_000;
    let data: Vec<u8> = (0..n).map(|i| (i % 251) as u8).collect();
    // Subflow 0 carries the first 1000 octets; the peer DATA_ACKs them.
    pin(&mut ep, h, Some(SubflowId(0)));
    ep.connection(h).unwrap().write(&data[..1000]).unwrap();
    let a = data_on(&drain(&mut ep, ms(20)), &syn);
    assert_eq!(a.len(), 1);
    peer_ack(&mut ep, &syn, ms(30), end(&a[0]), head + 1000, 65535);
    pin(&mut ep, h, None);
    // Subflow 1 has sent nothing when the infinite mapping arrives on it.
    peer_infinite_mapping(&mut ep, &jsyn, ms(40));
    assert_eq!(events(&mut ep), vec![Event::FellBack]);
    ep.connection(h).unwrap().write(&data[1000..]).unwrap();
    let first = drain(&mut ep, ms(40)).into_iter().map(leak).collect();
    let (got, inf) = fallen_back_peer(&mut ep, h, &jsyn, ms(40), head + 1000, n - 1000, first);
    assert_eq!(inf, (1, head + 1000), "SSN 1 / DSN origin + 1000");
    assert_eq!([a[0].payload, &got[..]].concat(), data, "byte-exact");
}

#[test]
fn infinite_mapping_with_join_outstanding_survivor_segment() {
    let (mut ep, h, syn, jsyn) = two_paths(reno, reno);
    let head = una(&ep, h);
    let n = 30_000;
    let data: Vec<u8> = (0..n).map(|i| (i % 251) as u8).collect();
    // Subflow 1's first data segment, with its finite mapping, is lost.
    pin(&mut ep, h, Some(SubflowId(1)));
    ep.connection(h).unwrap().write(&data[..1000]).unwrap();
    let lost = data_on(&drain(&mut ep, ms(20)), &jsyn).pop().unwrap();
    assert!(data_on(&drain(&mut ep, ms(20)), &syn).is_empty());
    pin(&mut ep, h, None);
    // Its RTO fires; then the infinite mapping arrives on it.
    let rto = ep.poll_timeout().unwrap();
    assert_eq!(rto, ms(20) + Duration::from_secs(1));
    ep.handle_timeout(rto);
    peer_infinite_mapping(&mut ep, &jsyn, rto);
    assert_eq!(events(&mut ep), vec![Event::FellBack]);
    let out: Vec<_> = drain(&mut ep, rto).into_iter().map(leak).collect();
    let b: Vec<_> = out.iter().filter(|s| s.src == jsyn.src).collect();
    assert_eq!((b[0].seq, &b[0].payload), (lost.seq, &lost.payload));
    assert_eq!(
        dss_map(b[0]),
        Some((1, head, 1000)),
        "the retransmission keeps its finite mapping"
    );
    let inf = b
        .iter()
        .position(|s| infinite_mapping(s))
        .expect("then the infinite mapping");
    assert!(inf > 0);
    assert_eq!(
        dss_map(b[inf]).map(|m| (m.0, m.1)),
        Some((1001, head + 1000))
    );
    ep.connection(h).unwrap().write(&data[1000..]).unwrap();
    let (got, _) = fallen_back_peer(&mut ep, h, &jsyn, rto, head, n, out);
    assert_eq!(got, data, "byte-exact across the boundary");
}

#[test]
fn infinite_mapping_with_stranded_data_closes() {
    let (mut ep, h, syn, jsyn) = two_paths(reno, reno);
    pin(&mut ep, h, Some(SubflowId(0)));
    ep.connection(h).unwrap().write(&[7; 1000]).unwrap();
    assert_eq!(data_on(&drain(&mut ep, ms(20)), &syn).len(), 1);
    pin(&mut ep, h, None);
    // Subflow 0's data is not DATA_ACKed when the infinite mapping arrives on subflow 1.
    peer_infinite_mapping(&mut ep, &jsyn, ms(30));
    let loss = Event::Closed {
        reason: CloseReason::FallbackDataLoss,
    };
    assert_eq!(events(&mut ep), vec![loss]);
    let out = drain(&mut ep, ms(30));
    assert!(rst_from(&out, &syn) && rst_from(&out, &jsyn));
    assert_eq!(
        ep.connection(h).unwrap().read(&mut [0; 8]),
        Err(crate::connection::ReadError::Reset)
    );
}

#[test]
fn stripping_after_join_history_resets_not_fallback() {
    let (mut ep, h, syn, jsyn) = two_paths(reno, reno);
    let head = una(&ep, h);
    // Subflow 0's window is closed: subflow 1 carries the first DSN range ...
    peer_ack(&mut ep, &syn, ms(20), syn.seq.wrapping_add(1), head, 0);
    ep.connection(h).unwrap().write(&[1; 1000]).unwrap();
    let b = data_on(&drain(&mut ep, ms(20)), &jsyn);
    assert_eq!(b.len(), 1);
    peer_ack(&mut ep, &jsyn, ms(30), end(&b[0]), head + 1000, 65535);
    // ... and is then reset by the peer.
    input_at(&mut ep, &rst_on(&jsyn), ms(31));
    assert!(events(&mut ep).contains(&Event::SubflowDown {
        subflow: SubflowId(1),
        reason: CloseReason::Reset,
        rst: None
    }));
    // Subflow 0's window opens; its first data is ACKed without any MPTCP option.
    peer_ack(
        &mut ep,
        &syn,
        ms(40),
        syn.seq.wrapping_add(1),
        head + 1000,
        65535,
    );
    ep.connection(h).unwrap().write(&[2; 1000]).unwrap();
    let a = data_on(&drain(&mut ep, ms(40)), &syn);
    assert_eq!(a.len(), 1);
    let stripped = Segment {
        ack: end(&a[0]),
        wnd: 65535,
        ..peer_data(&syn, 5001, &[], &[])
    };
    input_at(&mut ep, &stripped, ms(50));
    let out = drain(&mut ep, ms(50));
    assert!(rst_from(&out, &syn), "subflow 0 is reset");
    let all: Vec<_> = out.iter().map(|p| leak(p.clone())).collect();
    assert!(!all.iter().any(infinite_mapping), "no infinite mapping");
    assert!(!events(&mut ep).contains(&Event::FellBack));
    assert_eq!(state(&ep, h), State::Confirmed);
    // It was the last subflow: the no-subflow wait.
    assert_eq!(ep.poll_timeout(), Some(ms(50) + Duration::from_secs(60)));
}

/// A connection timer armed on subflow 0 (`arm`, at `ms(20)`), then subflow 0 reset while
/// the only other subflow is still Joining (its SYN unanswered): `poll_timeout` never stays
/// at a past deadline (a driver draining due timers would spin). Once the join is up the
/// joined subflow sends what `resent` finds.
fn joining_only_disarms(
    arm: fn(&mut Endpoint<ChaCha20Rng>, ConnectionHandle, &Segment),
    resent: fn(&[Vec<u8>], &Segment, u64) -> bool,
) {
    let (mut ep, h, syn, _) = confirmed_cc(reno);
    let head = una(&ep, h);
    let (_, jsyn) = join_syn(&mut ep, h, ms(10), JOIN_IP, 1500);
    arm(&mut ep, h, &syn);
    let deadline = ep.conns[&h].hooks.recovery_deadline().expect("armed");
    input_at(&mut ep, &rst_on(&syn), ms(50));
    let mut t = ms(50);
    while t <= deadline {
        t = ep.poll_timeout().expect("the join SYN's timer");
        ep.handle_timeout(t);
        drain(&mut ep, t);
        assert!(
            ep.poll_timeout().is_none_or(|n| n > t),
            "past deadline at {t:?}"
        );
    }
    let opts = synack_opts(&ep, h, &jsyn, 7, None);
    synack(&mut ep, &jsyn, &opts, t);
    from(&drain(&mut ep, t), JOIN_IP).pop().expect("third ACK");
    peer_ack(&mut ep, &jsyn, t, jsyn.seq.wrapping_add(1), head, 1000);
    let out = drain_until(&mut ep, t, t + Duration::from_secs(5));
    assert!(resent(&out, &jsyn, head));
}

/// Connection recovery (subflow 0 TCP-ACKs 1000 octets without a DATA_ACK): disarmed, as
/// nothing could consume it, and rearmed once the join is up.
#[test]
fn recovery_disarmed_while_only_joining_subflow() {
    joining_only_disarms(
        |ep, h, syn| {
            let head = una(ep, h);
            ep.connection(h).unwrap().write(&[7; 1000]).unwrap();
            let a = data_on(&drain(ep, ms(20)), syn);
            assert_eq!(a.len(), 1);
            peer_ack(ep, syn, ms(30), end(&a[0]), head, 65535);
        },
        |out, jsyn, head| {
            (data_on(out, jsyn).first()).is_some_and(|s| dsn_of(s, jsyn.seq).unwrap().0 == head)
        },
    );
}

/// The DATA_FIN retry (a standalone DATA_FIN on subflow 0, never DATA_ACKed): `poll_transmit`
/// consumes it through the dead `subflows[0]`; the DATA_FIN stays due for the join.
#[test]
fn data_fin_retry_disarmed_while_only_joining_subflow() {
    joining_only_disarms(
        |ep, h, syn| {
            ep.connection(h).unwrap().close();
            assert!(on(&drain(ep, ms(20)), syn).iter().any(data_fin));
        },
        |out, jsyn, _| on(out, jsyn).iter().any(data_fin),
    );
}

/// The initial subflow is gone and the ACK completing the join carries a bare FIN (no
/// DATA_FIN): the join is up (`SubflowUp`) and retired at once like any bare FIN (Closing,
/// our FIN goes out); its FIN exchange ends in `SubflowDown { Normal }`, then the no-subflow
/// wait runs to `Closed { Timeout }`, with a timer pending all along.
#[test]
fn bare_fin_on_join_confirming_ack_retires_subflow() {
    let (mut ep, h, syn, _) = confirmed_cc(reno);
    let head = una(&ep, h);
    let (id, jsyn) = join_syn(&mut ep, h, ms(10), JOIN_IP, 1500);
    let opts = synack_opts(&ep, h, &jsyn, 7, None);
    synack(&mut ep, &jsyn, &opts, ms(20));
    from(&drain(&mut ep, ms(20)), JOIN_IP)
        .pop()
        .expect("third ACK");
    input_at(&mut ep, &rst_on(&syn), ms(30));
    events(&mut ep);
    let opts = data_ack(head);
    let fin = Segment {
        flags: TcpFlags::ACK | TcpFlags::FIN,
        ..peer_data(&jsyn, 5001, &opts, &[])
    };
    input_at(&mut ep, &fin, ms(40));
    assert_eq!(events(&mut ep), vec![Event::SubflowUp { subflow: id }]);
    assert_eq!(ep.conns[&h].subflows[1].state, SubflowState::Closing);
    let out = on(&drain(&mut ep, ms(40)), &jsyn);
    let ours = (out.iter())
        .find(|s| s.flags.contains(TcpFlags::FIN))
        .expect("our FIN");
    let ack = Segment {
        ack: ours.seq.wrapping_add(1),
        ..peer_data(&jsyn, 5002, &opts, &[])
    };
    input_at(&mut ep, &ack, ms(50));
    let reason = CloseReason::Normal;
    assert_eq!(
        events(&mut ep),
        vec![Event::SubflowDown {
            subflow: id,
            reason,
            rst: None
        }]
    );
    let (ev, t) = loop {
        let t = ep.poll_timeout().expect("the no-subflow wait");
        ep.handle_timeout(t);
        drain(&mut ep, t);
        let ev = events(&mut ep);
        if !ev.is_empty() {
            break (ev, t);
        }
    };
    let reason = CloseReason::Timeout;
    assert_eq!(
        (ev, t),
        (
            vec![Event::Closed { reason }],
            ms(50) + Duration::from_secs(60)
        )
    );
}

/// The head on subflow 0, whose bare FIN (Closing) arms connection recovery; then subflow 0
/// is reset, which queues the head for reinjection, while subflow 1's peer window is zero.
/// The queued head disarms recovery: `poll_timeout` never stays at a past deadline. Once
/// subflow 1's window opens, the reinjection completes the transfer.
#[test]
fn queued_head_disarms_recovery() {
    let (mut ep, h, syn, jsyn) = two_paths(reno, reno);
    let head = una(&ep, h);
    peer_ack(&mut ep, &jsyn, ms(15), jsyn.seq.wrapping_add(1), head, 0);
    pin(&mut ep, h, Some(SubflowId(0)));
    ep.connection(h).unwrap().write(&[7; 1000]).unwrap();
    assert_eq!(data_on(&drain(&mut ep, ms(20)), &syn).len(), 1);
    pin(&mut ep, h, None);
    let opts = data_ack(head);
    let fin = Segment {
        flags: TcpFlags::ACK | TcpFlags::FIN,
        ..peer_data(&syn, 5001, &opts, &[])
    };
    input_at(&mut ep, &fin, ms(25));
    assert_eq!(ep.conns[&h].subflows[0].state, SubflowState::Closing);
    let deadline = ep.conns[&h].hooks.recovery_deadline().expect("armed");
    drain(&mut ep, ms(25));
    let rst = Segment {
        flags: TcpFlags::RST | TcpFlags::ACK,
        ..peer_data(&syn, 5002, &[], &[])
    };
    input_at(&mut ep, &rst, ms(30));
    assert_eq!(queue_first(&ep, h), Some((head, 1000)));
    assert!(
        data_on(&drain(&mut ep, ms(30)), &jsyn).is_empty(),
        "window closed"
    );
    let mut t = ms(30);
    while t <= deadline {
        t = ep.poll_timeout().expect("subflow 1's persist timer");
        ep.handle_timeout(t);
        assert!(
            data_on(&drain(&mut ep, t), &jsyn).is_empty(),
            "window closed"
        );
        assert!(
            ep.poll_timeout().is_none_or(|n| n > t),
            "past deadline at {t:?}"
        );
    }
    peer_ack(&mut ep, &jsyn, t, jsyn.seq.wrapping_add(1), head, 65535);
    let out = drain(&mut ep, t);
    ack_all(&mut ep, &jsyn, &out, t + Duration::from_millis(10));
    assert_eq!(una(&ep, h), head + 1000);
}

#[test]
fn last_subflow_lost_then_add_subflow_resumes() {
    let (mut ep, h, syn, _) = confirmed_cc(reno);
    let head = una(&ep, h);
    let n = 20_000;
    let data: Vec<u8> = (0..n).map(|i| (i % 251) as u8).collect();
    assert_eq!(ep.connection(h).unwrap().write(&data), Ok(n));
    let t = ms(20);
    assert!(!data_on(&drain(&mut ep, t), &syn).is_empty(), "lost");
    // The only subflow is reset: the 60 s wait starts, its data stays queued.
    input_at(&mut ep, &rst_on(&syn), t);
    assert_eq!(events(&mut ep), vec![initial_down(CloseReason::Reset)]);
    assert_eq!(ep.poll_timeout(), Some(t + Duration::from_secs(60)));
    assert_eq!(queue_first(&ep, h).map(|q| q.0), Some(head));
    // A new subflow 5 s later resumes the transfer at once.
    let t5 = t + Duration::from_secs(5);
    ep.cc = Some(reno);
    let (_, jsyn) = joined(&mut ep, h, t5, JOIN_IP, 1500, 7);
    let mut peer = Peer::new(head, n, &[(&syn, 30), (&jsyn, 10)]);
    peer.reset[0] = true;
    let now = peer.run(&mut ep, h, t5, t5 + Duration::from_secs(120));
    assert_eq!(peer.received(), data, "byte-exact");
    assert_eq!(
        peer.log.first().map(|l| l.0),
        Some(t5),
        "reinjected at once"
    );
    // The wait was cancelled: nothing closes at t + 60 s.
    peer.run(&mut ep, h, now, t + Duration::from_secs(90));
    drain_until(&mut ep, now, t + Duration::from_secs(90));
    assert!(events(&mut ep).is_empty());
    assert_eq!(state(&ep, h), State::Confirmed);
}

#[test]
fn initial_lost_before_confirmed_with_queued_join_times_out() {
    let (mut ep, h, syn, _) = connected_scaled(1 << 20);
    assert_eq!(state(&ep, h), State::PreConfirmed);
    let join_ip: IpAddr = JOIN_IP.parse().unwrap();
    let id = ep
        .add_subflow(ms(1), h, join_ip, remote(), 1500, false)
        .unwrap();
    assert!(drain(&mut ep, ms(1)).is_empty(), "queued");
    input_at(&mut ep, &rst_on(&syn), ms(2));
    let mut ev = Vec::new();
    let mut now = ms(2);
    while !ev.iter().any(|e| matches!(e, Event::Closed { .. })) {
        let at = ep.poll_timeout().expect("the wait keeps a deadline");
        assert!(at <= ms(2) + Duration::from_secs(60), "{at:?}");
        now = at.max(now);
        ep.handle_timeout(now);
        assert!(
            from(&drain(&mut ep, now), JOIN_IP).is_empty(),
            "no MP_JOIN SYN"
        );
        ev.extend(events(&mut ep));
    }
    assert_eq!(now, ms(2) + Duration::from_secs(60));
    let timeout = Event::Closed {
        reason: CloseReason::Timeout,
    };
    assert_eq!(ev[1], timeout);
    drain(&mut ep, now);
    ev.extend(events(&mut ep));
    let down = Event::SubflowDown {
        subflow: id,
        reason: CloseReason::Reset,
        rst: None,
    };
    assert_eq!(ev, vec![initial_down(CloseReason::Reset), timeout, down]);
}

#[test]
fn window_update_on_stale_only_subflow() {
    let (mut ep, h, syn, dsn) = connected_scaled_cc(8192, Some(reno));
    open_window(&mut ep, &syn, h);
    // The peer fills the 8 KiB receive buffer.
    for k in 0..8u32 {
        let opts = mapping(1 + k * 1024, dsn + u64::from(k) * 1024, 1024);
        let payload = [k as u8; 1024];
        let seg = peer_data(&syn, 5001 + k * 1024, &opts, &payload);
        input_at(&mut ep, &seg, ms(10));
    }
    // Our data is lost three times: the only subflow goes Stale.
    ep.connection(h).unwrap().write(&[1; 100]).unwrap();
    let acks = on(&drain_until(&mut ep, ms(10), ms(7500)), &syn);
    assert_eq!(acks.iter().find(|s| s.payload.is_empty()).unwrap().wnd, 0);
    let stale = Event::SubflowStale {
        subflow: SubflowId(0),
    };
    assert_eq!(events(&mut ep), vec![stale]);
    // A read reopens the window: the update goes out on the Stale subflow.
    let mut buf = [0; 8192];
    assert_eq!(ep.connection(h).unwrap().read(&mut buf), Ok(8192));
    let out = on(&drain(&mut ep, ms(7500)), &syn);
    assert_eq!(out.len(), 1);
    assert!(out[0].payload.is_empty() && out[0].wnd > 0);
}

/// Slots: the initial subflow Closed, B still Joining (third ACK unacknowledged), C Active.
/// C fills the 32 KiB receive buffer (zero window); a read just after B's third-ACK retry
/// fell due reopens it. B's MP_JOIN ACK, sent first, carries no DATA_ACK, so it must not
/// count as the connection-level window update: C still sends one (spec §5.4).
#[test]
fn join_ack_does_not_consume_window_update() {
    let (mut ep, h, syn, dsn) = connected_scaled_cc(32768, Some(reno));
    open_window(&mut ep, &syn, h);
    let (_, bsyn) = join_syn(&mut ep, h, ms(10), JOIN_IP, 1500);
    let opts = synack_opts(&ep, h, &bsyn, 7, None);
    synack(&mut ep, &bsyn, &opts, ms(20));
    from(&drain(&mut ep, ms(20)), JOIN_IP)
        .pop()
        .expect("third ACK");
    let (_, csyn) = joined(&mut ep, h, ms(20), "10.0.2.1", 1500, 7);
    input_at(&mut ep, &rst_on(&syn), ms(30));
    for k in 0..32u32 {
        let opts = mapping(1 + k * 1024, dsn + u64::from(k) * 1024, 1024);
        let payload = [k as u8; 1024];
        let seg = peer_data(&csyn, 5001 + k * 1024, &opts, &payload);
        input_at(&mut ep, &seg, ms(40));
    }
    let acks = on(&drain(&mut ep, ms(40)), &csyn);
    assert_eq!(
        acks.last().map(|s| (dack(s), s.wnd)),
        Some((dsn + 32768, 0))
    );
    let t = ms(20) + Duration::from_secs(1);
    ep.handle_timeout(t);
    let mut buf = vec![0; 32768];
    assert_eq!(ep.connection(h).unwrap().read(&mut buf), Ok(32768));
    let out = drain(&mut ep, t);
    let b = on(&out, &bsyn);
    assert!(
        matches!(mp_join(&b[0]).0, MpJoin::Ack { .. }),
        "B's retry first"
    );
    let update = on(&out, &csyn);
    assert!(
        update.iter().any(|s| s.wnd > 0 && dack(s) == dsn + 32768),
        "C's window update: {update:?}"
    );
}

#[test]
fn read_window_update_after_subflow_fin_goes_on_other_subflow() {
    let (mut ep, h, syn, dsn) = connected_scaled_cc(8192, Some(reno));
    open_window(&mut ep, &syn, h);
    let (_, jsyn) = joined(&mut ep, h, ms(10), JOIN_IP, 1500, 7);
    // The peer nearly fills the receive buffer on subflow 0, then retires it with a bare FIN.
    for k in 0..7u32 {
        let opts = mapping(1 + k * 1024, dsn + u64::from(k) * 1024, 1024);
        let payload = [k as u8; 1024];
        let seg = peer_data(&syn, 5001 + k * 1024, &opts, &payload);
        input_at(&mut ep, &seg, ms(20));
    }
    let fin = Segment {
        flags: TcpFlags::ACK | TcpFlags::FIN,
        ..peer_data(&syn, 5001 + 7168, &[], &[])
    };
    input_at(&mut ep, &fin, ms(20));
    drain(&mut ep, ms(20));
    assert_eq!(ep.conns[&h].subflows[0].state, SubflowState::Closing);
    let mut buf = [0; 8192];
    assert_eq!(ep.connection(h).unwrap().read(&mut buf), Ok(7168));
    let out = drain(&mut ep, ms(20));
    let update: Vec<_> = (on(&out, &jsyn).into_iter())
        .filter(|s| s.wnd > 0)
        .collect();
    assert_eq!(update.len(), 1, "the update goes on subflow 1");
    assert_eq!(dack(&update[0]), dsn + 7168);
}

#[test]
fn bare_fin_then_late_data_fin_on_only_subflow() {
    let (mut ep, h, syn, dsn) = confirmed_cc(reno);
    let head = una(&ep, h);
    // A bare FIN, then the peer's ACK-only DATA_FIN (reordered after it), both before we
    // send anything.
    let fin = Segment {
        flags: TcpFlags::ACK | TcpFlags::FIN,
        ..peer_data(&syn, 5001, &[], &[])
    };
    input_at(&mut ep, &fin, ms(20));
    let opts = fin_option(dsn, 0, 1, Some(head));
    input_at(&mut ep, &peer_data(&syn, 5002, &opts, &[]), ms(20));
    assert_eq!(ep.conns[&h].subflows[0].state, SubflowState::Closing);
    assert_eq!(ep.connection(h).unwrap().read(&mut [0; 1]), Ok(0), "EOF");
    // The subflow is closed from our side at once; pending data waits for a new subflow,
    // and our DATA_FIN does not go on the retired subflow.
    ep.connection(h).unwrap().write(&[5; 3000]).unwrap();
    ep.connection(h).unwrap().close();
    let out = on(&drain(&mut ep, ms(20)), &syn);
    let ours = out
        .iter()
        .find(|s| s.flags.contains(TcpFlags::FIN))
        .expect("our FIN");
    assert!(out.iter().all(|s| s.payload.is_empty() && !data_fin(s)));
    let ack = Segment {
        ack: ours.seq.wrapping_add(1),
        ..peer_data(&syn, 5002, &[], &[])
    };
    input_at(&mut ep, &ack, ms(30));
    assert_eq!(ep.conns[&h].subflows[0].tcb.state(), TcpState::Closed);
    let at = ep.poll_timeout().unwrap();
    assert_eq!(at, ms(30) + Duration::from_secs(60), "the no-subflow wait");
    ep.handle_timeout(at);
    let timeout = Event::Closed {
        reason: CloseReason::Timeout,
    };
    let down = initial_down(CloseReason::Normal);
    assert_eq!(events(&mut ep), vec![down, timeout]);
}

#[test]
fn initial_subflow_r2_resets_once_joined() {
    let n = 100_000;
    let (mut ep, h, mut peer, t, head, data) = two_paths_primed(Duration::from_secs(3), n);
    let r2 = Duration::from_secs(3);
    ep.conns.get_mut(&h).unwrap().subflows[0]
        .tcb
        .set_r2_data(r2);
    peer.drop[0] = true;
    // Subflow 0 holds the first 10,000 octets when its path fails.
    pin(&mut ep, h, Some(SubflowId(0)));
    assert_eq!(ep.connection(h).unwrap().write(&data[..10_000]), Ok(10_000));
    for p in drain(&mut ep, t) {
        peer.take(t, leak(p));
    }
    pin(&mut ep, h, None);
    assert_eq!(
        ep.connection(h).unwrap().write(&data[10_000..]),
        Ok(n - 10_000)
    );
    peer.run(&mut ep, h, t, t + Duration::from_secs(30));
    let down = Event::SubflowDown {
        subflow: SubflowId::INITIAL,
        reason: CloseReason::Timeout,
        rst: None,
    };
    assert_eq!(events(&mut ep), vec![down], "R2 before R1: no Stale");
    let rst = |p: &(usize, Segment)| p.0 == 0 && p.1.flags.contains(TcpFlags::RST);
    assert!(peer.sent.iter().any(rst), "subflow 0 reset at R2");
    assert_eq!(
        moved_at(&peer, 0, 1),
        Some(t + r2),
        "re-sent on subflow 1 at R2"
    );
    assert_eq!(una(&ep, h), head + n as u64);
    assert_eq!(peer.received(), data);
}

#[test]
fn ended_joined_subflow_freed_at_teardown() {
    let (mut ep, h, _, jsyn) = two_paths(reno, reno);
    input_at(&mut ep, &rst_on(&jsyn), ms(20));
    assert_eq!(ep.conns[&h].subflows.len(), 1, "freed at once");
    assert!(
        !ep.demux.contains_key(&(jsyn.src, jsyn.dst)),
        "port released"
    );
    // A late peer segment for it draws a RST.
    input_at(&mut ep, &peer_data(&jsyn, 5001, &[], &[]), ms(21));
    assert!(rst_from(&drain(&mut ep, ms(21)), &jsyn));
}

// Task 7 fix round 1 (ruling R17): only other subflows' data counts as stranded.

#[test]
fn stale_then_stripped_single_subflow_falls_back() {
    let (mut ep, h, syn, _) = connected_with_capacity(64);
    let syn = packet::parse(syn.leak()).unwrap();
    let t0 = ms(1);
    ep.connection(h).unwrap().write(b"first").unwrap();
    let sent = data_on(&drain(&mut ep, t0), &syn).pop().unwrap();
    assert_eq!(sent.payload, b"first");
    // Three RTOs: the only subflow goes Stale and its range is queued.
    drain_until(&mut ep, t0, t0 + Duration::from_secs(8));
    let stale = Event::SubflowStale {
        subflow: SubflowId(0),
    };
    assert_eq!(events(&mut ep), vec![stale]);
    // Then the data is ACKed without any MPTCP option: the path strips options.
    let t = t0 + Duration::from_secs(8);
    let stripped = Segment {
        ack: end(&sent),
        ..peer_data(&syn, 5001, &[], &[])
    };
    input_at(&mut ep, &stripped, t);
    assert_eq!(events(&mut ep), vec![Event::FellBack]);
    ep.connection(h).unwrap().write(b"second").unwrap();
    let out = on(&drain(&mut ep, t), &syn);
    assert!(out.iter().any(infinite_mapping));
    let data: Vec<_> = out.iter().filter(|s| !s.payload.is_empty()).collect();
    assert_eq!(data.len(), 1);
    assert_eq!((data[0].seq, data[0].payload), (end(&sent), &b"second"[..]));
    assert!(
        infinite_mapping(data[0]),
        "the data after the switch carries the infinite mapping until acknowledged"
    );
}

#[test]
fn infinite_mapping_on_stale_survivor_is_not_data_loss() {
    let (mut ep, h, syn, jsyn) = two_paths(reno, reno);
    let head = una(&ep, h);
    // Subflow 0's window is closed, so nothing moves to it.
    peer_ack(&mut ep, &syn, ms(20), syn.seq.wrapping_add(1), head, 0);
    pin(&mut ep, h, Some(SubflowId(1)));
    ep.connection(h).unwrap().write(&[4; 1000]).unwrap();
    let b = data_on(&drain(&mut ep, ms(20)), &jsyn).pop().unwrap();
    pin(&mut ep, h, None);
    let t = ms(20) + Duration::from_secs(8);
    let out = drain_until(&mut ep, ms(20), t);
    assert!(data_on(&out, &syn).is_empty());
    assert_eq!(events(&mut ep), vec![STALE1]);
    // The infinite mapping arrives on Stale subflow 1 and TCP-ACKs its data.
    let inf = mapping(1, peer_dsn(), 0);
    let seg = Segment {
        ack: end(&b),
        ..peer_data(&jsyn, 5001, &inf, b"reply")
    };
    input_at(&mut ep, &seg, t);
    assert_eq!(events(&mut ep), vec![Event::FellBack]);
    assert_eq!(una(&ep, h), head + 1000);
    // Subflow 1 carries the connection now, Stale or not.
    ep.connection(h).unwrap().write(&[5; 500]).unwrap();
    let more = data_on(&drain(&mut ep, t), &jsyn);
    assert_eq!(more.iter().map(|s| s.payload.len()).sum::<usize>(), 500);
}

#[test]
fn infinite_mapping_after_other_subflow_acked_without_data_ack_closes() {
    let (mut ep, h, syn, jsyn) = two_paths(reno, reno);
    let head = una(&ep, h);
    // Subflow 0's data is subflow-ACKed but not DATA_ACKed.
    pin(&mut ep, h, Some(SubflowId(0)));
    ep.connection(h).unwrap().write(&[6; 1000]).unwrap();
    let a = data_on(&drain(&mut ep, ms(20)), &syn).pop().unwrap();
    pin(&mut ep, h, None);
    peer_ack(&mut ep, &syn, ms(30), end(&a), head, 65535);
    peer_infinite_mapping(&mut ep, &jsyn, ms(31));
    let loss = Event::Closed {
        reason: CloseReason::FallbackDataLoss,
    };
    assert_eq!(events(&mut ep), vec![loss]);
}

// Task 8c (ruling R18): subflows left with only DATA_ACKed data at close.

/// `drain` at `now`, then `handle_timeout` and `drain` at every deadline up to `until`; every
/// segment we sent, with its time.
fn drive(
    ep: &mut Endpoint<ChaCha20Rng>,
    now: Instant,
    until: Instant,
) -> Vec<(Instant, Segment<'static>)> {
    let mut out: Vec<_> = drain(ep, now).into_iter().map(|p| (now, leak(p))).collect();
    while let Some(t) = ep.poll_timeout().filter(|&t| t <= until) {
        ep.handle_timeout(t);
        out.extend(drain(ep, t).into_iter().map(|p| (t, leak(p))));
    }
    out
}
const BIG_R2: Duration = Duration::from_secs(1000);

#[test]
fn stranded_subflow_reset_once_both_data_fins_acked() {
    let n = 200_000;
    let (mut ep, h, mut peer, t, head, data) = two_paths_primed(BIG_R2, n);
    let syn = peer.syns[0].clone();
    peer.drop[1] = true;
    assert_eq!(ep.connection(h).unwrap().write(&data), Ok(n));
    let now = peer.run(&mut ep, h, t, t + Duration::from_secs(30));
    assert_eq!(events(&mut ep), vec![STALE1]);
    assert_eq!(una(&ep, h), head + n as u64, "reinjected via subflow 0");
    assert!(ep.conns[&h].subflows[1].tcb.has_unacked(), "stranded");
    // Close: the DATA_FIN goes on subflow 0; the peer DATA_ACKs it and sends its own there.
    ep.connection(h).unwrap().close();
    let out = drain(&mut ep, now);
    let dfin = (on(&out, &syn).into_iter().find(data_fin)).expect("DATA_FIN on subflow 0");
    let t1 = now + Duration::from_millis(30);
    let opts = fin_option(peer_dsn(), 0, 1, Some(head + n as u64 + 1));
    let seg = Segment {
        ack: dfin.seq,
        wnd: 65535,
        ..peer_data(&syn, 5001, &opts, &[])
    };
    input_at(&mut ep, &seg, t1);
    let out = drain(&mut ep, t1);
    let fin0 = (on(&out, &syn).into_iter())
        .find(|s| s.flags.contains(TcpFlags::FIN))
        .expect("FIN on subflow 0");
    assert!(
        out.iter()
            .map(|p| leak(p.clone()))
            .all(|s| !s.flags.contains(TcpFlags::RST))
    );
    // The peer completes subflow 0's FIN exchange; subflow 1's path stays dead.
    let dack_fin = data_ack(head + n as u64 + 1);
    let seg = Segment {
        flags: TcpFlags::ACK | TcpFlags::FIN,
        ack: fin0.seq.wrapping_add(1),
        wnd: 65535,
        ..peer_data(&syn, 5001, &dack_fin, &[])
    };
    let t2 = t1 + Duration::from_millis(30);
    input_at(&mut ep, &seg, t2);
    let out = drive(&mut ep, t2, t1 + Duration::from_secs(300));
    let jsrc = peer.syns[1].src;
    let on1: Vec<_> = out.iter().filter(|(_, s)| s.src == jsrc).collect();
    let rst = (on1
        .iter()
        .position(|(_, s)| s.flags.contains(TcpFlags::RST)))
    .expect("RST on 1");
    // One un-backed-off RTO (1 s minimum) after both DATA_FINs were DATA_ACKed.
    assert_eq!(on1[rst].0, t1 + Duration::from_secs(1));
    assert!(
        on1.iter().all(|(_, s)| !s.flags.contains(TcpFlags::FIN)),
        "no FIN on 1"
    );
    assert_eq!(on1.len(), rst + 1, "nothing on subflow 1 after the RST");
    let ev = events(&mut ep);
    // Subflow 0's FIN exchange ended first (TIME-WAIT), while subflow 1 was still open.
    let down0 = Event::SubflowDown {
        subflow: SubflowId::INITIAL,
        reason: CloseReason::Normal,
        rst: None,
    };
    let down = Event::SubflowDown {
        subflow: SubflowId(1),
        reason: CloseReason::Reset,
        rst: None,
    };
    let closed = Event::Closed {
        reason: CloseReason::Normal,
    };
    assert_eq!(ev, vec![down0, down, closed]);
    assert!(
        ep.conns.is_empty(),
        "closed at subflow 0's TIME-WAIT end, not at R2"
    );
}

/// The single RST we send at `now` in answer to `seg` (exactly one packet out).
fn answer(ep: &mut Endpoint<ChaCha20Rng>, seg: &Segment, now: Instant) -> Option<Segment<'static>> {
    input_at(ep, seg, now);
    let out: Vec<_> = drain(ep, now).into_iter().map(leak).collect();
    assert!(out.len() <= 1, "one answer at most: {out:?}");
    out.into_iter().next()
}

/// RFC 9293 §3.10.7.1: subflow 0 is reset (stranded, Task 8c) while subflow 1 lives on in
/// TIME-WAIT, so its Closed TCB still owns the 4-tuple. Segments reaching it are answered as
/// in CLOSED (Linux's FIN after a blackhole, a challenge ACK to our RST); TIME-WAIT is not.
#[test]
fn closed_initial_subflow_answers_with_rst() {
    let n = 200_000;
    let (mut ep, h, mut peer, t, head, data) = two_paths_primed(BIG_R2, n);
    let (syn, jsyn) = (peer.syns[0].clone(), peer.syns[1].clone());
    peer.drop[0] = true;
    assert_eq!(ep.connection(h).unwrap().write(&data), Ok(n));
    let now = peer.run(&mut ep, h, t, t + Duration::from_secs(30));
    events(&mut ep);
    assert_eq!(una(&ep, h), head + n as u64, "reinjected via subflow 1");
    assert!(ep.conns[&h].subflows[0].tcb.has_unacked(), "stranded");
    // Both DATA_FINs and subflow 1's FIN exchange complete on subflow 1.
    ep.connection(h).unwrap().close();
    let out = drain(&mut ep, now);
    let dfin = (on(&out, &jsyn).into_iter().find(data_fin)).expect("DATA_FIN on 1");
    let t1 = now + Duration::from_millis(10);
    let opts = fin_option(peer_dsn(), 0, 1, Some(head + n as u64 + 1));
    let seg = Segment {
        ack: dfin.seq,
        wnd: 65535,
        ..peer_data(&jsyn, 5001, &opts, &[])
    };
    input_at(&mut ep, &seg, t1);
    let out = drain(&mut ep, t1);
    let fin1 = (on(&out, &jsyn).into_iter())
        .find(|s| s.flags.contains(TcpFlags::FIN))
        .expect("FIN on 1");
    let dack_fin = data_ack(head + n as u64 + 1);
    let fin_ack = Segment {
        flags: TcpFlags::ACK | TcpFlags::FIN,
        ack: fin1.seq.wrapping_add(1),
        wnd: 65535,
        ..peer_data(&jsyn, 5001, &dack_fin, &[])
    };
    input_at(&mut ep, &fin_ack, t1);
    let out = drive(&mut ep, t1, t1 + Duration::from_secs(5));
    let rst0 = |(_, s): &(Instant, Segment)| s.src == syn.src && s.flags.contains(TcpFlags::RST);
    assert_eq!(out.iter().filter(|x| rst0(x)).count(), 1, "abort RST on 0");
    assert_eq!(ep.conns[&h].subflows[0].tcb.state(), TcpState::Closed);
    assert_eq!(ep.conns[&h].subflows[1].tcb.state(), TcpState::TimeWait);
    events(&mut ep);
    let late = t1 + Duration::from_secs(20);
    // The peer's FIN (lost in the blackhole until now): <SEQ=SEG.ACK><CTL=RST>.
    let ack = syn.seq.wrapping_add(4321);
    let fin = Segment {
        flags: TcpFlags::ACK | TcpFlags::FIN,
        ack,
        ..peer_data(&syn, 5001, &[], &[])
    };
    let rst = answer(&mut ep, &fin, late).expect("RST for the FIN");
    assert_eq!((rst.src, rst.dst), (syn.src, syn.dst));
    assert_eq!((rst.seq, rst.flags), (ack, TcpFlags::RST));
    // A challenge ACK (RFC 5961) to our abort RST: the same rule.
    let ack = syn.seq.wrapping_add(99);
    let chal = Segment {
        ack,
        ..peer_data(&syn, 5001, &[], &[])
    };
    let rst = answer(&mut ep, &chal, late).expect("RST for the challenge ACK");
    assert_eq!((rst.seq, rst.flags), (ack, TcpFlags::RST));
    // No ACK bit: <SEQ=0><ACK=SEG.SEQ+SEG.LEN><CTL=RST,ACK>.
    let bare = Segment {
        flags: TcpFlags::FIN,
        ack: SeqNum(0),
        ..peer_data(&syn, 5001, &[], b"xy")
    };
    let rst = answer(&mut ep, &bare, late).expect("RST for the bare FIN");
    assert_eq!(
        (rst.seq, rst.ack, rst.flags),
        (SeqNum(0), SeqNum(5004), TcpFlags::RST | TcpFlags::ACK)
    );
    // Never a RST for a RST.
    assert!(answer(&mut ep, &rst_on(&syn), late).is_none());
    // Subflow 1 in TIME-WAIT ACKs a retransmitted FIN, no RST.
    let ack1 = answer(&mut ep, &fin_ack, late).expect("TIME-WAIT ACK");
    assert_eq!(ack1.src, jsyn.src);
    assert!(!ack1.flags.contains(TcpFlags::RST));
    assert!(events(&mut ep).is_empty());
    assert!(ep.conns.contains_key(&h));
}

#[test]
fn subflow_with_data_not_data_acked_is_not_reset() {
    let n = 200_000;
    let (mut ep, h, mut peer, t, head, data) = two_paths_primed(BIG_R2, n);
    let syn = peer.syns[0].clone();
    peer.drop[1] = true;
    assert_eq!(ep.connection(h).unwrap().write(&data), Ok(n));
    let now = peer.run(&mut ep, h, t, t + Duration::from_secs(2));
    assert!(una(&ep, h) < head + n as u64, "subflow 1 holds a hole");
    // The peer's DATA_FIN is DATA_ACKed and the app closes; ours cannot be DATA_ACKed yet.
    let opts = fin_option(peer_dsn(), 0, 1, None);
    let seg = peer_data(&syn, 5001, &opts, &[]);
    input_at(&mut ep, &seg, now);
    ep.connection(h).unwrap().close();
    let out = drive(&mut ep, now, t + Duration::from_millis(6900));
    assert!(out.iter().all(|(_, s)| !s.flags.contains(TcpFlags::RST)));
    assert!(ep.conns[&h].subflows[1].tcb.state() != TcpState::Closed);
    assert!(events(&mut ep).is_empty());
}

#[test]
fn late_tcp_ack_within_rto_closes_with_fin() {
    let (mut ep, h, syn, jsyn) = two_paths(reno, reno);
    let (t, una0) = prime(&mut ep, h, &syn, SubflowId(0), ms(20), 30);
    let (t, _) = prime(&mut ep, h, &jsyn, SubflowId(1), t, 10);
    events(&mut ep);
    let head = una(&ep, h);
    pin(&mut ep, h, Some(SubflowId(1)));
    ep.connection(h).unwrap().write(&[7; 1000]).unwrap();
    ep.connection(h).unwrap().close();
    let out = drain(&mut ep, t);
    let b = data_on(&out, &jsyn).pop().unwrap();
    assert!(data_fin(&b), "DATA_FIN rides on the data");
    // The DATA_ACK of the data and DATA_FIN comes on subflow 0, with the peer's DATA_FIN,
    // before subflow 1's own TCP ACK.
    let t1 = t + Duration::from_millis(5);
    let opts = fin_option(peer_dsn(), 0, 1, Some(head + 1001));
    let seg = Segment {
        ack: una0,
        wnd: 65535,
        ..peer_data(&syn, 5001, &opts, &[])
    };
    input_at(&mut ep, &seg, t1);
    let mut out = drive(&mut ep, t1, t1 + Duration::from_millis(500));
    peer_ack(
        &mut ep,
        &jsyn,
        t1 + Duration::from_millis(500),
        end(&b),
        head + 1001,
        65535,
    );
    out.extend(drive(
        &mut ep,
        t1 + Duration::from_millis(500),
        t1 + Duration::from_secs(2),
    ));
    assert!(
        out.iter().all(|(_, s)| !s.flags.contains(TcpFlags::RST)),
        "no RST"
    );
    let fin1 = |(_, s): &&(Instant, Segment)| s.src == jsyn.src && s.flags.contains(TcpFlags::FIN);
    assert!(
        out.iter().any(|x| fin1(&x)),
        "subflow 1 FINs once its data is ACKed"
    );
    assert!(events(&mut ep).is_empty());
}

#[test]
fn single_subflow_close_is_fin_only() {
    let (mut ep, h, syn, _) = confirmed_cc(reno);
    let head = una(&ep, h);
    ep.connection(h).unwrap().write(&[8; 1000]).unwrap();
    ep.connection(h).unwrap().close();
    let mut out = drive(&mut ep, ms(10), ms(10));
    let seg = (out.iter().map(|x| &x.1))
        .find(|s| !s.payload.is_empty())
        .unwrap()
        .clone();
    let opts = fin_option(peer_dsn(), 0, 1, Some(head + 1001));
    let ack = Segment {
        ack: end(&seg),
        wnd: 65535,
        ..peer_data(&syn, 5001, &opts, &[])
    };
    input_at(&mut ep, &ack, ms(40));
    let dack_fin = data_ack(head + 1001);
    let more = drive(&mut ep, ms(40), ms(40));
    let fin = (more.iter().map(|x| &x.1))
        .find(|s| s.flags.contains(TcpFlags::FIN))
        .unwrap()
        .clone();
    out.extend(more);
    let seg = Segment {
        flags: TcpFlags::ACK | TcpFlags::FIN,
        ack: fin.seq.wrapping_add(1),
        wnd: 65535,
        ..peer_data(&syn, 5001, &dack_fin, &[])
    };
    input_at(&mut ep, &seg, ms(70));
    out.extend(drive(&mut ep, ms(70), ms(70) + Duration::from_secs(300)));
    assert!(
        out.iter().all(|(_, s)| !s.flags.contains(TcpFlags::RST)),
        "no RST"
    );
    let closed = Event::Closed {
        reason: CloseReason::Normal,
    };
    assert_eq!(events(&mut ep), vec![closed]);
    assert!(ep.conns.is_empty());
}

/// With SACK negotiated on both subflows and an out-of-order receipt held on each, every
/// segment carries a SACK block beside its DSS (28 + 12 = 40 octets), and `seg_payload`
/// leaves room for it: no IP packet exceeds its subflow's MTU (1500 and 1280).
#[test]
fn per_subflow_mtu_bound_with_sack_blocks() {
    let (mut ep, h, syn, dsn) = connected_with(1 << 20, Some(reno), true);
    open_window(&mut ep, &syn, h);
    ep.cc = Some(reno);
    let (id1, jsyn) = join_syn(&mut ep, h, ms(10), JOIN_IP, 1280);
    let mut opts = synack_opts(&ep, h, &jsyn, 7, None);
    opts.extend_from_slice(&[4, 2, 1, 1]);
    synack(&mut ep, &jsyn, &opts, ms(10));
    let ack = from(&drain(&mut ep, ms(10)), JOIN_IP)
        .pop()
        .expect("third ACK");
    assert_third_ack(&ep, h, &jsyn, &ack);
    let head = una(&ep, h);
    peer_ack(&mut ep, &jsyn, ms(10), jsyn.seq.wrapping_add(1), head, 1000);
    assert_eq!(events(&mut ep), vec![Event::SubflowUp { subflow: id1 }]);
    // One out-of-order octet on each subflow (a hole at SSN 1–2).
    for (s, off) in [(&syn, 0), (&jsyn, 100)] {
        let m = mapping(3, dsn + 1000 + off, 1);
        input_at(&mut ep, &peer_data(s, 5003, &m, b"x"), ms(15));
    }
    drain(&mut ep, ms(15));
    // 1460 − 40 and 1240 − 40 octets of payload.
    for (s, id, mtu, seg) in [(&syn, SubflowId(0), 1500, 1420), (&jsyn, id1, 1280, 1200)] {
        pin(&mut ep, h, Some(id));
        ep.connection(h).unwrap().write(&vec![1; 2 * seg]).unwrap();
        let out = drain(&mut ep, ms(20));
        assert!(
            out.iter().all(|p| p.len() <= mtu),
            "IP packet within MTU {mtu}"
        );
        let data = data_on(&out, s);
        assert_eq!(data.len(), 2, "two full segments on MTU {mtu}");
        for d in &data {
            assert_eq!(d.payload.len(), seg);
            assert_eq!(d.options.len(), 40);
            assert!(walk(d.options).any(|o| matches!(o, Ok(TcpOpt::Sack(b)) if b.len() == 8)));
        }
        let last = data.last().unwrap();
        let head = una(&ep, h);
        peer_ack(&mut ep, s, ms(20), end(last), head, 1000);
        drain(&mut ep, ms(20));
    }
}

// M3 Task 1: opportunistic retransmission and penalization (M3 spec §2). Subflow 0 is path B
// (30 ms), the one that blackholes; subflow 1 is path A (10 ms).

thread_local! {
    /// `Penalized` events per subflow, counted by `Counting` controllers.
    static PENALIZED: std::cell::Cell<[u32; 2]> = const { std::cell::Cell::new([0, 0]) };
}
/// Fixed cwnd, paced at `rate` if set; counts `Penalized` for subflow `path`.
struct Counting {
    path: usize,
    cwnd: u32,
    rate: Option<u64>,
}
impl CongestionControl for Counting {
    fn on_ack(&mut self, _: &AckSample) {}
    fn on_congestion(&mut self, ev: CongestionEvent, _: u32, _: Instant) {
        if ev == CongestionEvent::Penalized {
            PENALIZED.with(|p| {
                let mut n = p.get();
                n[self.path] += 1;
                p.set(n);
            });
        }
    }
    fn on_recovery_ack(&mut self, _: RecoveryAck) {}
    fn cwnd(&self) -> u32 {
        self.cwnd
    }
    fn pacing_rate(&self) -> Option<u64> {
        self.rate
    }
}
const SEG: usize = 1432;
/// B: room for exactly its two-segment run at the head.
fn cc_b() -> Box<dyn CongestionControl> {
    Box::new(Counting {
        path: 0,
        cwnd: 2 * SEG as u32,
        rate: None,
    })
}
fn cc_a() -> Box<dyn CongestionControl> {
    Box::new(Counting {
        path: 1,
        cwnd: 64 << 10,
        rate: None,
    })
}
/// A with four segments of cwnd: several A RTTs to assign a 32-segment store.
fn cc_a_small() -> Box<dyn CongestionControl> {
    Box::new(Counting {
        path: 1,
        cwnd: 4 * SEG as u32,
        rate: None,
    })
}
fn cc_a_paced() -> Box<dyn CongestionControl> {
    Box::new(Counting {
        path: 1,
        cwnd: 64 << 10,
        rate: Some(RATE),
    })
}
fn penalized() -> [u32; 2] {
    PENALIZED.with(|p| p.get())
}
fn pattern(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i % 251) as u8).collect()
}
fn stats(ep: &mut Endpoint<ChaCha20Rng>, h: ConnectionHandle) -> crate::DebugStats {
    ep.connection(h).unwrap().debug_stats()
}
fn writable(ep: &Endpoint<ChaCha20Rng>, h: ConnectionHandle) -> usize {
    ep.conns[&h].hooks.data.as_ref().unwrap().send.writable()
}
/// `hol_rtt` with B's RTT 30 ms and A's 10 ms.
fn hol(
    b: fn() -> Box<dyn CongestionControl>,
    a: fn() -> Box<dyn CongestionControl>,
    cap: usize,
    n: usize,
) -> (
    Endpoint<ChaCha20Rng>,
    ConnectionHandle,
    Peer,
    Instant,
    u64,
    SeqNum,
) {
    hol_rtt(b, a, cap, n, 30, 10)
}
/// Both paths primed (B's RTT `rtt_b` ms, A's `rtt_a` ms) with controllers `b` and `a`, a send
/// store of `cap` octets, and a peer expecting `n` octets. Returns B's SND.UNA too.
fn hol_rtt(
    b: fn() -> Box<dyn CongestionControl>,
    a: fn() -> Box<dyn CongestionControl>,
    cap: usize,
    n: usize,
    rtt_b: u64,
    rtt_a: u64,
) -> (
    Endpoint<ChaCha20Rng>,
    ConnectionHandle,
    Peer,
    Instant,
    u64,
    SeqNum,
) {
    PENALIZED.with(|p| p.set([0, 0]));
    let (mut ep, h, syn, _) = confirmed_cc(b);
    ep.cc = Some(a);
    let (_, jsyn) = joined(&mut ep, h, ms(10), JOIN_IP, 1500, 7);
    let (t, una_b) = prime(&mut ep, h, &syn, SubflowId(0), ms(20), rtt_b);
    let (t, _) = prime(&mut ep, h, &jsyn, SubflowId(1), t, rtt_a);
    events(&mut ep);
    let head = una(&ep, h);
    let d = ep.conns.get_mut(&h).unwrap().hooks.data.as_mut().unwrap();
    d.send = crate::mptcp::data::SendStore::new(head, cap);
    let peer = Peer::new(head, n, &[(&syn, rtt_b), (&jsyn, rtt_a)]);
    (ep, h, peer, t, head, una_b)
}
/// B's two-segment run at the head of `data`, sent at `t` (the peer takes it), then the rest
/// of `data` written under MinRTT; returns how much of the rest the store took.
fn b_holds_head(
    ep: &mut Endpoint<ChaCha20Rng>,
    h: ConnectionHandle,
    peer: &mut Peer,
    t: Instant,
    data: &[u8],
) -> usize {
    pin(ep, h, Some(SubflowId(0)));
    assert_eq!(
        ep.connection(h).unwrap().write(&data[..2 * SEG]),
        Ok(2 * SEG)
    );
    let out = data_on(&drain(ep, t), &peer.syns[0]);
    assert_eq!(out.len(), 2);
    for seg in out {
        peer.take(t, seg);
    }
    pin(ep, h, None);
    ep.connection(h).unwrap().write(&data[2 * SEG..]).unwrap()
}
/// Placements on path A of octets in B's run `[head, head + 2·SEG)`: time and DSN.
fn copies(peer: &Peer, head: u64) -> Vec<(Instant, u64)> {
    (peer.log.iter())
        .filter(|l| l.1 == 1 && l.2.wrapping_sub(head) < 2 * SEG as u64)
        .map(|l| (l.0, l.2))
        .collect()
}

#[test]
fn opp_copy_on_a_when_store_full() {
    let cap = 32 * SEG;
    let (mut ep, h, mut peer, t, head, _) = hol(cc_b, cc_a, cap, cap);
    let data = pattern(cap);
    peer.drop[0] = true;
    assert_eq!(b_holds_head(&mut ep, h, &mut peer, t, &data), cap - 2 * SEG);
    assert_eq!(writable(&ep, h), 0);
    let done = peer.run(&mut ep, h, t, t + Duration::from_millis(500));
    assert_eq!(una(&ep, h), head + cap as u64, "DATA_ACK past the old head");
    assert_eq!(peer.received(), data);
    let last_new = (peer.log.iter())
        .filter(|l| l.1 == 1 && l.2 >= head + 2 * SEG as u64)
        .map(|l| l.0)
        .max()
        .unwrap();
    let copied = moved_at(&peer, 0, 1).expect("B's run copied on A");
    assert!(
        copied <= last_new + Duration::from_millis(10),
        "within one A RTT"
    );
    assert_eq!(copies(&peer, head).len(), 2, "the whole run, once");
    assert!(done < t + Duration::from_millis(100));
    assert_eq!(penalized(), [1, 0], "B penalized once");
    let s = stats(&mut ep, h);
    let s = (s.opp_triggers, s.opp_episodes, s.penalties, s.opp_bytes);
    assert_eq!(s, (1, 1, 1, 2 * SEG as u64));
}

#[test]
fn opp_no_trigger_while_new_assignable() {
    let cap = 32 * SEG;
    let (mut ep, h, mut peer, t, _, _) = hol(cc_b, cc_a_small, cap, cap);
    peer.drop[0] = true;
    b_holds_head(&mut ep, h, &mut peer, t, &pattern(cap));
    assert_eq!(writable(&ep, h), 0, "the store is full");
    peer.run(&mut ep, h, t, t + Duration::from_millis(35));
    let d = ep.conns[&h].hooks.data.as_ref().unwrap();
    assert_ne!(d.send.next, d.send.end, "unassigned data waits");
    assert_eq!(moved_at(&peer, 0, 1), None);
    let s = stats(&mut ep, h);
    assert_eq!((s.opp_triggers, s.opp_episodes, s.penalties), (0, 0, 0));
    assert_eq!(penalized(), [0, 0]);
}

#[test]
fn opp_no_penalty_sole_usable_path() {
    let cap = 32 * SEG;
    let (mut ep, h, mut peer, t, head, una_b) = hol(cc_b, cc_a, cap, cap);
    let data = pattern(cap);
    peer.drop[0] = true;
    b_holds_head(&mut ep, h, &mut peer, t, &data);
    // B's window closes: B holds the head but is not usable.
    let syn = peer.syns[0].clone();
    peer_ack(&mut ep, &syn, t, una_b, head, 0);
    assert!(ep.conns[&h].subflows[0].tcb.peer_window_closed());
    peer.run(&mut ep, h, t, t + Duration::from_millis(500));
    assert_eq!(peer.received(), data);
    assert!(moved_at(&peer, 0, 1).is_some(), "copied on A");
    assert_eq!(penalized(), [0, 0]);
    let s = stats(&mut ep, h);
    assert_eq!((s.opp_episodes, s.penalties), (1, 0));
}

#[test]
fn opp_trigger_survives_partial_data_ack() {
    let cap = 32 * SEG;
    let (mut ep, h, mut peer, t, head, _) = hol(cc_b, cc_a_small, cap, cap);
    let data = pattern(cap);
    // B's first segment reaches the peer, its TCP ACKs are lost; the second is lost.
    pin(&mut ep, h, Some(SubflowId(0)));
    ep.connection(h).unwrap().write(&data[..2 * SEG]).unwrap();
    let out = data_on(&drain(&mut ep, t), &peer.syns[0]);
    peer.take(t, out[0].clone());
    peer.drop[0] = true;
    peer.take(t, out[1].clone());
    pin(&mut ep, h, None);
    ep.connection(h).unwrap().write(&data[2 * SEG..]).unwrap();
    let now = peer.run(&mut ep, h, t, t + Duration::from_millis(15));
    let half = head + SEG as u64;
    assert_eq!(una(&ep, h), half, "DATA_ACK advanced halfway");
    let d = ep.conns[&h].hooks.data.as_ref().unwrap();
    assert!(d.send.end - d.send.una < cap as u64);
    assert_eq!(writable(&ep, h), 0, "B's mapping keeps its allocation");
    peer.run(&mut ep, h, now, t + Duration::from_millis(500));
    assert_eq!(peer.received(), data);
    let dsns: Vec<u64> = copies(&peer, head).iter().map(|c| c.1).collect();
    assert_eq!(dsns, [half], "the copy starts at send.una");
    assert_eq!(stats(&mut ep, h).opp_episodes, 1);
}

#[test]
fn opp_lost_copy_recovered_by_target_tcp() {
    let cap = 32 * SEG;
    let (mut ep, h, mut peer, t, head, _) = hol(cc_b, cc_a, cap, cap);
    let data = pattern(cap);
    peer.drop[0] = true;
    // The copy is lost, and so is its tail probe.
    let tail = head + SEG as u64;
    peer.lose = vec![(1, head, false), (1, tail, false), (1, tail, false)];
    b_holds_head(&mut ep, h, &mut peer, t, &data);
    let done = peer.run(&mut ep, h, t, t + Duration::from_secs(3));
    assert_eq!(peer.received(), data);
    assert!(peer.lose.is_empty(), "the copy was lost");
    let on_a = |dsn| {
        (peer.sent.iter())
            .filter(|(i, s)| *i == 1 && dsn_of(s, peer.syns[1].seq).map(|d| d.0) == Some(dsn))
            .count()
    };
    assert_eq!(on_a(head), 2, "the copy and A's own TCP retransmission");
    assert_eq!(
        on_a(tail),
        3,
        "the copy, the tail probe and the retransmission"
    );
    assert_eq!(stats(&mut ep, h).opp_episodes, 1, "no second episode");
    assert!(done > t + Duration::from_secs(1) && done < t + Duration::from_millis(1100));
}

#[test]
fn opp_tcp_acked_not_data_acked_repaired() {
    let cap = 32 * SEG;
    let (mut ep, h, mut peer, t, head, _) = hol(cc_b, cc_a, cap, cap);
    let data = pattern(cap);
    peer.drop[0] = true;
    peer.lose = vec![(1, head, true), (1, head + SEG as u64, true)];
    b_holds_head(&mut ep, h, &mut peer, t, &data);
    peer.run(&mut ep, h, t, t + Duration::from_secs(3));
    assert_eq!(peer.received(), data);
    // The copy (installed at t) was TCP-ACKed at t + 10 ms and dropped by the receiver: head
    // repair (M3 §2.7 H1) copies the run again 2·srtt of A later, not at the episode deadline.
    assert_eq!(moved_at(&peer, 0, 1), Some(t + Duration::from_millis(30)));
    let s = stats(&mut ep, h);
    assert_eq!((s.opp_episodes, s.opp_repairs), (1, 1));
}

#[test]
fn opp_partial_data_ack_into_copy_repaired() {
    let cap = 32 * SEG;
    let (mut ep, h, mut peer, t, head, _) = hol(cc_b, cc_a, cap, cap);
    let data = pattern(cap);
    peer.drop[0] = true;
    let half = head + SEG as u64;
    peer.lose = vec![(1, half, true)];
    b_holds_head(&mut ep, h, &mut peer, t, &data);
    peer.run(&mut ep, h, t, t + Duration::from_secs(3));
    assert_eq!(peer.received(), data);
    // DATA_ACK moved into the copy [head, head + 2·SEG) at t + 10 ms, whose TCP ACK covers both
    // segments: the new head is armed at once and repaired 2·srtt of A later (M3 §2.7).
    let c = copies(&peer, head);
    assert_eq!(c, [(t, head), (t + Duration::from_millis(30), half)]);
    let s = stats(&mut ep, h);
    assert_eq!((s.opp_episodes, s.opp_repairs), (1, 1));
}

#[test]
fn opp_pacing_blocked_target_sent_at_release() {
    let cap = 6 * SEG;
    let (mut ep, h, mut peer, t, head, _) = hol(cc_b, cc_a_paced, cap, cap);
    peer.drop[0] = true;
    b_holds_head(&mut ep, h, &mut peer, t, &pattern(cap));
    // A's four segments go out in paced bursts; no input arrives.
    let mut bursts = vec![(t, data_on(&drain(&mut ep, t), &peer.syns[1]).len())];
    let all_assigned = |ep: &Endpoint<ChaCha20Rng>| {
        let d = ep.conns[&h].hooks.data.as_ref().unwrap();
        d.send.next == d.send.end
    };
    while !all_assigned(&ep) {
        let at = ep.poll_timeout().unwrap();
        ep.handle_timeout(at);
        bursts.push((at, data_on(&drain(&mut ep, at), &peer.syns[1]).len()));
    }
    assert_eq!(bursts.iter().map(|b| b.1).sum::<usize>(), 4);
    let gap = bursts[1].0 - bursts[0].0;
    let last = bursts.last().unwrap().0;
    // The candidate exists now, A is pacing blocked: the release time is kept.
    assert_eq!(ep.poll_timeout(), Some(last + gap));
    ep.handle_timeout(last + gap);
    let out = data_on(&drain(&mut ep, last + gap), &peer.syns[1]);
    assert_eq!(
        dsn_of(&out[0], peer.syns[1].seq).unwrap().0,
        head,
        "the copy"
    );
}

#[test]
fn opp_install_respects_fin_dsn_end_slot_cap() {
    // (1) The run carries the DATA_FIN: the copy maps it too (DLL + 1). (2) A's DSN high-water
    // mark covers the copy.
    let (mut ep, h, mut peer, t, head, _) = hol(cc_b, cc_a, 2 * SEG, 2 * SEG);
    peer.drop[0] = true;
    pin(&mut ep, h, Some(SubflowId(0)));
    ep.connection(h).unwrap().write(&pattern(2 * SEG)).unwrap();
    ep.connection(h).unwrap().close();
    let b = data_on(&drain(&mut ep, t), &peer.syns[0]);
    assert!(
        b.iter()
            .all(|s| dss_map(s).unwrap().2 == 2 * SEG as u16 + 1 && data_fin(s))
    );
    pin(&mut ep, h, None);
    assert_eq!(ep.conns[&h].subflows[1].mp.dsn_end, Some(head));
    let a = data_on(&drain(&mut ep, t), &peer.syns[1]);
    assert_eq!(a.len(), 2);
    for s in &a {
        let (_, dsn, dll) = dss_map(s).unwrap();
        assert_eq!((dsn, dll, data_fin(s)), (head, 2 * SEG as u16 + 1, true));
    }
    assert_eq!(
        ep.conns[&h].subflows[1].mp.dsn_end,
        Some(head + 2 * SEG as u64)
    );
    // (3) A has all 1024 mapping slots taken: no target, nothing installed.
    let cap = 2 * SEG + 1024;
    let (mut ep, h, mut peer, t, _, _) = hol(cc_b, cc_a, cap, cap);
    peer.drop[0] = true;
    let data = pattern(cap);
    b_holds_head(&mut ep, h, &mut peer, t, &data[..2 * SEG]);
    pin(&mut ep, h, Some(SubflowId(1)));
    ep.connection(h).unwrap().set_nodelay(true);
    for b in &data[2 * SEG..] {
        ep.connection(h).unwrap().write(&[*b]).unwrap();
        assert_eq!(data_on(&drain(&mut ep, t), &peer.syns[1]).len(), 1);
    }
    pin(&mut ep, h, None);
    assert!(ep.conns[&h].subflows[1].mp.tx.is_full());
    assert_eq!(writable(&ep, h), 0);
    assert!(drain(&mut ep, t).is_empty(), "nothing installed");
    assert_eq!(ep.conns[&h].hooks.assign_failures, 0);
    assert_eq!(stats(&mut ep, h).opp_episodes, 0);
}

#[test]
fn opp_tail_no_trigger() {
    let n = 22 * SEG;
    let (mut ep, h, mut peer, t, head, _) = hol(cc_b, cc_a, 16 << 20, n);
    peer.drop[0] = true;
    b_holds_head(&mut ep, h, &mut peer, t, &pattern(n));
    peer.run(&mut ep, h, t, t + Duration::from_millis(900));
    let d = ep.conns[&h].hooks.data.as_ref().unwrap();
    assert_eq!(
        (d.send.next, d.send.una),
        (d.send.end, head),
        "idle, B's hole"
    );
    assert!(writable(&ep, h) > 0);
    assert_eq!(moved_at(&peer, 0, 1), None);
    let s = stats(&mut ep, h);
    assert_eq!((s.opp_triggers, s.opp_episodes, s.penalties), (0, 0, 0));
}

#[test]
fn opp_window_boundary_tail_no_trigger() {
    let n = 22 * SEG;
    let (mut ep, h, mut peer, t, head, _) = hol(cc_b, cc_a, 16 << 20, n);
    peer.drop[0] = true;
    set_edge(&mut ep, h, head + n as u64);
    b_holds_head(&mut ep, h, &mut peer, t, &pattern(n));
    // No ACK arrives: the edge stays where all data ends.
    let out = drain_until(&mut ep, t, t + Duration::from_millis(900));
    let d = ep.conns[&h].hooks.data.as_ref().unwrap();
    assert_eq!(
        (d.send.next, d.send.end),
        (head + n as u64, head + n as u64)
    );
    assert_eq!(edge(&ep, h), Some(head + n as u64));
    assert!(writable(&ep, h) > 0);
    let copy =
        |s: &Segment| dsn_of(s, peer.syns[1].seq).is_some_and(|d| d.0 < head + 2 * SEG as u64);
    assert!(!data_on(&out, &peer.syns[1]).iter().any(copy));
    assert_eq!(stats(&mut ep, h).opp_triggers, 0);
}

#[test]
fn penalty_rate_limited_and_skipped_in_recovery() {
    let (mut ep, h, mut peer, t, head, una_b) = hol(cc_b, cc_a, 1 << 20, 4 * SEG);
    peer.drop[0] = true;
    b_holds_head(&mut ep, h, &mut peer, t, &pattern(2 * SEG));
    let srtt = ep.conns[&h].subflows[0].tcb.srtt().unwrap();
    let blocked = |ep: &mut Endpoint<ChaCha20Rng>, at: Instant| {
        ep.conns.get_mut(&h).unwrap().head_blocked(0, at);
        penalized()[0]
    };
    assert_eq!(blocked(&mut ep, t), 1);
    assert_eq!(
        blocked(&mut ep, t + (srtt - Duration::from_nanos(1))),
        1,
        "once per srtt"
    );
    assert_eq!(blocked(&mut ep, t + srtt), 2);
    // Loss recovery: three duplicate ACKs on B.
    let syn = peer.syns[0].clone();
    let t2 = t + 3 * srtt;
    for _ in 0..3 {
        peer_ack(&mut ep, &syn, t2, una_b, head, 65535);
    }
    drain(&mut ep, t2);
    assert_eq!(blocked(&mut ep, t2), 2, "in fast recovery");
    // RTO backoff.
    let (mut ep, h, mut peer, t, ..) = hol(cc_b, cc_a, 1 << 20, 4 * SEG);
    peer.drop[0] = true;
    b_holds_head(&mut ep, h, &mut peer, t, &pattern(2 * SEG));
    let t3 = t + Duration::from_millis(1500);
    drain_until(&mut ep, t, t3);
    assert_eq!(ep.conns[&h].subflows[0].tcb.rto_streak(), 1);
    assert_eq!(blocked(&mut ep, t3), 0, "in RTO backoff");
    assert_eq!(stats(&mut ep, h).penalties, 0);
}

/// Data segments sent on `path` whose mapping starts at `dsn`, lost ones included.
fn sent_at_dsn(peer: &Peer, path: usize, dsn: u64) -> usize {
    (peer.sent.iter())
        .filter(|(i, s)| *i == path && dsn_of(s, peer.syns[path].seq).map(|d| d.0) == Some(dsn))
        .count()
}

#[test]
fn opp_copy_tail_loss_probed() {
    let cap = 32 * SEG;
    let (mut ep, h, mut peer, t, head, _) = hol(cc_b, cc_a, cap, cap);
    let data = pattern(cap);
    peer.drop[0] = true;
    let tail = head + SEG as u64;
    // Only the copy's last segment is lost, and nothing follows it on A.
    peer.lose = vec![(1, tail, false)];
    b_holds_head(&mut ep, h, &mut peer, t, &data);
    let done = peer.run(&mut ep, h, t, t + Duration::from_secs(3));
    assert_eq!(peer.received(), data);
    let srtt = ep.conns[&h].subflows[1].tcb.srtt().unwrap();
    assert_eq!(srtt, Duration::from_millis(10));
    // The probe resends the tail at the copy's last transmission + 2·srtt.
    assert_eq!(copies(&peer, head), [(t, head), (t + 2 * srtt, tail)]);
    assert_eq!(sent_at_dsn(&peer, 1, tail), 2);
    assert!(
        done <= t + 3 * srtt,
        "DATA_ACK past the old head long before A's RTO"
    );
    assert_eq!(stats(&mut ep, h).opp_episodes, 1);
}

#[test]
fn opp_tail_probe_once_and_disarmed_on_ack() {
    // The tail and its probe are lost: no second probe; A's RTO recovers it.
    let cap = 32 * SEG;
    let (mut ep, h, mut peer, t, head, _) = hol(cc_b, cc_a, cap, cap);
    let data = pattern(cap);
    peer.drop[0] = true;
    let tail = head + SEG as u64;
    peer.lose = vec![(1, tail, false), (1, tail, false)];
    b_holds_head(&mut ep, h, &mut peer, t, &data);
    let now = peer.run(&mut ep, h, t, t + Duration::from_millis(900));
    assert_eq!(sent_at_dsn(&peer, 1, tail), 2, "the copy and one probe");
    assert!(ep.conns[&h].opp.as_ref().is_some_and(|e| e.probed));
    peer.run(&mut ep, h, now, t + Duration::from_secs(3));
    assert_eq!(peer.received(), data);
    assert_eq!(
        sent_at_dsn(&peer, 1, tail),
        3,
        "then A's RTO retransmission"
    );
    // The copy is ACKed within the PTO: no probe at all.
    let (mut ep, h, mut peer, t, head, _) = hol(cc_b, cc_a, cap, cap);
    peer.drop[0] = true;
    b_holds_head(&mut ep, h, &mut peer, t, &data);
    peer.run(&mut ep, h, t, t + Duration::from_secs(3));
    assert_eq!(peer.received(), data);
    let tail = head + SEG as u64;
    assert_eq!(
        (sent_at_dsn(&peer, 1, head), sent_at_dsn(&peer, 1, tail)),
        (1, 1)
    );
    // A's ACK covers the copy but DATA_ACK does not (the receiver dropped it): the episode
    // runs on, its probe is disarmed.
    let (mut ep, h, mut peer, t, head, _) = hol(cc_b, cc_a, cap, cap);
    peer.drop[0] = true;
    peer.lose = vec![(1, head, true), (1, head + SEG as u64, true)];
    b_holds_head(&mut ep, h, &mut peer, t, &data);
    peer.run(&mut ep, h, t, t + Duration::from_millis(15));
    assert!(ep.conns[&h].opp.is_some());
    assert_eq!(ep.conns[&h].opp_probe_at(), None);
}

// M3 §2.7: head repair (H1) and bounded lookahead (H2).

fn ms_d(n: u64) -> Duration {
    Duration::from_millis(n)
}
/// Like `cc_a_paced`, slower: a two-segment release every 25 ms.
fn cc_a_paced_25() -> Box<dyn CongestionControl> {
    Box::new(Counting {
        path: 1,
        cwnd: 64 << 10,
        rate: Some(RATE * 4 / 5),
    })
}
fn cc_b_big() -> Box<dyn CongestionControl> {
    Box::new(Counting {
        path: 0,
        cwnd: 64 << 10,
        rate: None,
    })
}
/// Writes `data` pinned to subflow `sf` and hands what it sends at `t` to the peer.
fn pinned(
    ep: &mut Endpoint<ChaCha20Rng>,
    h: ConnectionHandle,
    peer: &mut Peer,
    t: Instant,
    sf: u8,
    data: &[u8],
) {
    pin(ep, h, Some(SubflowId(sf.into())));
    assert_eq!(ep.connection(h).unwrap().write(data), Ok(data.len()));
    for seg in data_on(&drain(ep, t), &peer.syns[usize::from(sf)].clone()) {
        peer.take(t, seg);
    }
    pin(ep, h, None);
}
/// A six-segment store: the head run on A, TCP-ACKed but dropped by the receiver (the head
/// becomes uncovered at t + 10 ms); then B's run (blackholed); then A's run, sent at the next
/// poll. Controller `a` on A.
fn uncovered_head(
    a: fn() -> Box<dyn CongestionControl>,
) -> (
    Endpoint<ChaCha20Rng>,
    ConnectionHandle,
    Peer,
    Instant,
    u64,
    Vec<u8>,
) {
    uncovered_head_of(a, 2)
}
/// `uncovered_head` with a head run of `segs` segments.
fn uncovered_head_of(
    a: fn() -> Box<dyn CongestionControl>,
    segs: usize,
) -> (
    Endpoint<ChaCha20Rng>,
    ConnectionHandle,
    Peer,
    Instant,
    u64,
    Vec<u8>,
) {
    let cap = (segs + 4) * SEG;
    let (mut ep, h, mut peer, t, head, _) = hol(cc_b, a, cap, cap);
    let data = pattern(cap);
    peer.drop[0] = true;
    peer.lose = (0..segs)
        .map(|i| (1, head + (i * SEG) as u64, true))
        .collect();
    pinned(&mut ep, h, &mut peer, t, 1, &data[..segs * SEG]);
    pinned(&mut ep, h, &mut peer, t, 0, &data[segs * SEG..][..2 * SEG]);
    let rest = ep.connection(h).unwrap().write(&data[(segs + 2) * SEG..]);
    assert_eq!(rest, Ok(2 * SEG));
    (ep, h, peer, t, head, data)
}
/// `k` runs of two segments each on B (blackholed), each followed by two on A, all sent
/// `idle` after priming; the store holds exactly them. With `feed` the application then keeps
/// it full with as much again (`Peer::feed`). B's RTT is `rtt_b` ms, A's 10 ms. Run `i` of B
/// starts at `head + 4·SEG·i`. The peer's `lose` entries, from the head DSN, apply from the
/// start: the episode's first copy goes out with the last run.
fn b_runs(
    k: usize,
    rtt_b: u64,
    idle: Duration,
    feed: bool,
    lose: fn(u64) -> Vec<(usize, u64, bool)>,
) -> (
    Endpoint<ChaCha20Rng>,
    ConnectionHandle,
    Peer,
    Instant,
    u64,
    Vec<u8>,
) {
    let cap = 4 * k * SEG;
    let n = if feed { 2 * cap } else { cap };
    let (mut ep, h, mut peer, t, head, _) = hol_rtt(cc_b_big, cc_a, cap, n, rtt_b, 10);
    let t = t + idle;
    let data = pattern(n);
    peer.feed = data[cap..].to_vec();
    peer.lose = lose(head);
    peer.drop[0] = true;
    for i in 0..k {
        pinned(&mut ep, h, &mut peer, t, 0, &data[4 * i * SEG..][..2 * SEG]);
        pinned(
            &mut ep,
            h,
            &mut peer,
            t,
            1,
            &data[(4 * i + 2) * SEG..][..2 * SEG],
        );
    }
    (ep, h, peer, t, head, data)
}
fn run_dsn(head: u64, i: usize) -> u64 {
    head + (4 * i * SEG) as u64
}

#[test]
fn repair_uncovered_head_fires_without_input() {
    let (mut ep, h, mut peer, t, head, _) = uncovered_head(cc_a);
    peer.run(&mut ep, h, t, t + ms_d(15));
    // A's ACK at t + 10 ms covers the head without DATA_ACK: no live mapping covers it.
    assert_eq!(una(&ep, h), head);
    let due = t + ms_d(30);
    assert_eq!(ep.poll_timeout(), Some(due), "2·srtt of A after the ACK");
    ep.handle_timeout(due);
    let out = data_on(&drain(&mut ep, due), &peer.syns[1]);
    assert_eq!(
        dsn_of(&out[0], peer.syns[1].seq).unwrap().0,
        head,
        "repair sent"
    );
    assert_eq!(una(&ep, h), head, "no DATA_ACK progress yet");
    let s = stats(&mut ep, h);
    assert_eq!((s.opp_repairs, s.opp_episodes, s.penalties), (1, 0, 0));
}

#[test]
fn repair_due_with_zero_budget_sent_at_release() {
    let (mut ep, h, mut peer, t, head, _) = uncovered_head(cc_a_paced_25);
    // A's last run goes out at the next release, t + 25 ms: from then the connection is
    // blocked and the head uncovered, so the repair is due at t + 45 ms, before A's next
    // release at t + 50 ms.
    peer.run(&mut ep, h, t, t + ms_d(47));
    let last = (peer.log.iter())
        .filter(|l| l.1 == 1)
        .map(|l| l.0)
        .max()
        .unwrap();
    assert_eq!(last, t + ms_d(25));
    assert_eq!(sent_at_dsn(&peer, 1, head), 1, "not yet repaired");
    assert_eq!(
        ep.poll_timeout(),
        Some(t + ms_d(50)),
        "no past deadline, the release"
    );
    peer.run(&mut ep, h, t + ms_d(47), t + ms_d(55));
    assert_eq!(copies(&peer, head).first(), Some(&(t + ms_d(50), head)));
}

#[test]
fn repair_one_install_until_tcp_ack() {
    let (mut ep, h, mut peer, t, head, _) = uncovered_head(cc_a);
    // The repair goes out at t + 30 ms; its TCP ACK arrives at t + 40 ms.
    peer.run(&mut ep, h, t, t + ms_d(39));
    for k in 0..5 {
        let now = t + ms_d(31 + k);
        ep.handle_timeout(now);
        drain(&mut ep, now);
    }
    assert_eq!(
        sent_at_dsn(&peer, 1, head),
        2,
        "the original and one repair"
    );
    assert_eq!(stats(&mut ep, h).opp_repairs, 1);
    peer.run(&mut ep, h, t + ms_d(39), t + ms_d(100));
    assert_eq!(
        una(&ep, h),
        head + 2 * SEG as u64,
        "the repaired head is DATA_ACKed"
    );
    assert_eq!(stats(&mut ep, h).opp_repairs, 1);
    // A three-segment repair at t + 30 ms: the first is delivered, the second TCP-ACKed but
    // dropped, the third lost. The new head is uncovered, but its copy is still
    // TCP-unacknowledged: no repair until the tail probe (t + 50 ms) gets the whole copy
    // ACKed at t + 60 ms; the next repair goes 2·srtt later.
    let (mut ep, h, mut peer, t, head, _) = uncovered_head_of(cc_a, 3);
    let (second, third) = (head + SEG as u64, head + 2 * SEG as u64);
    peer.lose.extend([(1, second, true), (1, third, false)]);
    peer.run(&mut ep, h, t, t + ms_d(85));
    let at = |dsn| {
        let on_a = peer.log.iter().filter(|l| l.1 == 1 && l.2 == dsn);
        on_a.map(|l| l.0).collect::<Vec<_>>()
    };
    assert_eq!(at(head), [t + ms_d(30)]);
    assert_eq!(
        at(second),
        [t + ms_d(80)],
        "repaired only after the whole copy is ACKed"
    );
    assert_eq!(stats(&mut ep, h).opp_repairs, 2);
}

#[test]
fn repair_probe_without_episode() {
    let (mut ep, h, mut peer, t, head, _) = uncovered_head(cc_a);
    // The repair's tail is lost too, and nothing follows it on A.
    let tail = head + SEG as u64;
    peer.lose.push((1, tail, false));
    peer.run(&mut ep, h, t, t + ms_d(100));
    assert_eq!(
        una(&ep, h),
        head + 2 * SEG as u64,
        "the repaired head is DATA_ACKed"
    );
    assert!(ep.conns[&h].opp.is_none(), "no episode");
    // The repair at t + 30 ms, its tail probe 2·srtt later.
    assert_eq!(
        copies(&peer, head),
        [(t + ms_d(30), head), (t + ms_d(50), tail)]
    );
}

#[test]
fn repair_precedes_later_queued_reinjections() {
    let (mut ep, h, mut peer, t, head, _) = uncovered_head(cc_a);
    peer.run(&mut ep, h, t, t + ms_d(29));
    // S is Stale: its range after the head is queued for reinjection (rule 3).
    let c = ep.conns.get_mut(&h).unwrap();
    c.subflows[0].state = SubflowState::Stale;
    let due = t + ms_d(30);
    ep.handle_timeout(due);
    queue_reinject(&mut ep, h, head + 2 * SEG as u64, 2 * SEG as u64);
    let out = data_on(&drain(&mut ep, due), &peer.syns[1]);
    let dsns: Vec<u64> = (out.iter())
        .map(|s| dsn_of(s, peer.syns[1].seq).unwrap().0)
        .collect();
    assert_eq!(dsns[0], head, "the repair first: {dsns:?}");
    assert!(
        dsns.contains(&(head + 2 * SEG as u64)),
        "then the reinjection"
    );
}

#[test]
fn repair_target_not_s_when_s_fastest() {
    // B (S) is the 10 ms path, A the 30 ms one.
    let cap = 32 * SEG;
    let (mut ep, h, mut peer, t, head, _) = hol_rtt(cc_b, cc_a, cap, cap, 10, 30);
    let data = pattern(cap);
    peer.drop[0] = true;
    peer.lose = vec![(1, head, true), (1, head + SEG as u64, true)];
    b_holds_head(&mut ep, h, &mut peer, t, &data);
    peer.run(&mut ep, h, t, t + Duration::from_secs(1));
    assert_eq!(peer.received(), data);
    // The copy on A is TCP-ACKed at t + 30 ms and dropped. S's silence deadline (2·srtt_S =
    // 20 ms) has started a lookahead, which copies the head again on A as soon as A's copy is
    // no longer live; the repair clock (2·srtt of A, t + 90 ms) is never needed. Every copy
    // goes on A, none on the faster S.
    assert_eq!(moved_at(&peer, 0, 1), Some(t + ms_d(30)));
    assert_eq!(sent_at_dsn(&peer, 0, head), 1, "nothing more on S");
    assert_eq!(sent_at_dsn(&peer, 1, head), 2);
    assert_eq!(stats(&mut ep, h).lookaheads, 1);
}

#[test]
fn repair_partial_discard_with_unacked_lookahead_tail() {
    // B (S) at 1 ms: its silence deadline expires at t + 2 ms, so the lookahead copies runs 1
    // and 2 behind the episode's copy of run 0.
    let (mut ep, h, mut peer, t, head, data) = b_runs(3, 1, Duration::ZERO, false, |head| {
        // Run 0's copy loses its second segment at the data level; the lookahead's last
        // segment is lost and stays TCP-unacknowledged.
        let tail = run_dsn(head, 2) + SEG as u64;
        vec![(1, head + SEG as u64, true), (1, tail, false)]
    });
    let half = head + SEG as u64;
    peer.run(&mut ep, h, t, t + Duration::from_secs(10));
    assert_eq!(peer.received(), data);
    assert_eq!(stats(&mut ep, h).lookaheads, 1);
    // DATA_ACK reaches `half` at t + 10 ms: repaired 2·srtt of A later all the same.
    let c: Vec<_> = copies(&peer, head)
        .into_iter()
        .filter(|c| c.1 == half)
        .collect();
    assert_eq!(c, [(t + ms_d(30), half)]);
}

#[test]
fn repair_each_round_never_recopies_lookahead() {
    let k = 6;
    let (mut ep, h, mut peer, t, head, data) = b_runs(k, 30, Duration::ZERO, false, |head| {
        // Every copy of the head is TCP-ACKed and dropped, four times.
        vec![(1, head, true); 4]
    });
    peer.run(&mut ep, h, t, t + Duration::from_secs(10));
    assert_eq!(peer.received(), data);
    let s = stats(&mut ep, h);
    assert_eq!((s.opp_repairs, s.lookaheads), (4, 1));
    assert_eq!(
        sent_at_dsn(&peer, 1, head),
        5,
        "the copy and a repair each round"
    );
    for i in 1..k {
        assert_eq!(
            sent_at_dsn(&peer, 1, run_dsn(head, i)),
            1,
            "run {i} copied once"
        );
    }
}

#[test]
fn lookahead_waits_for_silence_and_starts_without_input() {
    // Healthy asymmetric paths: a small store, A's cwnd four segments, so B carries data and
    // holds the head often; B ACKs within 2·srtt, so no lookahead ever starts.
    let (cap, n) = (16 * SEG, 150 * SEG);
    let (mut ep, h, mut peer, t, _, _) = hol(cc_b_big, cc_a_small, cap, n);
    let data = pattern(n);
    peer.feed = data.clone();
    peer.run(&mut ep, h, t, t + Duration::from_secs(10));
    assert_eq!(peer.received(), data);
    let s = stats(&mut ep, h);
    assert!(s.opp_triggers > 0, "the head was blocked on B: {s:?}");
    assert_eq!(s.lookaheads, 0);
    // B blackholed: S's silence deadline is its first transmission + 2·srtt.
    let k = 8;
    let (mut ep, h, mut peer, t, head, _) = b_runs(k, 30, Duration::ZERO, true, |_| Vec::new());
    peer.run(&mut ep, h, t, t + ms_d(55));
    assert_eq!(stats(&mut ep, h).lookaheads, 0);
    let at = t + ms_d(60);
    assert_eq!(ep.conns[&h].silence_deadline(), Some((at, SubflowId(0))));
    // No input: the deadline alone starts the lookahead. A's cwnd is full, so its copies
    // leave with A's next ACKs.
    ep.handle_timeout(at);
    for s in drain(&mut ep, at) {
        peer.take(at, leak(s));
    }
    assert_eq!(stats(&mut ep, h).lookaheads, 1);
    peer.run(&mut ep, h, at, at + ms_d(20));
    for i in [k - 2, k - 1] {
        assert_eq!(
            sent_at_dsn(&peer, 1, run_dsn(head, i)),
            1,
            "run {i} copied once"
        );
    }
}

#[test]
fn lookahead_idle_then_new_flight_counts_from_flight() {
    // B's last ACK was 500 ms before the flight starts: silence counts from the flight.
    let (mut ep, h, mut peer, t, _, _) = b_runs(8, 30, ms_d(500), true, |_| Vec::new());
    peer.run(&mut ep, h, t, t + ms_d(55));
    assert_eq!(stats(&mut ep, h).lookaheads, 0);
    assert_eq!(
        ep.conns[&h].silence_deadline(),
        Some((t + ms_d(60), SubflowId(0)))
    );
}

#[test]
fn lookahead_no_expired_deadline_or_second_batch() {
    let (mut ep, h, mut peer, t, _, _) = b_runs(8, 30, Duration::ZERO, true, |_| Vec::new());
    peer.run(&mut ep, h, t, t + ms_d(55));
    let at = t + ms_d(60);
    ep.handle_timeout(at);
    drain(&mut ep, at);
    assert_eq!(stats(&mut ep, h).lookaheads, 1);
    // Repeated polls without input while DATA_ACK stays below the old boundary.
    for now in [at, at, at + ms_d(1), at + ms_d(5)] {
        assert!(
            ep.poll_timeout().is_none_or(|d| d > now),
            "expired deadline at {now:?}"
        );
        assert_eq!(ep.conns[&h].silence_deadline(), None);
        ep.handle_timeout(now);
        assert!(data_on(&drain(&mut ep, now), &peer.syns[1]).is_empty());
        assert_eq!(stats(&mut ep, h).lookaheads, 1, "no second batch");
    }
}

#[test]
fn repair_and_episode_probe_share_one_tail_probe() {
    let cap = 32 * SEG;
    let (mut ep, h, mut peer, t, head, _) = hol(cc_b, cc_a, cap, cap);
    let data = pattern(cap);
    peer.drop[0] = true;
    let tail = head + SEG as u64;
    peer.lose = vec![(1, tail, false)];
    b_holds_head(&mut ep, h, &mut peer, t, &data);
    // The episode copy goes out at t; give the same copy a head-repair probe as well, so both
    // probe deadlines fall at t + 2·srtt on A.
    for s in data_on(&drain(&mut ep, t), &peer.syns[1]) {
        peer.take(t, s);
    }
    let c = ep.conns.get_mut(&h).unwrap();
    let ssn_end = c.opp.as_ref().unwrap().ssn_end;
    c.repair.probe = Some((SubflowId(1), ssn_end));
    assert_eq!(c.repair_probe_at(), c.opp_probe_at());
    peer.run(&mut ep, h, t, t + ms_d(25));
    assert_eq!(
        sent_at_dsn(&peer, 1, tail),
        2,
        "the copy and a single probe"
    );
    let c = &ep.conns[&h];
    assert!(c.repair.probe.is_none() && c.opp.as_ref().is_none_or(|e| e.probed));
}

#[test]
fn lookahead_boundary_skips_data_acked_mappings() {
    // S (B) at 10 ms like A: by S's silence deadline (t + 20 ms) DATA_ACK has passed run 0
    // through the episode's copy, while S still holds run 0's mapping (never TCP-ACKed).
    let k = 8;
    let (mut ep, h, mut peer, t, head, _) = b_runs(k, 10, Duration::ZERO, true, |_| Vec::new());
    let at = t + ms_d(20);
    peer.run(&mut ep, h, t, t + ms_d(19));
    assert!(una(&ep, h) > head + 2 * SEG as u64, "run 0 DATA_ACKed");
    let tx = &ep.conns[&h].subflows[0].mp.tx;
    assert_eq!(
        tx.ranges().next().map(|r| r.0),
        Some(head),
        "S still holds run 0"
    );
    let last_end = tx.ranges().map(|(d, n)| d + n).max();
    peer.run(&mut ep, h, t + ms_d(19), at);
    assert_eq!(stats(&mut ep, h).lookaheads, 1);
    // The boundary is the end of S's last mapping, wrap-safe relative to `send.una`: the
    // lookahead stays active and copies every remaining hole of S at once.
    let la = ep.conns[&h].repair.lookahead.expect("lookahead active");
    assert_eq!(Some(la.boundary), last_end);
    for i in 2..k {
        let on_a: Vec<_> = (peer.log.iter())
            .filter(|l| l.1 == 1 && l.2 == run_dsn(head, i))
            .map(|l| l.0)
            .collect();
        assert_eq!(on_a, [at], "run {i} copied once, at the deadline");
    }
}

/// M3 spec §2.3: the episode's `end` only advances; an install below it (a lookahead copying
/// again what is no longer live on A) leaves it, while the install still counts for the
/// deadline and the tail.
#[test]
fn episode_end_never_moves_back() {
    let cap = 32 * SEG;
    let (mut ep, h, mut peer, t, head, _) = hol(cc_b, cc_a, cap, cap);
    peer.drop[0] = true;
    b_holds_head(&mut ep, h, &mut peer, t, &pattern(cap));
    drain(&mut ep, t);
    let end = head + 2 * SEG as u64;
    assert_eq!(ep.conns[&h].opp.as_ref().map(|e| e.end), Some(end));
    let c = ep.conns.get_mut(&h).unwrap();
    let cand = crate::mptcp::Cand {
        dsn: head,
        len: SEG as u32,
        blocking: Some(SubflowId(0)),
        repair: false,
    };
    c.opp_installed(1, cand, SEG as u32, t + ms_d(5));
    let e = c.opp.as_ref().unwrap();
    assert_eq!(e.end, end, "end kept");
    let rto = c.subflows[1].tcb.base_rto().unwrap();
    assert_eq!(
        e.deadline,
        t + ms_d(5) + rto,
        "the install moves the deadline"
    );
}

/// M3 spec §2.3: the episode deadline is `max(last install, last DATA_ACK advance)` + T's
/// un-backed-off RTO. A at 600 ms, primed three times so that its RTO is below 2·srtt: the
/// deadline, not H1's clock (2·srtt after the copy's TCP ACK), decides. S (B) at 2 s.
#[test]
fn opp_episode_deadline_from_install_and_data_ack_advance() {
    PENALIZED.with(|p| p.set([0, 0]));
    let (cap, rtt_a) = (32 * SEG, 600);
    let (mut ep, h, syn, _) = confirmed_cc(cc_b);
    ep.cc = Some(cc_a);
    let (_, jsyn) = joined(&mut ep, h, ms(10), JOIN_IP, 1500, 7);
    let (mut t, _) = prime(&mut ep, h, &syn, SubflowId(0), ms(20), 2000);
    for _ in 0..3 {
        t = prime(&mut ep, h, &jsyn, SubflowId(1), t, rtt_a).0;
    }
    events(&mut ep);
    let head = una(&ep, h);
    let d = ep.conns.get_mut(&h).unwrap().hooks.data.as_mut().unwrap();
    d.send = crate::mptcp::data::SendStore::new(head, cap);
    let mut peer = Peer::new(head, cap, &[(&syn, 2000), (&jsyn, rtt_a)]);
    let data = pattern(cap);
    peer.drop[0] = true;
    // The copy's second segment is TCP-ACKed and dropped by the receiver.
    let half = head + SEG as u64;
    peer.lose = vec![(1, half, true)];
    b_holds_head(&mut ep, h, &mut peer, t, &data);
    let rto = |ep: &Endpoint<ChaCha20Rng>| ep.conns[&h].subflows[1].tcb.base_rto().unwrap();
    let deadline = |ep: &Endpoint<ChaCha20Rng>| ep.conns[&h].opp.as_ref().map(|e| e.deadline);
    // Installed at t.
    for s in drain(&mut ep, t) {
        peer.take(t, leak(s));
    }
    assert_eq!(
        (sent_at_dsn(&peer, 1, head), sent_at_dsn(&peer, 1, half)),
        (1, 1)
    );
    let first = t + rto(&ep);
    assert_eq!(deadline(&ep), Some(first));
    // DATA_ACK advances to `half` at t + 600 ms: the deadline moves to then + RTO.
    let acked = t + ms_d(rtt_a);
    peer.run(&mut ep, h, t, acked);
    assert_eq!(una(&ep, h), half);
    let moved = acked + rto(&ep);
    assert!(rto(&ep) < 2 * ep.conns[&h].subflows[1].tcb.srtt().unwrap());
    assert!(moved > first);
    assert_eq!(deadline(&ep), Some(moved));
    assert_eq!(
        ep.poll_timeout(),
        Some(moved),
        "the expiry is its own deadline"
    );
    // It expires exactly then, and a new episode copies the rest of the run at once.
    peer.run(&mut ep, h, acked, moved);
    assert_eq!(copies(&peer, head), [(t, head), (moved, half)]);
    let s = stats(&mut ep, h);
    assert_eq!((s.opp_episodes, s.opp_repairs), (2, 0));
    peer.run(&mut ep, h, moved, moved + Duration::from_secs(3));
    assert_eq!(peer.received(), data);
}

// BBRv3 Task 8: the controller chosen by `ConnectConfig::congestion_control`.

fn bbr_connected() -> Connected {
    let cfg = ConnectConfig {
        recv_buffer: 1 << 20,
        congestion_control: crate::tcp::CongestionControlKind::BbrV3,
        ..ConnectConfig::default()
    };
    let (mut ep, h, syn, dsn) = connected_cfg("10.0.0.1", "10.0.0.2:80", cfg, None, false);
    open_window(&mut ep, &syn, h);
    (ep, h, syn, dsn)
}
/// Per subflow: whether it runs BBR, which alone has a send quantum.
fn runs_bbr(ep: &Endpoint<ChaCha20Rng>, h: ConnectionHandle) -> Vec<bool> {
    let subflows = ep.conns[&h].subflows.iter();
    subflows
        .map(|s| s.tcb.cc().send_quantum().is_some())
        .collect()
}

/// A join inherits the connection's `BbrV3` (spec §4.1), and data over both subflows arrives
/// byte-exact.
#[test]
fn mptcp_two_subflows_bbr() {
    let (mut ep, h, syn, _) = bbr_connected();
    let (_, jsyn) = joined(&mut ep, h, ms(10), JOIN_IP, 1500, 7);
    assert_eq!(runs_bbr(&ep, h), [true, true]);
    let n = 400_000;
    let data: Vec<u8> = (0..n).map(|i| (i % 251) as u8).collect();
    let head = una(&ep, h);
    assert_eq!(ep.connection(h).unwrap().write(&data), Ok(n));
    let mut peer = Peer::new(head, n, &[(&syn, 30), (&jsyn, 10)]);
    let t = ms(10);
    peer.run(&mut ep, h, t, t + Duration::from_secs(30));
    assert_eq!(una(&ep, h), head + n as u64);
    assert_eq!(peer.received(), data);
    for path in [0, 1] {
        assert!(peer.log.iter().any(|l| l.1 == path), "data on {path}");
    }
}

/// Review Focus 4: after an infinite-mapping fallback the subflow keeps its BBR as it was, with
/// no reset (spec §4.2), and plain TCP carries on under it.
#[test]
fn fallback_keeps_bbr() {
    let (mut ep, h, syn, peer_dsn) = bbr_connected();
    let n = 200_000;
    let head = una(&ep, h);
    assert_eq!(ep.connection(h).unwrap().write(&vec![3; n]), Ok(n));
    let mut peer = Peer::new(head, n, &[(&syn, 20)]);
    let now = peer.run(&mut ep, h, ms(10), ms(10_000));
    assert_eq!(una(&ep, h), head + n as u64);
    let cc = |ep: &Endpoint<ChaCha20Rng>| {
        let c = ep.conns[&h].subflows[0].tcb.cc();
        (c.cwnd(), c.pacing_rate(), c.send_quantum())
    };
    let before = cc(&ep);
    assert!(
        before.0 > 10 * 1432,
        "grown past the initial window: {before:?}"
    );
    let inf = mapping(1, peer_dsn, 0);
    let seg = Segment {
        ack: peer.next[0],
        wnd: 65535,
        ..peer_data(&syn, 5001, &inf, &[])
    };
    input_at(&mut ep, &seg, now);
    assert!(events(&mut ep).contains(&Event::FellBack));
    assert_eq!(cc(&ep), before, "unchanged by the fallback");
    let head = una(&ep, h);
    assert_eq!(ep.connection(h).unwrap().write(&vec![4; n]), Ok(n));
    let mut peer = Peer::new(head, n, &[(&syn, 20)]);
    peer.strip[0] = true;
    peer.run(&mut ep, h, now, now + Duration::from_secs(10));
    assert_eq!(una(&ep, h), head + n as u64, "plain TCP delivered it");
    assert_eq!(runs_bbr(&ep, h), [true]);
}

// M4a Task 6: the MP_JOIN responder on an accepted connection (`server_tests::Script`).

/// RFC 8684 test keys and nonces (`crypto.rs` vectors): Key-A, Key-B, R-A, R-B.
const KA: u64 = 0x0102030405060708;
const KB: u64 = 0x1112131415161718;
const RA: u32 = 0xa1a2a3a4;
const RB: u32 = 0xb1b2b3b4;
const JOIN_SRC: &str = "10.0.1.1:40000";

/// A listener whose accepted connection is Confirmed, the client holding Key-A and the
/// server Key-B.
fn responder() -> super::super::server_tests::Script {
    use super::super::server_tests::{Script, cap, syn_cap};
    use crate::wire::mptcp::CAP_H;
    let mut s = Script::new(true);
    s.ep.keys.clear();
    s.ep.keys.push_back(KB);
    s.syn(&syn_cap(1, CAP_H));
    s.send(65535, &cap(1, CAP_H, Some(KA), Some(KB), None), &[]);
    assert_eq!(s.negotiation().state, State::Confirmed);
    s.events();
    s
}

/// The client's segment on the join 4-tuple; the server's ISS comes from its SYN/ACK.
fn join_input(s: &mut super::super::server_tests::Script, seg: Segment) -> Vec<Segment<'static>> {
    let seg = Segment {
        src: JOIN_SRC.parse().unwrap(),
        dst: super::super::server_tests::SERVER.parse().unwrap(),
        ..seg
    };
    input_at(&mut s.ep, &seg, s.now);
    s.output().into_iter().map(leak).collect()
}

/// The client's MP_JOIN SYN (nonce R-A, window scale 6); returns the server's answer.
fn responder_syn(s: &mut super::super::server_tests::Script, backup: bool) -> Segment<'static> {
    let mut opts = [0; 40];
    let join = MpJoin::Syn {
        backup,
        addr_id: 3,
        token: crate::crypto::key_token_idsn(KB).0,
        nonce: RA,
    };
    let n = mptcp::encode(&MptcpOption::Join(join), &mut opts).unwrap();
    let n = n + crate::wire::tcp_options::write_ws(&mut opts[n..], 6);
    let seg = Segment {
        src: JOIN_SRC.parse().unwrap(),
        dst: JOIN_SRC.parse().unwrap(),
        seq: SeqNum(7000),
        ack: SeqNum(0),
        flags: TcpFlags::SYN,
        wnd: 65535,
        options: &opts[..n],
        payload: &[],
    };
    let mut out = join_input(s, seg);
    assert_eq!(out.len(), 1);
    out.pop().unwrap()
}

/// HMAC-B in the SYN/ACK is the RFC vector `HMAC(Key-B‖Key-A, R-B‖R-A)` truncated to 64 bits;
/// HMAC-A in the third ACK, `HMAC(Key-A‖Key-B, R-A‖R-B)`, completes the join, and a
/// retransmitted third ACK draws a plain ACK and no second `SubflowUp` (RFC 8684 L1155–1187).
#[test]
fn responder_synack_hmac_matches_rfc_vector() {
    let mut s = responder();
    s.ep.nonces.push_back(RB);
    let synack = responder_syn(&mut s, false);
    assert_eq!(synack.flags, TcpFlags::SYN | TcpFlags::ACK);
    assert_eq!(synack.ack, SeqNum(7001));
    let expected = MpJoin::SynAck {
        backup: false,
        addr_id: 0,
        hmac64: 0x864b_4042_8762_fd06,
        nonce: RB,
    };
    assert_eq!(mp_join(&synack), (expected, 16));
    let hmac160: [u8; 20] = join_hmac(KA, KB, RA, RB)[..20].try_into().unwrap();
    assert_eq!(hmac160[..4], [0x53, 0x03, 0x7f, 0x28]);
    let mut opts = [0; 24];
    let n = mptcp::encode(&MptcpOption::Join(MpJoin::Ack { hmac160 }), &mut opts).unwrap();
    let third = Segment {
        seq: SeqNum(7001),
        ack: synack.seq.wrapping_add(1),
        flags: TcpFlags::ACK,
        options: &opts[..n],
        ..synack.clone()
    };
    for round in 0..2 {
        let out = join_input(&mut s, third.clone());
        assert!(
            !out.is_empty(),
            "round {round}: an ACK answers the third ACK"
        );
        for ack in &out {
            assert_eq!(ack.flags, TcpFlags::ACK);
            let join = |o: &&[u8]| matches!(mptcp::parse(o), Ok(MptcpOption::Join(_)));
            assert!(!mpc(ack.options).iter().any(join));
        }
        let up = Event::SubflowUp {
            subflow: SubflowId(1),
        };
        assert_eq!(s.events(), if round == 0 { vec![up] } else { vec![] });
    }
}

/// Spec G3c: the SYN's B bit is the peer's backup request (RFC 8684 L1101–1109); its window
/// scale is the subflow's. The SYN/ACK carries our own flag, which is clear.
#[test]
fn responder_takes_backup_from_syn() {
    for backup in [false, true] {
        let mut s = responder();
        let synack = responder_syn(&mut s, backup);
        let (MpJoin::SynAck { backup: ours, .. }, _) = mp_join(&synack) else {
            panic!()
        };
        assert!(!ours);
        let sf = &s.ep.conns[&ConnectionHandle(0)].subflows[1];
        assert_eq!((sf.mp.peer_backup, sf.mp.peer_scale), (backup, 6));
    }
}

/// The data level closes both ways while a join we answered waits for its lost third ACK:
/// the join can carry nothing more, so it is reset with MP_TCPRST at once, its listener slot
/// comes back, and the connection ends with subflow 0, not at the join's SYN timeout.
#[test]
fn responder_join_reset_when_data_closed() {
    use super::super::server_tests::SERVER;
    use crate::crypto::key_token_idsn;
    use crate::wire::mptcp::{DataAck, Dsn, Dss, Mapping};
    let mut s = responder();
    responder_syn(&mut s, false);
    let server: SocketAddr = SERVER.parse().unwrap();
    assert_eq!(s.ep.listeners[&server].half_open, 1);
    let dss = |data_ack: u64, fin: Option<u64>| {
        let o = MptcpOption::Dss(Dss {
            data_fin: fin.is_some(),
            data_ack: Some(DataAck::Ack64(data_ack)),
            mapping: fin.map(|dsn| Mapping {
                dsn: Dsn::Dsn64(dsn),
                ssn: 0,
                data_len: 1,
                checksum: None,
            }),
        });
        let mut out = [0; 40];
        let n = mptcp::encode(&o, &mut out).unwrap();
        out[..n].to_vec()
    };
    let (client, server_idsn) = (key_token_idsn(KA).1, key_token_idsn(KB).1);
    // The client's DATA_FIN, then ours, which the client DATA_ACKs with its subflow FIN.
    s.send(65535, &dss(server_idsn + 1, Some(client + 1)), &[]);
    s.conn().close();
    assert!(!s.output().is_empty(), "our DATA_FIN");
    let seq = s.seq;
    s.input(
        TcpFlags::ACK | TcpFlags::FIN,
        seq,
        65535,
        &dss(server_idsn + 2, None),
        &[],
    );
    s.seq += 1;
    let out = s.output();
    let rst: Vec<_> = (out.iter().map(|p| leak(p.clone())))
        .filter(|p| p.flags.contains(TcpFlags::RST))
        .collect();
    assert_eq!(rst.len(), 1, "the join is reset");
    assert_eq!(rst[0].dst, JOIN_SRC.parse().unwrap());
    let tcprst = MptcpOption::TcpRst {
        transient: false,
        reason: 0,
    };
    assert_eq!(
        mpc(rst[0].options)
            .iter()
            .map(|o| mptcp::parse(o).unwrap())
            .collect::<Vec<_>>(),
        [tcprst]
    );
    assert_eq!(s.ep.listeners[&server].half_open, 0);
    // The client ACKs our subflow FIN: the connection ends and is freed.
    s.iss += 1;
    s.send(65535, &[], &[]);
    s.ep.handle_timeout(s.now);
    let closed = Event::Closed {
        reason: CloseReason::Normal,
    };
    assert!(s.events().contains(&closed));
    assert!(s.ep.conns.is_empty() && s.ep.demux.is_empty());
}

// M3 Task 4: path-management API groundwork, reusing the helpers above.
#[path = "pm_tests.rs"]
mod pm_tests;
