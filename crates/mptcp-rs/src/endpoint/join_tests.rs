//! MP_JOIN subflows (RFC 8684 §3.2, spec §5.6) against a scripted Linux-like peer. A child of
//! `mptcp_tests`, whose helpers it reuses.
use super::*;
use crate::crypto::join_hmac;
use crate::endpoint::AddSubflowError;
use crate::mptcp::State;
use crate::wire::mptcp::MpJoin;

const JOIN_IP: &str = "10.0.1.1";
const PEER_NONCE: u32 = 0xb1b2_b3b4;

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
fn join_syn(
    ep: &mut Endpoint<ChaCha20Rng>,
    h: ConnectionHandle,
    now: Instant,
    ip: &str,
    mtu: u16,
) -> (SubflowId, Segment<'static>) {
    let id = ep.add_subflow(now, h, ip.parse().unwrap(), mtu).unwrap();
    let syn = from(&drain(ep, now), ip).pop().expect("join SYN");
    (id, syn)
}

/// The peer's SYN/ACK options: MP_JOIN with the right HMAC-B (unless `hmac` overrides it),
/// MSS 1460 and window scale `ws`.
fn synack_opts(
    ep: &Endpoint<ChaCha20Rng>,
    h: ConnectionHandle,
    jsyn: &Segment,
    ws: u8,
    hmac: Option<u64>,
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
    let n = n + crate::wire::tcp_options::write_mss(&mut out[n..], 1460);
    let n = n + crate::wire::tcp_options::write_ws(&mut out[n..], ws);
    out[..n].to_vec()
}
/// The peer's SYN/ACK on the join 4-tuple (ISN 5000, like the initial subflow's peer).
fn synack(ep: &mut Endpoint<ChaCha20Rng>, jsyn: &Segment, opts: &[u8], now: Instant) {
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
fn joined(
    ep: &mut Endpoint<ChaCha20Rng>,
    h: ConnectionHandle,
    now: Instant,
    ip: &str,
    mtu: u16,
    ws: u8,
) -> (SubflowId, Segment<'static>) {
    let (id, jsyn) = join_syn(ep, h, now, ip, mtu);
    let opts = synack_opts(ep, h, &jsyn, ws, None);
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
        assert!(mpc(out[0].options).is_empty());
    } else {
        assert!(out.is_empty(), "a RST is not answered");
    }
    assert_eq!(
        events(&mut ep),
        vec![Event::SubflowDown {
            subflow: id,
            reason: CloseReason::Reset
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
            reason: CloseReason::Timeout
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
    assert_eq!(ep.add_subflow(t, h, ip(JOIN_IP), 1500), Ok(SubflowId(1)));
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
        ep.add_subflow(ms(0), h, ip(JOIN_IP), 1500),
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
        reason: CloseReason::Reset
    }));
    assert_eq!(
        ep.add_subflow(ms(1), h, ip(JOIN_IP), 1500),
        Err(PeerForbidsJoin)
    );
    let dss = data_ack(una(&ep, h));
    input_at(&mut ep, &peer_data(&syn, 5001, &dss, &[]), ms(2));
    assert_eq!(state(&ep, h), State::Confirmed);
    assert_eq!(
        ep.add_subflow(ms(2), h, ip(JOIN_IP), 1500),
        Err(PeerForbidsJoin)
    );
    assert!(from(&drain(&mut ep, ms(2)), JOIN_IP).is_empty());
    // Queued, then handshake fallback: dropped, never sent; NotMptcp afterwards.
    let mut ep = Endpoint::new(ChaCha20Rng::seed_from_u64(41));
    let h = open(&mut ep);
    let syn = leak(transmit(&mut ep, ms(0)));
    assert_eq!(
        ep.add_subflow(ms(0), h, ip(JOIN_IP), 1500),
        Ok(SubflowId(1))
    );
    reply(&mut ep, &syn, &[], syn.seq.wrapping_add(1));
    assert!(from(&drain(&mut ep, ms(1)), JOIN_IP).is_empty());
    assert!(events(&mut ep).contains(&Event::SubflowDown {
        subflow: SubflowId(1),
        reason: CloseReason::Reset
    }));
    assert_eq!(ep.add_subflow(ms(1), h, ip(JOIN_IP), 1500), Err(NotMptcp));
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
    assert_eq!(ep.add_subflow(ms(0), h, ip(JOIN_IP), 1500), Err(NotMptcp));
    assert_eq!(
        ep.add_subflow(ms(0), ConnectionHandle(99), ip(JOIN_IP), 1500),
        Err(NoConnection)
    );
    // Confirmed: address family, MTU, the subflow cap, then close.
    let (mut ep, h, _, _) = confirmed();
    assert_eq!(
        ep.add_subflow(ms(5), h, ip("fd00::1"), 1500),
        Err(FamilyMismatch)
    );
    assert_eq!(ep.add_subflow(ms(5), h, ip(JOIN_IP), 67), Err(InvalidMtu));
    for i in 1..8 {
        assert_eq!(ep.add_subflow(ms(5), h, ip(JOIN_IP), 68), Ok(SubflowId(i)));
    }
    assert_eq!(
        ep.add_subflow(ms(5), h, ip(JOIN_IP), 1500),
        Err(TooManySubflows)
    );
    assert_eq!(from(&drain(&mut ep, ms(5)), JOIN_IP).len(), 7);
    let (mut ep, h, _, _) = confirmed();
    ep.connection(h).unwrap().close();
    assert_eq!(ep.add_subflow(ms(5), h, ip(JOIN_IP), 1500), Err(Closed));
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
    assert_eq!(events(ep), vec![]);
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
