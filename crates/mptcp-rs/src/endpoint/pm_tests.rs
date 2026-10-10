//! M3 API groundwork (M3 spec §4): subflow and address ids, the C=1 rule, the last initial
//! subflow's `SubflowDown` and argument checks of the path-management calls; MP_TCPRST on the
//! RSTs we send and receive (M3 spec §3.3, §3.4). A child of `join_tests`, whose helpers it
//! reuses.
use super::*;
use crate::endpoint::{AddressError, MpTcpRst, SubflowError};
use crate::mptcp::addr::PeerAddr;

fn addr_id(jsyn: &Segment) -> u8 {
    let (MpJoin::Syn { addr_id, .. }, _) = mp_join(jsyn) else {
        panic!()
    };
    addr_id
}
/// `join_syn`, then the peer resets the join: the subflow ends and is freed.
fn join_and_drop(
    ep: &mut Endpoint<ChaCha20Rng>,
    h: ConnectionHandle,
    now: Instant,
    ip: &str,
) -> (SubflowId, u8) {
    let (id, jsyn) = join_syn(ep, h, now, ip, 1500);
    input_at(ep, &rst_on(&jsyn), now);
    let down = Event::SubflowDown {
        subflow: id,
        reason: CloseReason::Reset,
        rst: None,
    };
    assert_eq!(events(ep), vec![down]);
    assert!(ep.conns[&h].subflows.iter().all(|sf| sf.id != id), "freed");
    (id, addr_id(&jsyn))
}

#[test]
fn subflow_ids_monotonic_never_reused() {
    let (mut ep, h, _, _) = confirmed();
    let (first, _) = join_and_drop(&mut ep, h, ms(10), JOIN_IP);
    let (second, _) = joined(&mut ep, h, ms(20), JOIN_IP, 1500, 7);
    assert_eq!((first, second), (SubflowId(1), SubflowId(2)));
}

#[test]
fn subflow_ids_exhausted_errors() {
    let (mut ep, h, _, _) = confirmed();
    ep.conns.get_mut(&h).unwrap().next_subflow = u32::MAX - 1;
    let (id, _) = join_syn(&mut ep, h, ms(10), JOIN_IP, 1500);
    assert_eq!(id, SubflowId(u32::MAX - 1));
    assert_eq!(
        ep.add_subflow(ms(10), h, JOIN_IP.parse().unwrap(), remote(), 1500, false),
        Err(AddSubflowError::SubflowIdsExhausted)
    );
}

#[test]
fn address_id_stable_per_ip() {
    let (mut ep, h, _, _) = confirmed();
    assert_eq!(join_and_drop(&mut ep, h, ms(10), JOIN_IP).1, 1);
    assert_eq!(join_and_drop(&mut ep, h, ms(20), "10.0.2.1").1, 2);
    assert_eq!(join_and_drop(&mut ep, h, ms(30), JOIN_IP).1, 1, "rejoin");
    assert_eq!(
        join_and_drop(&mut ep, h, ms(40), "10.0.0.1").1,
        0,
        "initial IP"
    );
    assert_eq!(join_and_drop(&mut ep, h, ms(50), "10.0.3.1").1, 3);
}

#[test]
fn too_many_addresses_after_256_ips() {
    let (mut ep, h, _, _) = confirmed();
    // With the initial IP, 256 distinct IPs.
    for i in 0..255 {
        let (_, id) = join_and_drop(&mut ep, h, ms(10), &format!("10.1.0.{i}"));
        assert_eq!(id, i + 1);
    }
    let ip = |s: &str| s.parse::<IpAddr>().unwrap();
    assert_eq!(
        ep.add_subflow(ms(20), h, ip("10.1.1.0"), remote(), 1500, false),
        Err(AddSubflowError::TooManyAddresses)
    );
    assert!(
        (ep.add_subflow(ms(20), h, ip("10.1.0.7"), remote(), 1500, false)).is_ok(),
        "a bound IP keeps its id"
    );
}

#[test]
fn peer_forbids_join_only_initial_pair() {
    let mut ep = Endpoint::new(ChaCha20Rng::seed_from_u64(40));
    let h = open(&mut ep);
    let syn = leak(transmit(&mut ep, ms(0)));
    let flags = CAP_H | mptcp::CAP_C;
    reply(&mut ep, &syn, &capable(1, flags), syn.seq.wrapping_add(1));
    drain(&mut ep, ms(1));
    let dss = data_ack(una(&ep, h));
    input_at(&mut ep, &peer_data(&syn, 5001, &dss, &[]), ms(2));
    assert_eq!(state(&ep, h), State::Confirmed);
    let ip: IpAddr = JOIN_IP.parse().unwrap();
    assert_eq!(
        ep.add_subflow(ms(3), h, ip, remote(), 1500, false),
        Err(AddSubflowError::PeerForbidsJoin)
    );
    let other = SocketAddr::new(remote().ip(), 81);
    assert_eq!(
        ep.add_subflow(ms(3), h, ip, other, 1500, false),
        Ok(SubflowId(1))
    );
    let jsyn = from(&drain(&mut ep, ms(3)), JOIN_IP);
    assert_eq!(jsyn.len(), 1);
    assert_eq!(jsyn[0].dst, other);
    assert!(matches!(mp_join(&jsyn[0]).0, MpJoin::Syn { .. }));
}

#[test]
fn failed_announced_address_refused() {
    let (mut ep, h, _, _) = confirmed();
    let other = SocketAddr::new(remote().ip(), 81);
    let entry = PeerAddr {
        advertised: Some((other.ip(), other.port())),
        failed: true,
    };
    ep.conns.get_mut(&h).unwrap().peer_addrs.0.insert(3, entry);
    let ip: IpAddr = JOIN_IP.parse().unwrap();
    assert_eq!(
        ep.add_subflow(ms(3), h, ip, other, 1500, false),
        Err(AddSubflowError::AddressFailed)
    );
    assert!(ep.add_subflow(ms(3), h, ip, remote(), 1500, false).is_ok());
}

#[test]
fn last_initial_subflow_down_emitted_and_retained() {
    let (mut ep, h, syn, _) = confirmed();
    let t = ms(10);
    input_at(&mut ep, &rst_on(&syn), t);
    assert_eq!(events(&mut ep), vec![initial_down(CloseReason::Reset)]);
    ep.handle_timeout(t);
    assert!(ep.connection(h).is_some(), "retained");
    assert_eq!(ep.poll_timeout(), Some(t + Duration::from_secs(60)));
    ep.handle_timeout(t + Duration::from_secs(60));
    let reason = CloseReason::Timeout;
    assert_eq!(events(&mut ep), vec![Event::Closed { reason }]);
}

#[test]
fn subflow_calls_reject_unknown_ids() {
    let (mut ep, h, _, _) = confirmed();
    let (ended, _) = join_and_drop(&mut ep, h, ms(10), JOIN_IP);
    let (up, _) = joined(&mut ep, h, ms(20), JOIN_IP, 1500, 7);
    let now = ms(30);
    for s in [SubflowId(7), ended] {
        assert_eq!(ep.set_backup(now, h, s, true), Err(SubflowError::NoSubflow));
        assert_eq!(
            ep.set_local_backup(h, s, true),
            Err(SubflowError::NoSubflow)
        );
        assert_eq!(ep.close_subflow(now, h, s), Err(SubflowError::NoSubflow));
    }
    assert!(drain(&mut ep, now).is_empty());
    assert_eq!(events(&mut ep), vec![]);
    for s in [SubflowId::INITIAL, up] {
        assert_eq!(ep.set_local_backup(h, s, true), Ok(()));
    }
    // A FIN exchange ending in TIME-WAIT has reported `SubflowDown` too. Only `close` leads
    // there today, so the connection's own `Closed` check is lifted.
    let (mut ep, h, ended) = stale_fin_then_time_wait(1);
    assert_eq!(ep.conns[&h].subflows[1].tcb.state(), TcpState::TimeWait);
    ep.conns.get_mut(&h).unwrap().closed_by_app = false;
    let now = ms(10_000);
    assert_eq!(
        ep.set_backup(now, h, ended, true),
        Err(SubflowError::NoSubflow)
    );
    assert_eq!(
        ep.set_local_backup(h, ended, true),
        Err(SubflowError::NoSubflow)
    );
    assert_eq!(
        ep.close_subflow(now, h, ended),
        Err(SubflowError::NoSubflow)
    );
}

#[test]
fn path_calls_validate_connection() {
    let ip = |s: &str| s.parse::<IpAddr>().unwrap();
    let s = SubflowId::INITIAL;
    let (mut ep, h, _, _) = confirmed();
    let none = ConnectionHandle(99);
    assert_eq!(
        ep.set_local_backup(none, s, true),
        Err(SubflowError::NoConnection)
    );
    assert_eq!(
        ep.remove_address(ms(5), none, ip("10.0.0.1")),
        Err(AddressError::NoConnection)
    );
    assert_eq!(
        ep.remove_address(ms(5), h, ip(JOIN_IP)),
        Err(AddressError::UnknownAddress)
    );
    assert_eq!(ep.remove_address(ms(5), h, ip("10.0.0.1")), Ok(()));
    // A queued join's id and IP are known as soon as `add_subflow` returns.
    let (mut ep, h, _, _) = connected_scaled(1 << 20);
    let q = (ep.add_subflow(ms(5), h, ip(JOIN_IP), remote(), 1500, false)).unwrap();
    assert_eq!(ep.set_local_backup(h, q, true), Ok(()));
    assert_eq!(ep.remove_address(ms(5), h, ip(JOIN_IP)), Ok(()));
    ep.connection(h).unwrap().close();
    assert_eq!(ep.set_local_backup(h, s, true), Err(SubflowError::Closed));
    assert_eq!(
        ep.remove_address(ms(5), h, ip("10.0.0.1")),
        Err(AddressError::Closed)
    );
    let mut ep = Endpoint::new(ChaCha20Rng::seed_from_u64(42));
    let cfg = ConnectConfig::default();
    let h = (ep.connect(ms(0), ip("10.0.0.1"), remote(), cfg)).unwrap();
    assert_eq!(ep.set_local_backup(h, s, true), Err(SubflowError::NotMptcp));
    assert_eq!(
        ep.remove_address(ms(0), h, ip("10.0.0.1")),
        Err(AddressError::NotMptcp)
    );
    ep.connection(h).unwrap().abort();
}

// Outside the crate (`#[non_exhaustive]`) this is the only way to build one.
#[allow(clippy::field_reassign_with_default)]
#[test]
fn connect_config_default_then_assign() {
    let mut cfg = ConnectConfig::default();
    cfg.mtu = 1400;
    cfg.recv_buffer = 1 << 16;
    let mut ep = Endpoint::new(ChaCha20Rng::seed_from_u64(1));
    let h = ep.connect_mptcp(ms(0), "10.0.0.1".parse().unwrap(), remote(), cfg);
    assert_eq!(ep.conns[&h.unwrap()].cfg.mtu, 1400);
}

/// MP_TCPRST wire bytes: kind 30, length 4, subtype 8 with the T flag, reason.
fn tcprst(reason: u8, transient: bool) -> [u8; 4] {
    [30, 4, 0x80 | u8::from(transient), reason]
}
/// The options of the only RST from `src` among `segs`.
fn rst_options<'a>(
    segs: impl IntoIterator<Item = &'a Segment<'static>>,
    src: SocketAddr,
) -> Vec<u8> {
    let rsts: Vec<_> = (segs.into_iter())
        .filter(|s| s.src == src && s.flags.contains(TcpFlags::RST))
        .collect();
    assert_eq!(rsts.len(), 1, "one RST from {src}");
    rsts[0].options.to_vec()
}

/// M3 spec §3.4, one scenario per row whose path exists (the `remove_address` and keepalive
/// rows come with REMOVE_ADDR).
#[test]
fn our_rst_reason_table() {
    // Joined-subflow option stripping: its first stripped ACK resets it. 0x06/T0.
    let (mut ep, h, _, jsyn) = two_paths(reno, reno);
    pin(&mut ep, h, Some(SubflowId(1)));
    ep.connection(h).unwrap().write(&[7; 1000]).unwrap();
    let seg = data_on(&drain(&mut ep, ms(20)), &jsyn).remove(0);
    let stripped = Segment {
        ack: end(&seg),
        ..peer_data(&jsyn, 5001, &[], &[])
    };
    input_at(&mut ep, &stripped, ms(30));
    let out = on(&drain(&mut ep, ms(30)), &jsyn);
    assert_eq!(
        rst_options(&out, jsyn.src),
        tcprst(0x06, false),
        "stripping"
    );

    // Invalid MP_JOIN in the SYN/ACK (bad HMAC). 0x01/T0.
    let (mut ep, h, _, _) = confirmed();
    let (_, jsyn) = join_syn(&mut ep, h, ms(10), JOIN_IP, 1500);
    let opts = synack_opts(&ep, h, &jsyn, 7, Some(1));
    synack(&mut ep, &jsyn, &opts, ms(20));
    let out = from(&drain(&mut ep, ms(20)), JOIN_IP);
    assert_eq!(
        rst_options(&out, jsyn.src),
        tcprst(0x01, false),
        "bad SYN/ACK"
    );

    // Ruling R18: subflow 1 holds data the peer DATA_ACKed on subflow 0 but never TCP-ACKs;
    // once both DATA_FINs are DATA_ACKed it is reset. 0x04/T1.
    let (mut ep, h, syn, jsyn) = two_paths(reno, reno);
    let head = una(&ep, h);
    pin(&mut ep, h, Some(SubflowId(1)));
    ep.connection(h).unwrap().write(&[7; 1000]).unwrap();
    assert_eq!(data_on(&drain(&mut ep, ms(20)), &jsyn).len(), 1);
    pin(&mut ep, h, None);
    ep.connection(h).unwrap().close();
    let out = drain(&mut ep, ms(20));
    let dfin = (on(&out, &syn).into_iter().find(data_fin)).expect("DATA_FIN on subflow 0");
    let opts = fin_option(peer_dsn(), 0, 1, Some(head + 1001));
    let seg = Segment {
        ack: dfin.seq,
        wnd: 65535,
        ..peer_data(&syn, 5001, &opts, &[])
    };
    input_at(&mut ep, &seg, ms(30));
    let out: Vec<_> = drive(&mut ep, ms(30), ms(5000))
        .into_iter()
        .map(|p| p.1)
        .collect();
    assert_eq!(rst_options(&out, jsyn.src), tcprst(0x04, true), "R18");

    // Data R2 on a joined subflow. 0x00/T1.
    let (mut ep, h, mut peer, t, _, data) = two_paths_primed(Duration::from_secs(3), 50_000);
    peer.drop[1] = true;
    ep.connection(h).unwrap().write(&data).unwrap();
    peer.run(&mut ep, h, t, t + Duration::from_secs(30));
    let out: Vec<_> = (peer.sent.iter()).map(|p| p.1.clone()).collect();
    assert_eq!(
        rst_options(&out, peer.syns[1].src),
        tcprst(0x00, true),
        "data R2"
    );

    // Third-ACK give-up at R2. 0x00/T1.
    let (mut ep, h, _, _) = confirmed();
    ep.conns.get_mut(&h).unwrap().cfg.r2_data = Duration::from_secs(5);
    let (_, jsyn) = join_syn(&mut ep, h, ms(10), JOIN_IP, 1500);
    let opts = synack_opts(&ep, h, &jsyn, 7, None);
    synack(&mut ep, &jsyn, &opts, ms(20));
    let out: Vec<_> = drive(&mut ep, ms(20), ms(20_000))
        .into_iter()
        .map(|p| p.1)
        .collect();
    assert_eq!(
        rst_options(&out, jsyn.src),
        tcprst(0x00, true),
        "third-ACK give-up"
    );

    // A received infinite mapping resets the other subflows. 0x01/T0.
    let (mut ep, _, syn, jsyn) = two_paths(reno, reno);
    peer_infinite_mapping(&mut ep, &jsyn, ms(20));
    let out = on(&drain(&mut ep, ms(20)), &syn);
    assert_eq!(
        rst_options(&out, syn.src),
        tcprst(0x01, false),
        "infinite mapping"
    );
}

/// A RST answering the join SYN: with MP_TCPRST T=0, T=1 or none it ends the subflow and the
/// join failure is recorded with what it carried; without ACK it is not acceptable in
/// SYN-SENT (RFC 9293 §3.10.7.3) and changes nothing.
#[test]
fn syn_sent_rst_t0_t1_none_unacceptable() {
    let t0 = MpTcpRst {
        reason: 0x03,
        transient: false,
    };
    let t1 = MpTcpRst {
        reason: 0x02,
        transient: true,
    };
    let rst = |jsyn: &Segment, opt: Option<MpTcpRst>, flags| {
        let opts = opt.map_or(vec![], |r| tcprst(r.reason, r.transient).to_vec());
        Segment {
            flags,
            ..peer_data(jsyn, 0, opts.leak(), &[])
        }
    };
    let ra = TcpFlags::RST | TcpFlags::ACK;
    for (opt, flags, accepted) in [
        (Some(t0), ra, true),
        (Some(t1), ra, true),
        (None, ra, true),
        (Some(t0), TcpFlags::RST, false),
    ] {
        // The record, read before the endpoint frees the subflow.
        let (mut ep, h, _, _) = confirmed();
        let (id, jsyn) = join_syn(&mut ep, h, ms(10), JOIN_IP, 1500);
        let c = ep.conns.get_mut(&h).unwrap();
        let sf = c.subflows.iter_mut().find(|s| s.id == id).unwrap();
        let mut hk = SubflowHooks {
            conn: &mut c.hooks,
            sf: &mut sf.mp,
        };
        sf.tcb.on_segment(&rst(&jsyn, opt, flags), ms(20), &mut hk);
        assert_eq!(
            sf.mp.join_failed,
            accepted.then_some(opt),
            "{opt:?} {flags:?}"
        );
        assert_eq!(sf.tcb.state() == TcpState::Closed, accepted);
        // The event, through the endpoint.
        let (mut ep, h, _, _) = confirmed();
        let (id, jsyn) = join_syn(&mut ep, h, ms(10), JOIN_IP, 1500);
        input_at(&mut ep, &rst(&jsyn, opt, flags), ms(20));
        let down = Event::SubflowDown {
            subflow: id,
            reason: CloseReason::Reset,
            rst: opt,
        };
        let want = if accepted { vec![down] } else { vec![] };
        assert_eq!(events(&mut ep), want, "{opt:?} {flags:?}");
    }
}

#[test]
fn joined_rst_reason_surfaced_in_subflow_down() {
    // Linux refusing a join (M3 suite probe): a bare RST at RCV.NXT after our third ACK.
    let (mut ep, h, _, _) = confirmed();
    let (id, jsyn) = join_syn(&mut ep, h, ms(10), JOIN_IP, 1500);
    let opts = synack_opts(&ep, h, &jsyn, 7, None);
    synack(&mut ep, &jsyn, &opts, ms(20));
    assert_eq!(from(&drain(&mut ep, ms(20)), JOIN_IP).len(), 1, "third ACK");
    let opt = tcprst(0x03, false);
    let refuse = Segment {
        flags: TcpFlags::RST,
        ..peer_data(&jsyn, 5001, &opt, &[])
    };
    input_at(&mut ep, &refuse, ms(30));
    let rst = Some(MpTcpRst {
        reason: 0x03,
        transient: false,
    });
    let reason = CloseReason::Reset;
    let subflow = id;
    assert_eq!(
        events(&mut ep),
        vec![Event::SubflowDown {
            subflow,
            reason,
            rst
        }]
    );
    // An Active joined subflow, then the last (initial) one.
    let (mut ep, _, syn, jsyn) = two_paths(reno, reno);
    for (s, subflow, reason) in [
        (&jsyn, SubflowId(1), 0x05),
        (&syn, SubflowId::INITIAL, 0x00),
    ] {
        let opt = tcprst(reason, true);
        let seg = Segment {
            options: &opt,
            ..rst_on(s)
        };
        input_at(&mut ep, &seg, ms(30));
        let rst = Some(MpTcpRst {
            reason,
            transient: true,
        });
        let reason = CloseReason::Reset;
        assert_eq!(
            events(&mut ep),
            vec![Event::SubflowDown {
                subflow,
                reason,
                rst
            }]
        );
    }
}

/// RSTs answering segments with no TCB carry no MPTCP option, also on a 4-tuple whose
/// subflow we reset with MP_TCPRST.
#[test]
fn no_tcb_rst_has_no_mptcp_option() {
    let (mut ep, h, _, _) = confirmed();
    let stray = Segment {
        src: "10.0.9.9:80".parse().unwrap(),
        dst: "10.0.0.1:40000".parse().unwrap(),
        seq: SeqNum(1),
        ack: SeqNum(77),
        flags: TcpFlags::ACK,
        wnd: 1000,
        options: &[],
        payload: b"x",
    };
    input_at(&mut ep, &stray, ms(10));
    let out: Vec<_> = drain(&mut ep, ms(10)).into_iter().map(leak).collect();
    assert_eq!(
        rst_options(&out, stray.dst),
        Vec::<u8>::new(),
        "unknown 4-tuple"
    );
    // A bad SYN/ACK resets the join with MP_TCPRST; its retransmission finds no TCB.
    let (_, jsyn) = join_syn(&mut ep, h, ms(20), JOIN_IP, 1500);
    let opts = synack_opts(&ep, h, &jsyn, 7, Some(1));
    synack(&mut ep, &jsyn, &opts, ms(30));
    let out = from(&drain(&mut ep, ms(30)), JOIN_IP);
    assert_eq!(rst_options(&out, jsyn.src), tcprst(0x01, false));
    synack(&mut ep, &jsyn, &opts, ms(40));
    let out = from(&drain(&mut ep, ms(40)), JOIN_IP);
    assert_eq!(
        rst_options(&out, jsyn.src),
        Vec::<u8>::new(),
        "freed join 4-tuple"
    );
}

/// MP_FASTCLOSE wire bytes carrying `key`.
fn fastclose(key: u64) -> Vec<u8> {
    let mut out = [0; 12];
    let option = MptcpOption::FastClose { receiver_key: key };
    let n = mptcp::encode(&option, &mut out).unwrap();
    out[..n].to_vec()
}
/// SND.MAX of `syn`'s subflow: `sent` holds everything it sent after its SYN.
fn snd_max(sent: &[Vec<u8>], syn: &Segment) -> SeqNum {
    let ends = on(sent, syn).iter().map(end).collect::<Vec<_>>();
    (ends.into_iter()).fold(syn.seq.wrapping_add(1), |m, e| if e.gt(m) { e } else { m })
}
const ABORTED: Event = Event::Closed {
    reason: CloseReason::Aborted,
};
/// `confirmed`, 3000 octets sent (none acknowledged), then aborted and freed at `ms(10)`.
/// Returns the endpoint, the SYN and SND.MAX.
fn aborted_with_data() -> (Endpoint<ChaCha20Rng>, Segment<'static>, SeqNum) {
    let (mut ep, h, syn, _) = confirmed();
    ep.connection(h).unwrap().write(&[7; 3000]).unwrap();
    let sent = drain(&mut ep, ms(5));
    let max = snd_max(&sent, &syn);
    assert!(max.gt(syn.seq.wrapping_add(1)), "data in flight");
    ep.connection(h).unwrap().abort();
    ep.handle_timeout(ms(10));
    assert_eq!(events(&mut ep), vec![ABORTED]);
    assert!(ep.connection(h).is_none());
    let out: Vec<_> = drain(&mut ep, ms(10)).into_iter().map(leak).collect();
    assert_eq!(out.len(), 1);
    let fc = fastclose(PEER_KEY);
    assert_eq!(
        (out[0].seq, out[0].flags, out[0].options),
        (max, TcpFlags::RST, &fc[..])
    );
    (ep, syn, max)
}

/// M3 spec §3.5: every synchronized subflow (Active, Stale, Joining after its SYN/ACK) gets
/// one RST at SND.MAX carrying only MP_FASTCLOSE with the peer's key, sent after the teardown;
/// a join in SYN-SENT gets none. No `SubflowDown`.
#[test]
fn abort_sends_fastclose_rst_on_every_subflow() {
    let (mut ep, h, syn, jsyn) = two_paths(reno, reno);
    ep.connection(h).unwrap().write(&[7; 20_000]).unwrap();
    let mut sent = drain(&mut ep, ms(20));
    let (_, jsyn2) = join_syn(&mut ep, h, ms(30), "10.0.2.1", 1500);
    let opts = synack_opts(&ep, h, &jsyn2, 7, None);
    synack(&mut ep, &jsyn2, &opts, ms(30));
    sent.extend(drain(&mut ep, ms(30)));
    let (_, jsyn3) = join_syn(&mut ep, h, ms(30), "10.0.3.1", 1500);
    let c = ep.conns.get_mut(&h).unwrap();
    // Health is not under test: subflow 1 is made Stale directly.
    c.subflows[1].state = SubflowState::Stale;
    assert_eq!(c.subflows[2].state, SubflowState::Joining);
    assert_eq!(c.subflows[2].tcb.state(), TcpState::Established);
    assert_eq!(c.subflows[3].tcb.state(), TcpState::SynSent);
    ep.connection(h).unwrap().abort();
    ep.handle_timeout(ms(40));
    assert_eq!(events(&mut ep), vec![ABORTED]);
    assert!(
        ep.connection(h).is_none(),
        "torn down before the RSTs leave"
    );
    let out: Vec<_> = drain(&mut ep, ms(40)).into_iter().map(leak).collect();
    let fc = fastclose(PEER_KEY);
    for s in [&syn, &jsyn, &jsyn2] {
        let rst: Vec<_> = out.iter().filter(|g| g.src == s.src).collect();
        assert_eq!(rst.len(), 1, "one RST from {}", s.src);
        assert_eq!(rst[0].dst, s.dst);
        let max = snd_max(&sent, s);
        assert_eq!(
            (rst[0].seq, rst[0].flags, rst[0].options),
            (max, TcpFlags::RST, &fc[..])
        );
    }
    assert!(out.iter().all(|g| g.src != jsyn3.src), "SYN-SENT: no RST");
    assert_eq!(out.len(), 3);
    assert_eq!(events(&mut ep), vec![]);
}

/// Before the SYN/ACK nothing is synchronized and no key is known: the TCB is deleted without
/// a RST (RFC 9293 §3.10.5), and a late SYN/ACK gets a plain RST.
#[test]
fn abort_before_synack_plain_rst() {
    let mut ep = Endpoint::new(ChaCha20Rng::seed_from_u64(42));
    let h = open(&mut ep);
    let syn = leak(transmit(&mut ep, ms(0)));
    ep.connection(h).unwrap().abort();
    assert!(drain(&mut ep, ms(1)).is_empty(), "no RST in SYN-SENT");
    assert_eq!(events(&mut ep), vec![ABORTED]);
    ep.handle_timeout(ms(1));
    assert!(ep.connection(h).is_none());
    let opts = capable(1, CAP_H);
    let synack = Segment {
        flags: TcpFlags::SYN | TcpFlags::ACK,
        seq: SeqNum(5000),
        ..peer_data(&syn, 5000, &opts, &[])
    };
    let rst = answer(&mut ep, &synack, ms(2)).expect("RST for the late SYN/ACK");
    assert_eq!((rst.seq, rst.flags), (synack.ack, TcpFlags::RST));
    assert!(rst.options.is_empty());
    assert_eq!(events(&mut ep), vec![]);
}

/// After a fallback to TCP: a plain RST at SND.MAX, and the 4-tuple is not retained.
#[test]
fn abort_after_fallback_plain_rst() {
    let (mut ep, h, syn, _) = confirmed();
    peer_infinite_mapping(&mut ep, &syn, ms(10));
    let mut sent = drain(&mut ep, ms(10));
    assert_eq!(events(&mut ep), vec![Event::FellBack]);
    ep.connection(h).unwrap().write(&[7; 100]).unwrap();
    sent.extend(drain(&mut ep, ms(20)));
    ep.connection(h).unwrap().abort();
    let out: Vec<_> = drain(&mut ep, ms(30)).into_iter().map(leak).collect();
    assert_eq!(out.len(), 1);
    let max = snd_max(&sent, &syn);
    assert_eq!(
        (out[0].src, out[0].seq, out[0].flags),
        (syn.src, max, TcpFlags::RST)
    );
    assert!(out[0].options.is_empty());
    assert_eq!(events(&mut ep), vec![ABORTED]);
    ep.handle_timeout(ms(30));
    assert!(ep.connection(h).is_none());
    let chal = peer_data(&syn, 5006, &[], &[]);
    let rst = answer(&mut ep, &chal, ms(40)).expect("RST");
    assert!(rst.options.is_empty(), "not retained");
}

#[test]
fn abort_plain_tcp_plain_rst() {
    let mut ep = Endpoint::new(ChaCha20Rng::seed_from_u64(42));
    let cfg = ConnectConfig::default();
    let h = (ep.connect(ms(0), "10.0.0.1".parse().unwrap(), remote(), cfg)).unwrap();
    let syn = leak(transmit(&mut ep, ms(0)));
    reply(&mut ep, &syn, &[], syn.seq.wrapping_add(1));
    let mut sent = drain(&mut ep, ms(1));
    assert_eq!(events(&mut ep), vec![Event::Connected { mptcp: false }]);
    ep.connection(h).unwrap().write(&[7; 100]).unwrap();
    sent.extend(drain(&mut ep, ms(2)));
    ep.connection(h).unwrap().abort();
    let out: Vec<_> = drain(&mut ep, ms(3)).into_iter().map(leak).collect();
    assert_eq!(out.len(), 1);
    let max = snd_max(&sent, &syn);
    assert!(max.gt(syn.seq.wrapping_add(1)));
    assert_eq!((out[0].seq, out[0].flags), (max, TcpFlags::RST));
    assert!(out[0].options.is_empty());
    assert_eq!(events(&mut ep), vec![ABORTED]);
}

/// The peer missed our data, so our RST at SND.MAX is beyond its RCV.NXT: it answers with a
/// challenge ACK (RFC 9293 L3567–3575), and our RST to that is at its ACK, with MP_FASTCLOSE,
/// whether the aborted connection is still held or already freed.
#[test]
fn fastclose_challenge_ack_answered_exactly() {
    for freed in [false, true] {
        let (mut ep, h, syn, _) = confirmed();
        ep.connection(h).unwrap().write(&[7; 3000]).unwrap();
        let sent = drain(&mut ep, ms(5));
        ep.connection(h).unwrap().abort();
        let out: Vec<_> = drain(&mut ep, ms(10)).into_iter().map(leak).collect();
        assert_eq!(out[0].seq, snd_max(&sent, &syn));
        if freed {
            ep.handle_timeout(ms(10));
        }
        assert_eq!(ep.connection(h).is_none(), freed);
        let rcv_nxt = syn.seq.wrapping_add(1);
        let chal = Segment {
            ack: rcv_nxt,
            ..peer_data(&syn, 5001, &[], &[])
        };
        let rst = answer(&mut ep, &chal, ms(30)).expect("RST for the challenge ACK");
        assert_eq!((rst.src, rst.dst), (syn.src, syn.dst));
        assert_eq!(
            (rst.seq, rst.ack, rst.flags),
            (rcv_nxt, SeqNum(0), TcpFlags::RST)
        );
        assert_eq!(rst.options, &fastclose(PEER_KEY)[..], "freed={freed}");
    }
}

/// RSTs are never answered (RFC 9293 §3.10.7.1), so simultaneous aborts cannot loop.
#[test]
fn retained_tuple_incoming_rst_not_answered() {
    let (mut ep, syn, _) = aborted_with_data();
    assert!(answer(&mut ep, &rst_on(&syn), ms(20)).is_none());
    let fc = fastclose(0x55);
    let theirs = Segment {
        flags: TcpFlags::RST,
        options: &fc,
        ..rst_on(&syn)
    };
    assert!(
        answer(&mut ep, &theirs, ms(20)).is_none(),
        "the peer's own abort"
    );
}

/// No ACK bit: `<SEQ=0><ACK=SEG.SEQ+SEG.LEN><CTL=RST,ACK>`, with MP_FASTCLOSE.
#[test]
fn retained_tuple_no_ack_segment_format() {
    let (mut ep, syn, _) = aborted_with_data();
    let bare = Segment {
        flags: TcpFlags::FIN,
        ack: SeqNum(0),
        ..peer_data(&syn, 5001, &[], b"xy")
    };
    let rst = answer(&mut ep, &bare, ms(20)).expect("RST for the bare FIN");
    assert_eq!(
        (rst.seq, rst.ack, rst.flags),
        (SeqNum(0), SeqNum(5004), TcpFlags::RST | TcpFlags::ACK)
    );
    assert_eq!(rst.options, &fastclose(PEER_KEY)[..]);
}

/// The entry lasts 3 × the subflow's RTO (1 s here), which `poll_timeout` reports; until then
/// its 4-tuple is not given to a new connection, afterwards it is, and answers are plain.
#[test]
fn retained_tuple_not_reallocated_until_expiry() {
    let (mut ep, syn, _) = aborted_with_data();
    let expiry = ms(10) + Duration::from_secs(3);
    assert_eq!(ep.poll_timeout(), Some(expiry));
    // Every other ephemeral port to the remote is taken: only the retained one is left.
    let taken = (ConnectionHandle(99), SubflowId::INITIAL);
    for port in EPHEMERAL_FIRST..=u16::MAX {
        if port != syn.src.port() {
            ep.demux
                .insert((SocketAddr::new(syn.src.ip(), port), syn.dst), taken);
        }
    }
    let chal = peer_data(&syn, 5001, &[], &[]);
    let before = Instant::from_nanos(expiry.as_nanos() - 1);
    let rst = answer(&mut ep, &chal, before).expect("RST");
    assert_eq!(rst.options, &fastclose(PEER_KEY)[..]);
    let cfg = ConnectConfig::default;
    let ip = syn.src.ip();
    assert_eq!(
        ep.connect(before, ip, syn.dst, cfg()).err(),
        Some(ConnectError::NoPort)
    );
    ep.handle_timeout(expiry);
    assert_eq!(ep.poll_timeout(), None);
    let rst = answer(&mut ep, &chal, expiry).expect("RST");
    assert!(rst.options.is_empty(), "expired");
    let h = ep.connect(expiry, ip, syn.dst, cfg()).unwrap();
    assert_eq!(ep.connection(h).unwrap().local(), syn.src);
}

/// The 65th aborted 4-tuple evicts the oldest; the others keep answering with MP_FASTCLOSE.
#[test]
fn retained_table_evicts_oldest_at_64() {
    let mut ep = Endpoint::new(ChaCha20Rng::seed_from_u64(42));
    let syns: Vec<_> = (0..65)
        .map(|_| {
            let h = open(&mut ep);
            let syn = from(&drain(&mut ep, ms(0)), "10.0.0.1").pop().unwrap();
            reply(&mut ep, &syn, &capable(1, CAP_H), syn.seq.wrapping_add(1));
            ep.connection(h).unwrap().abort();
            drain(&mut ep, ms(0));
            syn
        })
        .collect();
    ep.handle_timeout(ms(1));
    // Aborted before the third ACK left: no `Connected`.
    assert_eq!(events(&mut ep), vec![ABORTED; 65]);
    for (i, syn) in syns.iter().enumerate() {
        let rst = answer(&mut ep, &peer_data(syn, 5001, &[], &[]), ms(2)).expect("RST");
        let want = if i == 0 { vec![] } else { fastclose(PEER_KEY) };
        assert_eq!(rst.options, &want[..], "tuple {i}");
    }
}

/// Review Focus 4: `abort` twice, after `Closed`, in the no-subflow wait and in SYN-SENT: no
/// panic, exactly one `Closed`, and only the RSTs §3.5 prescribes.
#[test]
fn abort_is_idempotent_in_every_state() {
    // Twice, then once more after the RST left.
    let (mut ep, h, syn, _) = confirmed();
    ep.connection(h).unwrap().abort();
    ep.connection(h).unwrap().abort();
    let out: Vec<_> = drain(&mut ep, ms(10)).into_iter().map(leak).collect();
    assert_eq!(out.len(), 1);
    let fc = fastclose(PEER_KEY);
    assert_eq!(
        (out[0].src, out[0].flags, out[0].options),
        (syn.src, TcpFlags::RST, &fc[..])
    );
    // `close` after `abort` changes nothing.
    ep.connection(h).unwrap().close();
    ep.connection(h).unwrap().abort();
    assert!(drain(&mut ep, ms(10)).is_empty());
    ep.handle_timeout(ms(10));
    assert_eq!(events(&mut ep), vec![ABORTED]);
    assert!(ep.connection(h).is_none());

    // After `Closed { Reset }` from the peer's MP_FASTCLOSE: only its own RST.
    let (mut ep, h, syn, _) = confirmed();
    let fc = fastclose(local_key(&ep, h));
    input_at(&mut ep, &peer_data(&syn, 5001, &fc, &[]), ms(10));
    ep.connection(h).unwrap().abort();
    let out: Vec<_> = drain(&mut ep, ms(10)).into_iter().map(leak).collect();
    assert_eq!(out.len(), 1);
    assert!(
        out[0].options.is_empty(),
        "the reset of a received MP_FASTCLOSE"
    );
    let reason = CloseReason::Reset;
    assert_eq!(events(&mut ep), vec![Event::Closed { reason }]);

    // After `Closed { Reset }` of a plain TCP connection.
    let mut ep = Endpoint::new(ChaCha20Rng::seed_from_u64(42));
    let cfg = ConnectConfig::default();
    let h = (ep.connect(ms(0), "10.0.0.1".parse().unwrap(), remote(), cfg)).unwrap();
    let syn = leak(transmit(&mut ep, ms(0)));
    reply(&mut ep, &syn, &[], syn.seq.wrapping_add(1));
    drain(&mut ep, ms(1));
    input_at(&mut ep, &rst_on(&syn), ms(2));
    ep.connection(h).unwrap().abort();
    assert!(drain(&mut ep, ms(2)).is_empty());
    let connected = Event::Connected { mptcp: false };
    assert_eq!(events(&mut ep), vec![connected, Event::Closed { reason }]);

    // In the no-subflow wait: no TCB is synchronized, so no RST.
    let (mut ep, h, syn, _) = confirmed();
    input_at(&mut ep, &rst_on(&syn), ms(10));
    assert_eq!(events(&mut ep), vec![initial_down(CloseReason::Reset)]);
    ep.connection(h).unwrap().abort();
    assert!(drain(&mut ep, ms(10)).is_empty());
    assert_eq!(events(&mut ep), vec![ABORTED]);
    ep.handle_timeout(ms(10) + Duration::from_secs(60));
    assert_eq!(events(&mut ep), vec![]);

    // SYN-SENT, twice.
    let mut ep = Endpoint::new(ChaCha20Rng::seed_from_u64(42));
    let h = open(&mut ep);
    transmit(&mut ep, ms(0));
    ep.connection(h).unwrap().abort();
    ep.connection(h).unwrap().close();
    ep.connection(h).unwrap().abort();
    assert!(drain(&mut ep, ms(1)).is_empty());
    ep.handle_timeout(ms(1));
    assert_eq!(events(&mut ep), vec![ABORTED]);
    assert!(ep.connection(h).is_none());
    assert_eq!(ep.poll_timeout(), None);
}

/// RFC 9293 §3.10.7: a valid peer RST at RCV.NXT is never answered, with or without
/// MP_FASTCLOSE; MP_FASTCLOSE still resets the connection's other subflows.
#[test]
fn valid_peer_rst_never_answered() {
    for with_fastclose in [false, true] {
        let (mut ep, h, syn, jsyn) = two_paths(reno, reno);
        let fc = fastclose(local_key(&ep, h));
        let opts = if with_fastclose { &fc[..] } else { &[] };
        let rst = Segment {
            options: opts,
            ..rst_on(&syn)
        };
        input_at(&mut ep, &rst, ms(20));
        let out: Vec<_> = drain(&mut ep, ms(20)).into_iter().map(leak).collect();
        assert!(
            out.iter().all(|g| g.src != syn.src),
            "{with_fastclose}: {out:?}"
        );
        let others = out
            .iter()
            .filter(|g| g.src == jsyn.src && g.flags.contains(TcpFlags::RST));
        assert_eq!(others.count(), usize::from(with_fastclose));
    }
}

/// Ruling R15: TIME-WAIT subflows are synchronized too, so `abort` resets them with
/// MP_FASTCLOSE at SND.MAX and retains their 4-tuples.
#[test]
fn abort_resets_time_wait_subflows() {
    let (mut ep, h, _) = stale_fin_then_time_wait(1);
    let now = ms(10_000);
    let tuples: Vec<_> = (ep.conns[&h].subflows.iter())
        .map(|sf| (sf.local, sf.remote))
        .collect();
    assert!((ep.conns[&h].subflows.iter()).all(|sf| sf.tcb.state() == TcpState::TimeWait));
    // The peer's FIN again, without ACK: TIME-WAIT ACKs it at SND.NXT, which is SND.MAX.
    let fin = |(local, remote): (SocketAddr, SocketAddr)| Segment {
        src: remote,
        dst: local,
        seq: SeqNum(5001),
        ack: SeqNum(0),
        flags: TcpFlags::FIN,
        wnd: 65535,
        options: &[],
        payload: &[],
    };
    let max: Vec<_> = (tuples.iter())
        .map(|&t| answer(&mut ep, &fin(t), now).expect("TIME-WAIT ACK").seq)
        .collect();
    ep.connection(h).unwrap().abort();
    ep.handle_timeout(now);
    assert_eq!(events(&mut ep), vec![ABORTED]);
    let out: Vec<_> = drain(&mut ep, now).into_iter().map(leak).collect();
    assert_eq!(out.len(), 2);
    let fc = fastclose(PEER_KEY);
    for (&(local, _), max) in tuples.iter().zip(max) {
        let rst = out.iter().find(|g| g.src == local).expect("RST");
        assert_eq!(
            (rst.seq, rst.flags, rst.options),
            (max, TcpFlags::RST, &fc[..])
        );
    }
    for &t in &tuples {
        let rst = answer(&mut ep, &fin(t), now).expect("retained answer");
        assert_eq!((rst.ack, rst.options), (SeqNum(5002), &fc[..]));
    }
}
