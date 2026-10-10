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

// M3 Task 7: MP_PRIO, backup scheduling and the signal queue (M3 spec §3.2, §3.3, §4.5).

use crate::mptcp::signal::Echo;
use crate::tcp::{AckPurpose, SegmentHooks};

fn mptcp_opts(seg: &Segment) -> Vec<MptcpOption> {
    (mpc(seg.options).iter())
        .map(|o| mptcp::parse(o).unwrap())
        .collect()
}
fn prios(seg: &Segment) -> Vec<bool> {
    (mptcp_opts(seg).into_iter())
        .filter_map(|o| match o {
            MptcpOption::Prio { backup } => Some(backup),
            _ => None,
        })
        .collect()
}
/// The MP_PRIO values sent on `syn`'s subflow among `pkts`, and that none went elsewhere.
fn prios_on(pkts: &[Vec<u8>], syn: &Segment) -> Vec<bool> {
    let all: Vec<_> = pkts.iter().map(|p| leak(p.clone())).collect();
    assert!(
        (all.iter()).all(|s| s.src == syn.src || prios(s).is_empty()),
        "MP_PRIO on another subflow"
    );
    all.iter()
        .filter(|s| s.src == syn.src)
        .flat_map(prios)
        .collect()
}
/// The peer's DSS DATA_ACK plus MP_PRIO (Linux's form, M3 notes: `endpoint change … backup`).
fn peer_prio(ep: &Endpoint<ChaCha20Rng>, h: ConnectionHandle, backup: bool) -> Vec<u8> {
    let mut opts = data_ack(una(ep, h));
    opts.extend([30, 3, 0x50 | u8::from(backup)]);
    opts
}
fn snapshot_backup(ep: &Endpoint<ChaCha20Rng>, h: ConnectionHandle) -> Vec<bool> {
    ep.conns[&h].snapshots().iter().map(|s| s.backup).collect()
}
fn signals(
    ep: &mut Endpoint<ChaCha20Rng>,
    h: ConnectionHandle,
) -> &mut crate::mptcp::signal::Signals {
    &mut ep.conns.get_mut(&h).unwrap().hooks.signals
}
fn v6_echo() -> Echo {
    Echo {
        id: 3,
        addr: "dead:beef::2".parse().unwrap(),
        port: Some(5201),
    }
}
type Idle = (
    Endpoint<ChaCha20Rng>,
    ConnectionHandle,
    Segment<'static>,
    u64,
    Instant,
    SeqNum,
);
/// A single-path Confirmed connection (Reno) with an RTT sample of 100 ms: also the peer's
/// first DSN, the time after the sample and SND.UNA.
fn idle_100ms() -> Idle {
    let (mut ep, h, syn, dsn) = confirmed_cc(reno);
    let (t, una0) = prime(&mut ep, h, &syn, SubflowId::INITIAL, ms(20), 100);
    (ep, h, syn, dsn, t, una0)
}
fn srtt0(ep: &Endpoint<ChaCha20Rng>, h: ConnectionHandle) -> Duration {
    let srtt = ep.conns[&h].subflows[0].tcb.srtt().unwrap();
    assert!(srtt >= Duration::from_millis(10), "{srtt:?}");
    srtt
}

#[test]
fn mp_prio_sent_on_its_subflow_once() {
    let (mut ep, h, _, jsyn) = two_paths(reno, reno);
    let now = ms(20);
    assert_eq!(ep.set_backup(now, h, SubflowId(1), true), Ok(()));
    let out = drain(&mut ep, now);
    assert_eq!(prios_on(&out, &jsyn), vec![true]);
    let seg = on(&out, &jsyn).into_iter().find(|s| !prios(s).is_empty());
    let seg = seg.unwrap();
    assert_eq!((seg.flags, seg.payload.len()), (TcpFlags::ACK, 0));
    assert_eq!(seg.seq, jsyn.seq.wrapping_add(1), "at SND.MAX: acceptable");
    // A signal-only ACK: the DSS DATA_ACK first, then MP_PRIO B=1.
    let opts = mptcp_opts(&seg);
    assert!(
        matches!(opts[..], [MptcpOption::Dss(d), MptcpOption::Prio { backup: true }]
            if d.data_ack.is_some() && d.mapping.is_none()),
        "{opts:?}"
    );
    // Sent once: no repeat on later polls and timers.
    let later = drain_until(&mut ep, now, now + Duration::from_secs(10));
    assert!(prios_on(&later, &jsyn).is_empty());
}

#[test]
fn mp_prio_repeat_and_coalesce() {
    let (mut ep, h, _, jsyn) = two_paths(reno, reno);
    let s = SubflowId(1);
    // Sent, lost, then repeated with the same value: sent again.
    let t = ms(20);
    ep.set_backup(t, h, s, true).unwrap();
    assert_eq!(prios_on(&drain(&mut ep, t), &jsyn), vec![true]);
    ep.set_backup(t, h, s, true).unwrap();
    assert_eq!(prios_on(&drain(&mut ep, t), &jsyn), vec![true]);
    // Two identical calls before a poll: one option.
    let t = ms(3000);
    ep.set_backup(t, h, s, false).unwrap();
    ep.set_backup(t, h, s, false).unwrap();
    assert_eq!(prios_on(&drain(&mut ep, t), &jsyn), vec![false]);
    // A change reverted before transmission: the latest value, once.
    let t = ms(6000);
    ep.set_backup(t, h, s, true).unwrap();
    ep.set_backup(t, h, s, false).unwrap();
    assert_eq!(prios_on(&drain(&mut ep, t), &jsyn), vec![false]);
    assert!(prios_on(&drain_until(&mut ep, t, ms(20_000)), &jsyn).is_empty());
}

#[test]
fn join_syn_b_bit_advertises_backup() {
    let (mut ep, h, _, _) = confirmed();
    let ip: IpAddr = JOIN_IP.parse().unwrap();
    for backup in [true, false] {
        ep.add_subflow(ms(10), h, ip, remote(), 1500, backup)
            .unwrap();
        let jsyn = from(&drain(&mut ep, ms(10)), JOIN_IP).pop().unwrap();
        assert!(matches!(mp_join(&jsyn).0, MpJoin::Syn { backup: b, .. } if b == backup));
    }
    // Advertised only: our own transmit policy is unchanged.
    let c = &ep.conns[&h];
    assert!(c.subflows.iter().all(|sf| !sf.mp.backup()));
}

#[test]
fn peer_mp_prio_and_synack_b_bit_set_peer_requested() {
    let (mut ep, h, syn, _) = confirmed();
    let now = ms(10);
    let (id, jsyn) = join_syn(&mut ep, h, now, JOIN_IP, 1500);
    let mut opts = synack_opts(&ep, h, &jsyn, 7, None);
    assert_eq!(opts[..3], [30, 16, 0x10]);
    opts[2] |= 1; // the SYN/ACK's B bit
    synack(&mut ep, &jsyn, &opts, now);
    let ack = from(&drain(&mut ep, now), JOIN_IP)
        .pop()
        .expect("third ACK");
    assert_third_ack(&ep, h, &jsyn, &ack);
    let head = una(&ep, h);
    peer_ack(&mut ep, &jsyn, now, jsyn.seq.wrapping_add(1), head, 1000);
    // The B bit is the initial value: no event.
    assert_eq!(events(&mut ep), vec![Event::SubflowUp { subflow: id }]);
    drain(&mut ep, now);
    assert_eq!(snapshot_backup(&ep, h), [false, true]);
    // MP_PRIO on the subflow it arrived on, each time.
    let prio = peer_prio(&ep, h, false);
    signal_ack(&mut ep, &jsyn, jsyn.seq.wrapping_add(1), &prio, now);
    let prio = peer_prio(&ep, h, true);
    signal_ack(&mut ep, &syn, syn.seq.wrapping_add(1), &prio, now);
    signal_ack(&mut ep, &syn, syn.seq.wrapping_add(1), &prio, now);
    let peer = |subflow, backup| Event::PeerPriority { subflow, backup };
    let s0 = SubflowId::INITIAL;
    assert_eq!(
        events(&mut ep),
        vec![peer(id, false), peer(s0, true), peer(s0, true)]
    );
    drain(&mut ep, now);
    assert_eq!(snapshot_backup(&ep, h), [true, false]);
    // A TCP-unacceptable segment carries no signal.
    let late = Segment {
        seq: SeqNum(4000),
        ..peer_data(&jsyn, 5001, &prio, &[])
    };
    input_at(&mut ep, &late, now);
    assert_eq!(events(&mut ep), vec![]);
}

#[test]
fn effective_backup_is_local_or_peer() {
    for (local, peer) in [(false, false), (true, false), (false, true), (true, true)] {
        let (mut ep, h, _, jsyn) = two_paths(reno, reno);
        let now = ms(20);
        ep.set_local_backup(h, SubflowId(1), local).unwrap();
        let prio = peer_prio(&ep, h, peer);
        signal_ack(&mut ep, &jsyn, jsyn.seq.wrapping_add(1), &prio, now);
        drain(&mut ep, now);
        assert_eq!(
            snapshot_backup(&ep, h),
            [false, local || peer],
            "{local} {peer}"
        );
        // Our advertised preference (MP_PRIO we send) is a third, independent notion.
        ep.set_backup(now, h, SubflowId(1), !(local || peer))
            .unwrap();
        drain(&mut ep, now);
        assert_eq!(snapshot_backup(&ep, h), [false, local || peer]);
    }
    // `set_local_backup` right after `add_subflow`, while the join is queued.
    let mut ep = Endpoint::new(ChaCha20Rng::seed_from_u64(40));
    let h = open(&mut ep);
    let ip: IpAddr = JOIN_IP.parse().unwrap();
    let id = ep.add_subflow(ms(0), h, ip, remote(), 1500, false).unwrap();
    assert_eq!(ep.set_local_backup(h, id, true), Ok(()));
    let syn = leak(transmit(&mut ep, ms(0)));
    reply(&mut ep, &syn, &capable(1, CAP_H), syn.seq.wrapping_add(1));
    drain(&mut ep, ms(1));
    let dss = data_ack(una(&ep, h));
    input_at(&mut ep, &peer_data(&syn, 5001, &dss, &[]), ms(2));
    let jsyn = from(&drain(&mut ep, ms(2)), JOIN_IP)
        .pop()
        .expect("join SYN");
    assert!(matches!(
        mp_join(&jsyn).0,
        MpJoin::Syn { backup: false, .. }
    ));
    assert!(ep.conns[&h].subflows[1].mp.backup(), "local backup kept");
}

/// Two Reno paths, subflow 1 (10 ms) faster than subflow 0 (30 ms) and locally backup.
fn primary_and_backup() -> (
    Endpoint<ChaCha20Rng>,
    ConnectionHandle,
    Segment<'static>,
    Segment<'static>,
    Instant,
    SeqNum,
) {
    let (mut ep, h, syn, jsyn) = two_paths(reno, reno);
    let (t, una0) = prime(&mut ep, h, &syn, SubflowId(0), ms(20), 30);
    let (t, _) = prime(&mut ep, h, &jsyn, SubflowId(1), t, 10);
    ep.set_local_backup(h, SubflowId(1), true).unwrap();
    (ep, h, syn, jsyn, t, una0)
}

#[test]
fn zero_window_primary_activates_backup_and_back() {
    let (mut ep, h, syn, jsyn, t, una0) = primary_and_backup();
    // The primary's own window closes while data waits.
    let head = una(&ep, h);
    peer_ack(&mut ep, &syn, t, una0, head, 0);
    ep.connection(h).unwrap().write(&[1; 200_000]).unwrap();
    // Drives `ep` for `secs` with data always waiting, answering the primary's probes with
    // window `wnd0` and ACKing the backup's data at once; returns (probes on 0, data octets on
    // 0, data octets on 1, the time reached).
    let run = |ep: &mut Endpoint<ChaCha20Rng>, mut now: Instant, secs: u64, wnd0: u16| {
        let (mut probes, mut on0, mut on1) = (0, 0, 0);
        let until = now + Duration::from_secs(secs);
        while now < until {
            if ep.poll_timeout().is_some_and(|d| d <= now) {
                ep.handle_timeout(now);
            }
            // The application always has more: data waits throughout.
            ep.connection(h).unwrap().write(&[1; 65536]).unwrap();
            for s in drain(ep, now).into_iter().map(leak) {
                let len = s.payload.len();
                if s.src == syn.src {
                    if len == 0 && s.seq == una0.wrapping_add(u32::MAX) {
                        probes += 1;
                        let head = una(ep, h);
                        peer_ack(ep, &syn, now, una0, head, wnd0);
                    }
                    on0 += len;
                } else if len > 0 {
                    on1 += len;
                    let (dsn, _) = dsn_of(&s, jsyn.seq).unwrap();
                    peer_ack(ep, &jsyn, now, end(&s), dsn + len as u64, 65535);
                }
            }
            now = now + ms_d(10);
        }
        (probes, on0, on1, now)
    };
    let (probes, on0, on1, now) = run(&mut ep, t, 5, 0);
    assert!(probes >= 2, "the primary is probed: {probes}");
    assert_eq!(on0, 0, "no data on the zero-window primary");
    assert!(on1 > 0, "the backup carries the data");
    // The window reopens: new data returns to the primary, none goes to the backup.
    let head = una(&ep, h);
    peer_ack(&mut ep, &syn, now, una0, head, 1000);
    let (_, on0, on1, _) = run(&mut ep, now, 2, 1000);
    assert!(on0 > 0);
    assert_eq!(on1, 0);
}

#[test]
fn cwnd_exhausted_primary_never_spills_to_backup() {
    let (mut ep, h, syn, jsyn, t, _) = primary_and_backup();
    ep.connection(h).unwrap().write(&[1; 200_000]).unwrap();
    // No ACKs: the primary's cwnd fills and its RTO fires (not yet Stale).
    let out = drain_until(&mut ep, t, t + Duration::from_secs(3));
    assert!(!data_on(&out, &syn).is_empty());
    assert!(
        data_on(&out, &jsyn).is_empty(),
        "nothing spills onto the backup"
    );
    let d = ep.conns[&h].hooks.data.as_ref().unwrap();
    assert_ne!(d.send.next, d.send.end, "data still waits");
}

#[test]
fn all_backup_still_sends() {
    let (mut ep, h, syn, jsyn) = two_paths(reno, reno);
    let (t, _) = prime(&mut ep, h, &syn, SubflowId(0), ms(20), 30);
    let (t, una1) = prime(&mut ep, h, &jsyn, SubflowId(1), t, 10);
    // One subflow backup locally, the other by the peer's request.
    ep.set_local_backup(h, SubflowId::INITIAL, true).unwrap();
    let prio = peer_prio(&ep, h, true);
    signal_ack(&mut ep, &jsyn, una1, &prio, t);
    let n = 300_000;
    let data: Vec<u8> = (0..n).map(|i| (i % 251) as u8).collect();
    let head = una(&ep, h);
    assert_eq!(ep.connection(h).unwrap().write(&data), Ok(n));
    let mut peer = Peer::new(head, n, &[(&syn, 30), (&jsyn, 10)]);
    peer.run(&mut ep, h, t, t + Duration::from_secs(30));
    assert_eq!(peer.received(), data);
    assert_eq!(snapshot_backup(&ep, h), [true, true]);
    assert!(peer.log.iter().any(|l| l.1 == 0) && peer.log.iter().any(|l| l.1 == 1));
}

#[test]
fn signal_rate_limit_three_on_idle() {
    let (mut ep, h, syn, _, t, _) = idle_100ms();
    let srtt = srtt0(&ep, h);
    let s = SubflowId::INITIAL;
    for backup in [true, false] {
        ep.set_backup(t, h, s, backup).unwrap();
        assert_eq!(prios_on(&drain(&mut ep, t), &syn), vec![backup]);
    }
    ep.set_backup(t, h, s, true).unwrap();
    assert!(
        prios_on(&drain(&mut ep, t), &syn).is_empty(),
        "the third waits"
    );
    assert_eq!(ep.poll_timeout(), Some(t + srtt));
    let early = t + (srtt - Duration::from_nanos(1));
    ep.handle_timeout(early);
    assert!(drain(&mut ep, early).is_empty());
    ep.handle_timeout(t + srtt);
    assert_eq!(prios_on(&drain(&mut ep, t + srtt), &syn), vec![true]);
    assert_eq!(ep.poll_timeout(), None);
}

#[test]
fn signal_never_displaces_join_or_capable_or_datafin() {
    // PreConfirmed: every ACK carries the MP_CAPABLE keys; MP_PRIO waits for Confirmed.
    let mut ep = Endpoint::new(ChaCha20Rng::seed_from_u64(41));
    let h = open(&mut ep);
    let syn = leak(transmit(&mut ep, ms(0)));
    ep.set_backup(ms(0), h, SubflowId::INITIAL, true).unwrap();
    reply(&mut ep, &syn, &capable(1, CAP_H), syn.seq.wrapping_add(1));
    let out: Vec<_> = drain(&mut ep, ms(1)).into_iter().map(leak).collect();
    assert_eq!(out.len(), 1, "the third ACK");
    assert!(
        matches!(mptcp_opts(&out[0])[..], [MptcpOption::Capable(c)] if c.receiver_key.is_some())
    );
    let dss = data_ack(una(&ep, h));
    input_at(&mut ep, &peer_data(&syn, 5001, &dss, &[]), ms(2));
    assert_eq!(prios_on(&drain(&mut ep, ms(2)), &syn), vec![true]);

    // Joining: every ACK carries only the MP_JOIN third-ACK form; MP_PRIO follows the join.
    let (mut ep, h, _, _) = confirmed();
    let (id, jsyn) = join_syn(&mut ep, h, ms(10), JOIN_IP, 1500);
    ep.set_backup(ms(10), h, id, true).unwrap();
    let opts = synack_opts(&ep, h, &jsyn, 7, None);
    synack(&mut ep, &jsyn, &opts, ms(20));
    let acks = from(&drain(&mut ep, ms(20)), JOIN_IP);
    assert_eq!(acks.len(), 1);
    assert_third_ack(&ep, h, &jsyn, &acks[0]);
    let at = ep.poll_timeout().unwrap();
    ep.handle_timeout(at);
    let again = from(&drain(&mut ep, at), JOIN_IP);
    assert_eq!(again.len(), 1);
    assert_third_ack(&ep, h, &jsyn, &again[0]);
    let head = una(&ep, h);
    peer_ack(&mut ep, &jsyn, at, jsyn.seq.wrapping_add(1), head, 1000);
    assert_eq!(prios_on(&drain(&mut ep, at), &jsyn), vec![true]);

    // A standalone DATA_FIN (DSS 28) stays first and intact; signals take what is left.
    let (mut ep, h, syn, _) = confirmed();
    ep.set_backup(ms(10), h, SubflowId::INITIAL, true).unwrap();
    for id in 10..35 {
        signals(&mut ep, h).remove(id);
    }
    ep.connection(h).unwrap().close();
    let out = on(&drain(&mut ep, ms(10)), &syn);
    let fin = (out.iter()).find(|s| data_fin(s)).expect("DATA_FIN");
    let opts = mptcp_opts(fin);
    let [
        MptcpOption::Dss(d),
        MptcpOption::Prio { backup: true },
        MptcpOption::RemoveAddr { ids },
    ] = opts[..]
    else {
        panic!("{opts:?}")
    };
    assert!(d.data_fin && d.data_ack.is_some());
    assert_eq!(d.mapping.map(|m| m.data_len), Some(1));
    assert_eq!(ids.iter().collect::<Vec<_>>(), (10..16).collect::<Vec<_>>());
    assert!(fin.options.len() <= 40);
}

#[test]
fn signals_combine_after_dss() {
    let (mut ep, h, syn, dsn) = connected_with(1 << 20, Some(reno), true);
    open_window(&mut ep, &syn, h);
    // Three holes' worth of out-of-order data: three SACK blocks are pending.
    let data = |ep: &mut Endpoint<ChaCha20Rng>, off: u32| {
        let opts = mapping(1 + off, dsn + u64::from(off), 50);
        input_at(ep, &peer_data(&syn, 5001 + off, &opts, &[9; 50]), ms(10));
    };
    data(&mut ep, 100);
    data(&mut ep, 300);
    drain(&mut ep, ms(10));
    ep.set_backup(ms(10), h, SubflowId::INITIAL, true).unwrap();
    signals(&mut ep, h).remove(7);
    data(&mut ep, 500);
    let out = on(&drain(&mut ep, ms(10)), &syn);
    assert_eq!(out.len(), 1, "one ACK carries both signals");
    let opts: Vec<_> = walk(out[0].options).map(Result::unwrap).collect();
    // DSS12, MP_PRIO 3, REMOVE_ADDR 4, one NOP: 20 octets; two SACK blocks in the 20 left.
    let parsed = mptcp_opts(&out[0]);
    let [
        MptcpOption::Dss(d),
        MptcpOption::Prio { backup: true },
        MptcpOption::RemoveAddr { ids },
    ] = parsed[..]
    else {
        panic!("{parsed:?}")
    };
    assert!(d.data_ack.is_some() && ids.iter().eq([7]));
    let sack: Vec<_> = (opts.iter())
        .filter_map(|o| match o {
            TcpOpt::Sack(b) => Some(b.len()),
            _ => None,
        })
        .collect();
    assert_eq!(sack, vec![16], "two blocks fit");
    assert!(matches!(opts.last(), Some(TcpOpt::Sack(_))), "SACK last");
    // Without signals the next ACK carries three.
    data(&mut ep, 700);
    let out = on(&drain(&mut ep, ms(10)), &syn);
    let sack = walk(out[0].options).find_map(|o| match o {
        Ok(TcpOpt::Sack(b)) => Some(b.len()),
        _ => None,
    });
    assert_eq!(sack, Some(24));
}

#[test]
fn signal_not_fitting_is_deferred() {
    let (mut ep, h, syn, _) = confirmed();
    assert!(signals(&mut ep, h).echo(v6_echo()));
    ep.connection(h).unwrap().close();
    let out = on(&drain(&mut ep, ms(10)), &syn);
    assert_eq!(out.len(), 2, "{out:?}");
    // The DATA_FIN ACK (DSS 28) has no room for the 22-octet echo, which waits ...
    assert!(data_fin(&out[0]));
    assert_eq!(mptcp_opts(&out[0]).len(), 1);
    // ... and leaves intact, next to DSS12, on the next ACK.
    let e = v6_echo();
    let want = MptcpOption::AddAddr {
        echo: true,
        id: e.id,
        addr: e.addr,
        port: e.port,
        hmac: None,
    };
    let opts = mptcp_opts(&out[1]);
    assert!(
        matches!(opts[..], [MptcpOption::Dss(d), o] if !d.data_fin && o == want),
        "{opts:?}"
    );
    assert_eq!(out[1].options.len(), 36);
}

#[test]
fn signal_survives_unsent_option_build() {
    let (mut ep, h, syn, _, t, _) = idle_100ms();
    let s = SubflowId::INITIAL;
    ep.set_backup(t, h, s, true).unwrap();
    // Option builds whose segment never goes out: signal peeks of both purposes and the
    // speculative sizing call.
    {
        let c = ep.conns.get_mut(&h).unwrap();
        let sf = &mut c.subflows[0];
        let mut hk = SubflowHooks {
            conn: &mut c.hooks,
            sf: &mut sf.mp,
        };
        hk.prepare_send(&mut sf.tcb, t, s);
        let mut o = [0; 40];
        for purpose in [
            AckPurpose::Ordinary,
            AckPurpose::SignalOnly,
            AckPurpose::SignalOnly,
        ] {
            assert_eq!(hk.ack_signals(purpose, 28, &mut o), 4);
        }
        assert_eq!(hk.options_for(TcpFlags::ACK, &mut o), 12);
    }
    // The first emitted ACK carries it, once; nothing was charged, so a second signal-only ACK
    // still goes out at once.
    assert_eq!(prios_on(&drain(&mut ep, t), &syn), vec![true]);
    ep.set_backup(t, h, s, false).unwrap();
    assert_eq!(prios_on(&drain(&mut ep, t), &syn), vec![false]);
}

#[test]
fn signal_not_on_persist_probe() {
    let (mut ep, h, syn, _, t, una0) = idle_100ms();
    let head = una(&ep, h);
    peer_ack(&mut ep, &syn, t, una0, head, 0);
    ep.connection(h).unwrap().write(&[1; 5000]).unwrap();
    assert!(drain(&mut ep, t).is_empty());
    let p = ep.poll_timeout().expect("persist timer");
    ep.set_backup(p, h, SubflowId::INITIAL, true).unwrap();
    ep.handle_timeout(p);
    let out = on(&drain(&mut ep, p), &syn);
    assert_eq!(out.len(), 2, "{out:?}");
    // The probe, at SND.UNA − 1, carries no signal; the next ACK, at SND.MAX, carries it once.
    assert_eq!(
        (out[0].seq, out[0].payload.len()),
        (una0.wrapping_add(u32::MAX), 0)
    );
    assert!(prios(&out[0]).is_empty());
    assert_eq!((out[1].seq, prios(&out[1])), (una0, vec![true]));
    assert!(prios_on(&drain_until(&mut ep, p, p + Duration::from_secs(5)), &syn).is_empty());
}

#[test]
fn ordinary_ack_bypasses_signal_limit() {
    let (mut ep, h, syn, dsn, t, _) = idle_100ms();
    let s = SubflowId::INITIAL;
    for backup in [true, false] {
        ep.set_backup(t, h, s, backup).unwrap();
        assert_eq!(prios_on(&drain(&mut ep, t), &syn), vec![backup]);
    }
    ep.set_backup(t, h, s, true).unwrap();
    assert!(drain(&mut ep, t).is_empty(), "both signal-only slots used");
    // Two data segments before the srtt window ends: TCP ACKs them at once.
    let now = t + ms_d(10);
    for off in [0u32, 100] {
        let opts = mapping(1 + off, dsn + u64::from(off), 100);
        input_at(&mut ep, &peer_data(&syn, 5001 + off, &opts, &[9; 100]), now);
    }
    let out = on(&drain(&mut ep, now), &syn);
    assert_eq!(out.len(), 1);
    assert_eq!((out[0].ack, prios(&out[0])), (SeqNum(5201), vec![true]));
    // Uncharged: no wake for a signal, nothing more to send.
    assert!(
        prios_on(
            &drain_until(&mut ep, now, now + Duration::from_secs(1)),
            &syn
        )
        .is_empty()
    );
}

/// B with room for the whole 32-segment store.
fn cc_b_wide() -> Box<dyn CongestionControl> {
    Box::new(Counting {
        path: 0,
        cwnd: 64 << 10,
        rate: None,
    })
}

#[test]
fn opp_and_repair_skip_backup_while_primary_usable() {
    let cap = 32 * SEG;
    // B takes the whole store, so the connection is blocked with nothing left to assign.
    let (mut ep, h, mut peer, t, head, una_b) = hol(cc_b_wide, cc_a, cap, cap);
    ep.set_local_backup(h, SubflowId(1), true).unwrap();
    let data = pattern(cap);
    peer.drop[0] = true;
    b_holds_head(&mut ep, h, &mut peer, t, &data);
    // B is blackholed but Active with an open window: usable, so the backup A is no eligible
    // target. No candidate exists (no trigger), and A gets no copy and no head repair.
    let t2 = peer.run(&mut ep, h, t, t + Duration::from_millis(500));
    assert!(peer.log.iter().all(|l| l.1 == 0), "nothing on the backup");
    let s = stats(&mut ep, h);
    let s = (s.opp_triggers, s.opp_episodes, s.opp_repairs, s.opp_bytes);
    assert_eq!(s, (0, 0, 0, 0));
    // B's window closes: B is unusable and the backup is eligible.
    let syn = peer.syns[0].clone();
    peer_ack(&mut ep, &syn, t2, una_b, head, 0);
    peer.run(&mut ep, h, t2, t2 + Duration::from_secs(2));
    assert_eq!(peer.received(), data);
    assert!(moved_at(&peer, 0, 1).is_some(), "copied on the backup");
}
