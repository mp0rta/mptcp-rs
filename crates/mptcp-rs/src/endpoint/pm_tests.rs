//! M3 API groundwork (M3 spec §4): subflow and address ids, the C=1 rule, the last initial
//! subflow's `SubflowDown` and argument checks of the path-management calls. A child of
//! `join_tests`, whose helpers it reuses.
use super::*;
use crate::endpoint::{AddressError, SubflowError};
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
