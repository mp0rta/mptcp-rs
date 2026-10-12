use super::*;
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
