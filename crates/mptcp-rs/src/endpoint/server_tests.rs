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
