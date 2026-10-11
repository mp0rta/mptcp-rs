# mptcp-rs

A userspace, sans-I/O library for the client side of Multipath TCP v1 (RFC 8684), in Rust.

mptcp-rs implements MPTCP itself, on its own TCP engine; it does not use the MPTCP in the
Linux kernel. You give it incoming packets and the current time. It gives you back packets to
send and data to read. So it can run over any packet I/O, such as a TUN device or a userspace
network stack.

Status: 0.1.0, client only.

## Features

- TCP: CUBIC with HyStart++, pacing, and SACK loss recovery (RFC 6675).
- MPTCP v1: MP_CAPABLE, DSS, DATA_ACK, DATA_FIN, MP_TCPRST, and MP_FASTCLOSE in both
  directions. Falls back to plain TCP when MPTCP cannot be used.
- Multiple paths: MP_JOIN, a MinRTT scheduler with reinjection, and opportunistic
  retransmission so that one stalled path does not block the others.
- Path management: the application can add, close and remove subflows (for example, to rejoin
  when a link returns). Backup subflows, MP_PRIO, and ADD_ADDR and REMOVE_ADDR from the server.
- IPv4, IPv6 and mixed-family paths.

Not yet supported (planned): the server role, MPTCP checksums, MP_FAIL, and sending 32-bit
DSNs. The client does not ask for checksums, and falls back to plain TCP if the server requires
them.

## Interoperability

Tested against Linux kernel MPTCP (kernel 7.0) as the server, over IPv4, IPv6 and mixed-family
paths:

- The Interop Suite: 33 scripted cases covering joins (including refused and failed ones),
  backup subflows and MP_PRIO, failover, ADD_ADDR and REMOVE_ADDR, subflow re-establishment,
  MP_TCPRST and MP_FASTCLOSE. Every case passes; CI runs the suite on every push.
- Transfers: 64 MiB each way, byte-exact; fallback when middleboxes strip MPTCP options;
  zero-window recovery; a different MTU per path; and 1 GiB transfers that complete while one
  of two paths is blackholed for 15 seconds.
- Two paths with different speeds give at least 1.2× the goodput of the better single path.

It has not been tested against other MPTCP implementations yet.

## Known limits

- If the application has no more data to send and a path fails, the data stuck on that path is
  resent on another path only after the path is marked stale (about 7 seconds in our tests).
- A backup subflow carries data only after the primary subflow stops working.
- After a normal close, `Closed` is reported only after every subflow leaves TIME-WAIT. This can
  take up to 120 seconds.

## Usage

`Endpoint::connect_mptcp` starts an MPTCP connection and falls back to TCP if the server does
not support MPTCP. `Endpoint::connect` starts a plain TCP connection. Both use the same APIs for
packets, timers and the application. See the [API documentation](https://docs.rs/mptcp-rs) for
an example.

The repository also has a Linux TUN client, `mptcp-rs-tun` (not on crates.io):

```sh
cargo build --release -p mptcp-rs-tun
sudo target/release/mptcp-rs-tun --mode mptcp --tun mtun0 \
  --local 10.0.9.2 --remote 10.0.1.2:5201 --send 67108864 --expect 67108864
```

Rust 1.85 or later is required.

## Congestion control

Two congestion controllers are available, chosen per connection with
`ConnectConfig::congestion_control`:

- `CongestionControlKind::Cubic` (the default): CUBIC with HyStart++ and pacing.
- `CongestionControlKind::BbrV3`: BBRv3 (draft-ietf-ccwg-bbr-06, experimental).

```rust
let mut cfg = ConnectConfig::default();
cfg.congestion_control = CongestionControlKind::BbrV3;
```

`mptcp-rs-tun` takes `--cc cubic|bbr3`. Every subflow of a connection runs the same
controller, and the subflows are not coupled: two subflows that share one bottleneck take about
the share of two TCP flows, with either controller.

## Testing

Run `cargo test --workspace` for the unit and integration tests.

The interop tests run the TUN client against Linux kernel MPTCP inside Docker. They need a
Linux kernel with MPTCP, TUN, and the iptables TCPOPTSTRIP, u32 and CONNMARK modules. Build the
release client first (`cargo build --release -p mptcp-rs-tun`).

```sh
tests/interop/run.sh m1                     # one transfer scenario
bash tests/interop/suite/run.sh --runs 3    # the Interop Suite: 33 cases, about 20 min per run
bash tests/interop/suite/run.sh --case NAME # one case
```

Each run saves pcaps and logs under `artifacts/interop/`.

## Roadmap

Next: the server role, checksums and MP_FAIL. TCP work continues alongside: RACK-TLP,
timestamps and BBR. Async runtime integration, `no_std` and coupled congestion control are not
planned yet.

## License

Licensed under either of MIT or Apache-2.0, at your option.
