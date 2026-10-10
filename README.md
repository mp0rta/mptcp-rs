# mptcp-rs

Portable, RFC 8684-compatible, Sans-I/O Multipath TCP implementation in Rust.

It implements the MPTCP protocol itself in userspace; it is not a helper for
creating kernel MPTCP sockets. The `mptcp-rs` crate (0.1.0) is the core library.
A Linux TUN adapter (`mptcp-rs-tun`, not published) provides the first network
integration, with Linux kernel TCP/MPTCP as the interoperability peer.

0.1.0 is client only, at milestone M3 (path management). The server role, MPTCP
checksums and MP_FAIL are still missing (see the roadmap); two limits on how fast
the connection reacts to a failing path are recorded below.

## Status

M0–M2 are merged: the plain TCP engine, MPTCP option codec, crypto helpers and
TUN adapter; single-subflow MPTCP v1 (DSS, DATA_ACK, connection recovery, shared
windows, DATA_FIN, TCP fallback); and MP_JOIN with a second subflow, the MinRTT
scheduler with reinjection, stale-subflow detection and a static per-subflow MTU.
M3 (branch `m3`, awaiting the maintainer's review) adds path management:
opportunistic retransmission and penalization (the head-of-line stall fix),
`add_subflow` / `close_subflow` / `remove_address` with subflow re-establishment
(make-before-break, rejoin after a link returns), backup subflows and MP_PRIO,
ADD_ADDR and REMOVE_ADDR receive with echo, MP_TCPRST, `Connection::abort`
(MP_FASTCLOSE send) and IPv6, including mixed-family paths.
The sender uses CUBIC with HyStart++, pacing and SACK-based loss recovery
(RFC 6675); the receiver sends SACK/DSACK.

Local validation (GitHub Actions reports CI separately), each with both fuzz
targets for 10 minutes:

- M0: 180 tests, clippy, formatting and the Rust 1.85 build; 64 MiB each way
  against Linux TCP, byte-exact, FIN/FIN close, no RST.
- M1: 256 tests; the six Linux scenarios below, including both option-stripping
  cases and zero-window recovery after a lost reopening update. The DATA_FIN
  checker rejects a deliberately shifted DSN.
- M2, final build b34d749: 421 tests; the six M1 scenarios and the per-path MTU
  case (path B at 1280 octets); two-path goodput medians of 354.9 Mbit/s
  client-to-server (gate 338.5) and 350.4 server-to-client (gate 340.1); all four
  1 GiB blackhole cases, with the failed subflow reported stale client-to-server.

- M3, final revision 05f11a4 (0.1.0): 576 tests; the Interop Suite (33 cases
  against Linux kernel MPTCP 7.0) passed 99 of 99 runs (3 of 3 per case, 0 SKIP);
  the head-of-line gap in `m2-blackhole-b` client-to-server is 0.423 s (gate 1.0 s)
  with the witness; all four 1 GiB blackhole cases pass; M0/M1 scenarios and
  `m2-mtu` pass; two-path goodput medians 354.7 Mbit/s client-to-server and
  350.3 Mbit/s server-to-client; both fuzz targets ran 10 minutes without a crash.

Known limitations (M3):

- **N3:** the head-of-line fix has a tail ceiling. If the application has no more data
  to send while a path blackholes, the healthy path still waits for the stale
  declaration (R1 = 3 RTOs, about 7 s in the interop profile) before the data is
  reinjected.
- **N4:** backup failover waits for the primary subflow to become unusable (stale or
  down) before a backup subflow carries data.

## Roadmap

| Milestone | Scope | Acceptance gate |
|---|---|---|
| **M0 — plain TCP foundation (merged)** | MPTCP option codec, crypto helpers, plain TCP engine and TUN adapter | Unit tests; each fuzz target runs 10 minutes locally and 60 seconds in CI without a crash or out-of-bounds access; 64 MiB each way against Linux TCP through TUN, byte-exact, followed by FIN/FIN close with no RST in the pcap. |
| **M1 — single-subflow MPTCP (merged)** | MP_CAPABLE, DSS, DATA_ACK, shared windows, DATA_FIN/close, control queue including connection-level data retransmission, handshake and post-handshake fallback using an infinite mapping, and MP_FASTCLOSE receive | 64 MiB each way against Linux MPTCP, byte-exact; both DATA_FINs acknowledged by DATA_ACK, subflow FIN/FIN close, no RST and server EOF; Wireshark decodes MPTCP v1. Stripping SYN options yields plain TCP with no MPTCP options after the SYN. Stripping data options yields `FellBack`, exactly one DSS with DLL=0, intact payload and clean close. |
| **M2 — two paths (merged)** | MP_JOIN, two subflows, MinRTT scheduler and reinjection | On asymmetric paths, test each direction separately for 30 seconds over three runs: median goodput at least 1.2× the better single path. During a 1 GiB transfer in each direction, blackhole either path for 15 seconds: transfer completes byte-exact without an application error. For client-to-server transfers, the client also reports the failed subflow as stale. |
| **M3 — path management (on `m3`, pending merge)** | Head-of-line stall fix, ADD_ADDR/REMOVE_ADDR, subflow re-establishment, MP_PRIO/backup, MP_TCPRST, MP_FASTCLOSE send, IPv6 and mixed-family paths, and the Interop Suite | Every Interop Suite case passes 3 of 3 runs against Linux kernel MPTCP on the reference kernel (host 7.0), 0 SKIP; every scripted contract test passes; in `m2-blackhole-b` client-to-server the longest DATA_ACK gap in the blackhole window is at most 1 s, with a pcap witness that path A carried path B's DSNs; the four 1 GiB blackhole cases pass byte-exact; M0/M1 scenarios and `m2-mtu` pass, m2-goodput medians stay at least 338.5 / 340.1 Mbit/s; both fuzz targets run 10 minutes. CI runs the whole suite on Ubuntu 26.04 (kernel 7.0), split over four jobs. |
| **M4 — remaining protocol features** | MPTCP checksums, MP_FAIL, 32-bit DSN transmission and server role | Library-to-library tests. |

TCP performance work continues alongside: RACK-TLP, timestamps and BBR (CUBIC,
pacing and SACK recovery are done). Reordering throughput and WAN testing remain
open.

Async runtime integration, `no_std`, mqvpn integration and coupled congestion
control are deferred.

## Running the client and Linux acceptance

`Endpoint::connect` preserves plain TCP; `Endpoint::connect_mptcp` explicitly
requests MPTCP v1 and falls back when negotiation or initial DSS confirmation fails.
Drive both with the same packet, timeout and application APIs. MPTCP normal closure
is reported after the TCP subflow closes, including its 120-second TIME_WAIT.

The TUN client requires `--mode tcp|mptcp`:

```sh
cargo build --release -p mptcp-rs-tun
sudo target/release/mptcp-rs-tun --mode mptcp --tun mtun0 \
  --local 10.0.9.2 --remote 10.0.1.2:5201 --send 67108864 --expect 67108864
```

The acceptance harness creates isolated Docker network namespaces, runs the Linux
TCP/MPTCP peer, and checks byte-exact 64 MiB transfers in both directions, EOF,
FIN/FIN and no RST. It also checks DATA_FIN/DATA_ACK coverage and fallback options:

```sh
for scenario in m0 m1 syn-strip dataack-strip zero-server zero-client m2-mtu; do
  tests/interop/run.sh "$scenario"
done
```

The Interop Suite (`tests/interop/suite/`) runs scripted path-management cases against
Linux kernel MPTCP over IPv4, IPv6 and mixed-family paths and judges each from the
pcaps and the client's events. `bash tests/interop/suite/run.sh --runs 3` runs every
case (about 20 minutes per pass); add `--ci` for a fast subset, `--shard K/N` for one of
N balanced parts (CI runs four), or `--case NAME` for one case. The client driver is `mptcp-rs-tun --script FILE`.

Docker and a Linux kernel with MPTCP, TUN and the iptables TCPOPTSTRIP/u32/CONNMARK
modules are required. The image is built from `tests/interop/Dockerfile`.
Each attempt prints its unique directory under `artifacts/interop/`, containing
pcaps, application logs, rule counters and the checker result. The zero-window
cases pause application reads for eight seconds with small receive buffers while
packet processing continues, drop the first reopening update, and require a
subsequent probe and DATA_ACK/window response before bulk traffic resumes.

To repeat the negative DATA_FIN checker test on a successful normal MPTCP capture:
`python3 tests/interop/check_fin_mutation.py artifacts/interop/m1/RUN_DIRECTORY`.
