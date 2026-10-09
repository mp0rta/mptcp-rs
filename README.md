# mptcp-rs

Portable, RFC 8684-compatible, Sans-I/O Multipath TCP implementation in Rust.

It implements the MPTCP protocol itself in userspace; it is not a helper for
creating kernel MPTCP sockets. The `mptcp-rs` crate (0.0.1) is the core library.
A Linux TUN adapter (`mptcp-rs-tun`, not published) provides the first network
integration, with Linux kernel TCP/MPTCP as the interoperability peer.

0.0.1 is client only, at milestone M2 (two paths). Path management, the server
role and several options are still missing (see the roadmap), and a blackholed
path can stall the connection for several seconds (see the known limitation).

## Status

M0–M2 are merged: the plain TCP engine, MPTCP option codec, crypto helpers and
TUN adapter; single-subflow MPTCP v1 (DSS, DATA_ACK, connection recovery, shared
windows, DATA_FIN, TCP fallback); and MP_JOIN with a second subflow, the MinRTT
scheduler with reinjection, stale-subflow detection and a static per-subflow MTU.
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

Known limitation (M2): if a path blackholes with data outstanding on it, the
healthy path stalls until that subflow is declared stale (R1 = 3 RTOs, about 7 s
in the interop profile) and its data is reinjected. Opportunistic retransmission
on the healthy path is planned.

## Roadmap

| Milestone | Scope | Acceptance gate |
|---|---|---|
| **M0 — plain TCP foundation (merged)** | MPTCP option codec, crypto helpers, plain TCP engine and TUN adapter | Unit tests; each fuzz target runs 10 minutes locally and 60 seconds in CI without a crash or out-of-bounds access; 64 MiB each way against Linux TCP through TUN, byte-exact, followed by FIN/FIN close with no RST in the pcap. |
| **M1 — single-subflow MPTCP (merged)** | MP_CAPABLE, DSS, DATA_ACK, shared windows, DATA_FIN/close, control queue including connection-level data retransmission, handshake and post-handshake fallback using an infinite mapping, and MP_FASTCLOSE receive | 64 MiB each way against Linux MPTCP, byte-exact; both DATA_FINs acknowledged by DATA_ACK, subflow FIN/FIN close, no RST and server EOF; Wireshark decodes MPTCP v1. Stripping SYN options yields plain TCP with no MPTCP options after the SYN. Stripping data options yields `FellBack`, exactly one DSS with DLL=0, intact payload and clean close. |
| **M2 — two paths (merged)** | MP_JOIN, two subflows, MinRTT scheduler and reinjection | On asymmetric paths, test each direction separately for 30 seconds over three runs: median goodput at least 1.2× the better single path. During a 1 GiB transfer in each direction, blackhole either path for 15 seconds: transfer completes byte-exact without an application error. For client-to-server transfers, the client also reports the failed subflow as stale. |
| **M3 — path management** | ADD_ADDR/REMOVE_ADDR, MP_PRIO/backup, MP_TCPRST, MP_FASTCLOSE send and MPTCP checksums | Per-feature interoperability tests. |
| **M4 — remaining protocol features** | MP_FAIL, 32-bit DSN transmission and server role | Library-to-library tests. |

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
for scenario in m0 m1 syn-strip dataack-strip zero-server zero-client; do
  tests/interop/run.sh "$scenario"
done
```

Docker and a Linux kernel with MPTCP, TUN and the iptables TCPOPTSTRIP/u32/CONNMARK
modules are required. The image is built from `tests/interop/Dockerfile`.
Each attempt prints its unique directory under `artifacts/interop/`, containing
pcaps, application logs, rule counters and the checker result. The zero-window
cases pause application reads for eight seconds with small receive buffers while
packet processing continues, drop the first reopening update, and require a
subsequent probe and DATA_ACK/window response before bulk traffic resumes.

To repeat the negative DATA_FIN checker test on a successful normal MPTCP capture:
`python3 tests/interop/check_fin_mutation.py artifacts/interop/m1/RUN_DIRECTORY`.
