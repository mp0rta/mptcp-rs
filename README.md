# mptcp-rs

A userspace Multipath TCP v1 (RFC 8684) implementation in Rust. The core library
is sans-I/O; a Linux TUN adapter provides the first network integration. The
initial role is client only, with Linux kernel TCP/MPTCP as the interoperability
peer.

## Status

M0 is merged. The plain TCP engine, MPTCP option codec, crypto helpers and TUN
adapter are implemented. Single-subflow MPTCP v1 is implemented, including DSS,
DATA_ACK, connection recovery, shared windows, DATA_FIN and TCP fallback. M2 adds
MP_JOIN, a second subflow, the MinRTT scheduler with reinjection, stale-subflow
detection and a static per-subflow MTU. The sender now uses pacing, CUBIC with
HyStart++ and SACK-based loss recovery (RFC 6675); receiver SACK/DSACK is also
implemented.

The final M0 code passed 180 tests, both fuzz targets for 10 minutes each, and
64 MiB transfers in each direction against Linux TCP with byte-exact delivery,
FIN/FIN close and no RST. Clippy, formatting and the Rust 1.85 build also passed.
These are local results; GitHub Actions reports CI results separately.

M1 local validation passed 256 tests and both fuzz targets for 10 minutes each.
All six Linux scenarios below passed: plain TCP, normal MPTCP, both option
stripping cases, and both directions of zero-window recovery after losing a
reopening update. The DATA_FIN checker also rejects a deliberately shifted DSN.

M2 local validation is partial. Passed: 404 tests, both fuzz targets for 10
minutes each, the six M1 scenarios, the per-path MTU case (path B at 1280
octets), single-path goodput within 5 % of the reference, and client-to-server
two-path goodput (median 338.8 Mbit/s, gate 338.5). Not yet passed:
server-to-client goodput, which met the gate over three runs (341.0, gate 340.2)
but not over six (332.0), and the client-to-server blackhole cases. Those
transfers are byte-exact without an application error, but they fail the
harness's close checks. The blackhole server-to-client cases passed. Details are
in the local note `docs/superpowers/notes/2026-10-09-m2-verification.md`.

## Roadmap

| Milestone | Scope | Acceptance gate |
|---|---|---|
| **M0 — plain TCP foundation (merged)** | MPTCP option codec, crypto helpers, plain TCP engine and TUN adapter | Unit tests; each fuzz target runs 10 minutes locally and 60 seconds in CI without a crash or out-of-bounds access; 64 MiB each way against Linux TCP through TUN, byte-exact, followed by FIN/FIN close with no RST in the pcap. |
| **M1 — single-subflow MPTCP** | MP_CAPABLE, DSS, DATA_ACK, shared windows, DATA_FIN/close, control queue including connection-level data retransmission, handshake and post-handshake fallback using an infinite mapping, and MP_FASTCLOSE receive | 64 MiB each way against Linux MPTCP, byte-exact; both DATA_FINs acknowledged by DATA_ACK, subflow FIN/FIN close, no RST and server EOF; Wireshark decodes MPTCP v1. Stripping SYN options yields plain TCP with no MPTCP options after the SYN. Stripping data options yields `FellBack`, exactly one DSS with DLL=0, intact payload and clean close. |
| **M2 — two paths (implemented; acceptance partial)** | MP_JOIN, two subflows, MinRTT scheduler and reinjection | On asymmetric paths, test each direction separately for 30 seconds over three runs: median goodput at least 1.2× the better single path. During a 256 MiB transfer in each direction, blackhole either path for 15 seconds: transfer completes byte-exact without an application error. For client-to-server transfers, the client also reports the failed subflow as stale. |
| **M3 — path management** | ADD_ADDR/REMOVE_ADDR, MP_PRIO/backup, MP_TCPRST, MP_FASTCLOSE send and MPTCP checksums | Per-feature interoperability tests. |
| **M4 — remaining protocol features** | MP_FAIL, 32-bit DSN transmission and server role | Library-to-library tests. |

TCP performance work proceeds in parallel after M1: CUBIC, sender SACK recovery,
RACK-TLP, timestamps, pacing and BBR. Receiver SACK/DSACK was brought forward
into M0; reordering throughput remains a known issue, and the final version
still needs WAN retesting. M0 has no throughput threshold.

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

The client deadline is 900 seconds (harness: 910). Post-handshake fallback currently
waits for the 500 ms sender SWS override at short storage-chunk boundaries, making
that scenario much slower than ordinary MPTCP; M1 has no throughput gate.

To repeat the negative DATA_FIN checker test on a successful normal MPTCP capture:
`python3 tests/interop/check_fin_mutation.py artifacts/interop/m1/RUN_DIRECTORY`.
