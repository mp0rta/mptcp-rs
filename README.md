# mptcp-rs

A userspace Multipath TCP v1 (RFC 8684) implementation in Rust. The core library
is sans-I/O; a Linux TUN adapter provides the first network integration. The
initial role is client only, with Linux kernel TCP/MPTCP as the interoperability
peer.

## Status

M0 is merged. The plain TCP engine, MPTCP option codec, crypto helpers and TUN
adapter are implemented. Receiver SACK/DSACK is also implemented; the sender
still uses Reno/NewReno. MPTCP connections and multiple subflows are planned.

The final M0 code passed 180 tests, both fuzz targets for 10 minutes each, and
64 MiB transfers in each direction against Linux TCP with byte-exact delivery,
FIN/FIN close and no RST. Clippy, formatting and the Rust 1.85 build also passed.
These are local results; GitHub Actions reports CI results separately.

## Roadmap

| Milestone | Scope | Acceptance gate |
|---|---|---|
| **M0 — plain TCP foundation (merged)** | MPTCP option codec, crypto helpers, plain TCP engine and TUN adapter | Unit tests; each fuzz target runs 10 minutes locally and 60 seconds in CI without a crash or out-of-bounds access; 64 MiB each way against Linux TCP through TUN, byte-exact, followed by FIN/FIN close with no RST in the pcap. |
| **M1 — single-subflow MPTCP (next)** | MP_CAPABLE, DSS, DATA_ACK, shared windows, DATA_FIN/close, control queue including connection-level data retransmission, handshake and post-handshake fallback using an infinite mapping, and MP_FASTCLOSE receive | 64 MiB each way against Linux MPTCP, byte-exact; both DATA_FINs acknowledged by DATA_ACK, subflow FIN/FIN close, no RST and server EOF; Wireshark decodes MPTCP v1. Stripping SYN options yields plain TCP with no MPTCP options after the SYN. Stripping data options yields `FellBack`, exactly one DSS with DLL=0, intact payload and clean close. |
| **M2 — two paths** | MP_JOIN, two subflows, MinRTT scheduler and reinjection | On asymmetric paths, test each direction separately for 30 seconds over three runs: median goodput at least 1.2× the better single path. During a 256 MiB transfer in each direction, blackhole either path for 15 seconds: transfer completes byte-exact without an application error. For client-to-server transfers, the client also reports the failed subflow as stale. |
| **M3 — path management** | ADD_ADDR/REMOVE_ADDR, MP_PRIO/backup, MP_TCPRST, MP_FASTCLOSE send and MPTCP checksums | Per-feature interoperability tests. |
| **M4 — remaining protocol features** | MP_FAIL, 32-bit DSN transmission and server role | Library-to-library tests. |

TCP performance work proceeds in parallel after M1: CUBIC, sender SACK recovery,
RACK-TLP, timestamps, pacing and BBR. Receiver SACK/DSACK was brought forward
into M0; reordering throughput remains a known issue, and the final version
still needs WAN retesting. M0 has no throughput threshold.

Async runtime integration, `no_std`, mqvpn integration and coupled congestion
control are deferred.
