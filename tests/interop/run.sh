#!/usr/bin/env bash
# M0 interop: mptcp-rs-tun (userland TCP over TUN) <-> Linux plain TCP, 64 MiB each way.
# Usage: cargo build --release -p mptcp-rs-tun && tests/interop/run.sh m0
# Needs docker (runs a --privileged ubuntu:24.04 container; the host-built binary must be
# glibc-compatible with it; on another host, build inside the container). Writes m0.pcap in the repo root.
set -euo pipefail

N=67108864

if [ "${1:-}" = "--inner" ]; then
  apt-get update -qq >/dev/null
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq iproute2 python3 tcpdump >/dev/null
  ip netns add cli; ip netns add srv
  ip link add a0 netns cli type veth peer name a1 netns srv
  ip -n cli addr add 10.0.1.1/24 dev a0; ip -n srv addr add 10.0.1.2/24 dev a1
  for ns in cli srv; do
    ip -n $ns link set lo up
    ip netns exec $ns sysctl -qw net.ipv4.conf.all.rp_filter=0
  done
  ip -n cli link set a0 up; ip -n srv link set a1 up
  ip netns exec cli sysctl -qw net.ipv4.ip_forward=1
  ip -n srv route add 10.0.9.0/24 via 10.0.1.1

  rm -f m0.pcap srv.log cli.log
  ip netns exec srv tcpdump -i a1 -U -s 128 -w m0.pcap >/dev/null 2>&1 &
  tdpid=$!
  ip netns exec srv timeout 130 python3 tests/interop/server.py --mode tcp --port 5201 --bytes $N \
    >srv.log 2>&1 &
  srvpid=$!
  for _ in $(seq 50); do grep -qs listening srv.log && break; sleep 0.1; done
  sleep 1  # tcpdump is up

  start=$(date +%s.%N)
  ip netns exec cli timeout 120 target/release/mptcp-rs-tun --tun mtun0 --local 10.0.9.2 \
    --remote 10.0.1.2:5201 --send $N --expect $N >cli.log 2>&1 &
  clipid=$!
  for _ in $(seq 50); do ip -n cli link show mtun0 >/dev/null 2>&1 && break; sleep 0.1; done
  if ! ip -n cli link show mtun0 >/dev/null 2>&1; then
    echo "M0 FAIL: mtun0 not created"; cat cli.log; exit 1
  fi
  ip -n cli addr add 10.0.9.1/24 dev mtun0
  ip -n cli link set mtun0 up

  cli_rc=0; wait $clipid || cli_rc=$?
  srv_rc=0; wait $srvpid || srv_rc=$?
  end=$(date +%s.%N)
  sleep 1; kill $tdpid; wait $tdpid 2>/dev/null || true

  rst=$(tcpdump -r m0.pcap 'tcp[tcpflags] & tcp-rst != 0' 2>/dev/null | wc -l)
  fin_c2s=$(tcpdump -r m0.pcap 'src 10.0.9.2 and tcp[tcpflags] & tcp-fin != 0' 2>/dev/null | wc -l)
  fin_s2c=$(tcpdump -r m0.pcap 'src 10.0.1.2 and tcp[tcpflags] & tcp-fin != 0' 2>/dev/null | wc -l)
  echo "--- client:"; tail -3 cli.log; echo "--- server:"; tail -3 srv.log
  python3 -c "print('duration=%.1fs' % ($end - $start))"
  if [ $cli_rc -eq 0 ] && [ $srv_rc -eq 0 ] && [ "$rst" -eq 0 ] && [ "$fin_c2s" -ge 1 ] && [ "$fin_s2c" -ge 1 ]; then
    echo "M0 PASS bytes=$N rst=$rst fin_c2s=$fin_c2s fin_s2c=$fin_s2c"
  else
    echo "M0 FAIL cli_rc=$cli_rc srv_rc=$srv_rc rst=$rst fin_c2s=$fin_c2s fin_s2c=$fin_s2c (m0.pcap kept)"
    exit 1
  fi
  exit 0
fi

[ "${1:-}" = "m0" ] || { echo "usage: $0 m0" >&2; exit 2; }
cd "$(dirname "$0")/../.."
docker run --rm --init --privileged -v "$PWD":/w -w /w ubuntu:24.04 bash tests/interop/run.sh --inner
