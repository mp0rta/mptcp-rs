#!/usr/bin/env bash
# Reproducible isolated Linux TCP/MPTCP acceptance. Build the release client first.
set -euo pipefail
N=67108864
if [ "${1:-}" != --inner ]; then
  cd "$(dirname "$0")/../.."
  case "${1:-}:${2:-}" in
    m0:|m1:|syn-strip:|dataack-strip:|zero-server:|zero-client:|base-a:c2s|base-a:s2c|base-b:c2s|base-b:s2c|base-unshaped:c2s|base-unshaped:s2c) ;;
    *) echo "usage: $0 m0|m1|syn-strip|dataack-strip|zero-server|zero-client | $0 base-a|base-b|base-unshaped c2s|s2c" >&2; exit 2;;
  esac
  docker build -t mptcp-rs-m1-test:local tests/interop
  exec docker run --rm --init --network none --privileged -v "$PWD":/w -w /w mptcp-rs-m1-test:local bash tests/interop/run.sh --inner "$1" "${2:-}"
fi
scenario=$2; dir=${3:-}
mkdir -p "artifacts/interop/$scenario${dir:+-$dir}"
out=$(mktemp -d "artifacts/interop/$scenario${dir:+-$dir}/$(date -u +%Y%m%dT%H%M%S)-XXXXXX")
echo "artifacts: $out"
chmod 755 "$out"
sha256sum target/release/mptcp-rs-tun tests/interop/{run.sh,server.py,check.py} >"$out/inputs.sha256"
uname -a >"$out/kernel.txt"
mode=mptcp; [ "$scenario" != m0 ] || mode=tcp
ip netns add cli; ip netns add srv
# Two legs: A = a0<->a1 (10.0.1.0/24), B = b0<->b1 (10.0.2.0/24).
ip link add a0 netns cli type veth peer name a1 netns srv
ip link add b0 netns cli type veth peer name b1 netns srv
ip -n cli addr add 10.0.1.1/24 dev a0; ip -n srv addr add 10.0.1.2/24 dev a1
ip -n cli addr add 10.0.2.1/24 dev b0; ip -n srv addr add 10.0.2.2/24 dev b1
for ns in cli srv; do
  ip -n "$ns" link set lo up
  ip netns exec "$ns" sysctl -qw net.ipv4.conf.all.rp_filter=0
  ip netns exec "$ns" sysctl -qw net.mptcp.enabled=1
done
for l in a0 b0; do ip -n cli link set $l up; done; for l in a1 b1; do ip -n srv link set $l up; done
ip netns exec cli sysctl -qw net.ipv4.ip_forward=1
ip -n srv route add 10.0.9.0/24 via 10.0.1.1
ip -n srv route add 10.0.8.0/24 via 10.0.2.1
ip netns exec srv ip mptcp limits set subflows 2 add_addr_accepted 0
# Source routing for the client addresses on mtun0: 10.0.9.2 -> A, 10.0.8.2 -> B.
ip -n cli rule add from 10.0.9.2 table 100; ip -n cli route add 10.0.1.0/24 dev a0 table 100
ip -n cli rule add from 10.0.8.2 table 200; ip -n cli route add 10.0.1.2 via 10.0.2.2 dev b0 table 200
# mqvpn asym netem on both egress directions of a leg; limit = 2*BDP in 1500 B packets:
# A 300 Mbit x 20 ms RTT = 750000 B = 500 pkts -> 1000; B 80 Mbit x 60 ms = 600000 B = 400 pkts -> 800.
case "$scenario" in base-a|base-b)
  for x in "cli a0 10 300 1000" "srv a1 10 300 1000" "cli b0 30 80 800" "srv b1 30 80 800"; do
    set -- $x; ip netns exec "$1" tc qdisc add dev "$2" root netem delay "$3"ms rate "$4"mbit limit "$5"
  done;;
esac
cip=10.0.9.2; sif=a1; cif=a0
[ "$scenario" != base-b ] || { cip=10.0.8.2; sif=b1; cif=b0; }
if [ "$scenario" = syn-strip ]; then
  ip netns exec cli iptables -t mangle -A FORWARD -s 10.0.9.2 -p tcp --syn -j TCPOPTSTRIP --strip-options 30
elif [ "$scenario" = dataack-strip ]; then
  ip netns exec srv iptables -t mangle -A OUTPUT -s 10.0.1.2 -p tcp --sport 5201 --tcp-flags SYN NONE -j TCPOPTSTRIP --strip-options 30
fi
server_pause=0; client_pause=0
if [[ "$scenario" = zero-* ]]; then
  source=10.0.1.2
  if [ "$scenario" = zero-server ]; then server_pause=8000; else source=10.0.9.2; client_pause=8000; fi
  ip netns exec cli iptables -t mangle -N WINDOW
  ip netns exec cli iptables -t mangle -A FORWARD -s "$source" -p tcp --tcp-flags SYN,ACK ACK -j WINDOW
  ip netns exec cli iptables -t mangle -A WINDOW -m u32 --u32 '0>>22&0x3C@12&0xFFFF=0' -m connmark --mark 0 -j CONNMARK --set-mark 1
  ip netns exec cli iptables -t mangle -A WINDOW -m u32 --u32 '0>>22&0x3C@12&0xFFFF=0' -j RETURN
  ip netns exec cli iptables -t mangle -N REOPEN
  ip netns exec cli iptables -t mangle -A WINDOW -m connmark --mark 1 -j REOPEN
  ip netns exec cli iptables -t mangle -A REOPEN -j CONNMARK --set-mark 2
  ip netns exec cli iptables -t mangle -A REOPEN -j DROP
fi
ip netns exec srv tcpdump -Z root -i "$sif" -U -s 160 -w "$out/server.pcap" >"$out/capture.log" 2>&1 &
tdpid=$!
ip netns exec cli tcpdump -Z root -i "$cif" -U -s 160 -w "$out/client.pcap" >"$out/client-capture.log" 2>&1 &
tdcli=$!
tdtun=
trap 'kill "$tdpid" "$tdcli" ${tdtun:-} 2>/dev/null || true' EXIT
# Fixed cases: N bytes each way. Timed cases: 30 s in $dir, the other direction idle.
sargs=(--bytes "$N"); cargs=(--send "$N" --expect "$N")
if [ "$dir" = c2s ]; then sargs=(--expect any --send-bytes 0); cargs=(--send-secs 30 --expect 0)
elif [ "$dir" = s2c ]; then sargs=(--expect 0 --send-secs 30); cargs=(--send 0 --expect any); fi
want_c2s=$N; want_s2c=$N
[ "$dir" != c2s ] || { want_c2s=any; want_s2c=0; }
[ "$dir" != s2c ] || { want_c2s=0; want_s2c=any; }
ip netns exec srv timeout 910 python3 tests/interop/server.py --mode "$mode" --port 5201 "${sargs[@]}" --pause-read-ms "$server_pause" >"$out/server.log" 2>&1 &
srvpid=$!
for _ in $(seq 50); do grep -qs listening "$out/server.log" && break; sleep 0.1; done
sleep 1
ip netns exec cli timeout 910 target/release/mptcp-rs-tun --mode "$mode" --tun mtun0 --local "$cip" --remote 10.0.1.2:5201 "${cargs[@]}" --pause-read-ms "$client_pause" >"$out/client.log" 2>&1 &
clipid=$!
for _ in $(seq 50); do ip -n cli link show mtun0 >/dev/null 2>&1 && break; sleep 0.1; done
ip -n cli link set mtun0 up
ip netns exec cli tcpdump -Z root -i mtun0 -U -s 160 -w "$out/tun.pcap" >"$out/tun-capture.log" 2>&1 &
tdtun=$!
sleep 1
ip -n cli addr add 10.0.9.1/24 dev mtun0; ip -n cli addr add 10.0.8.1/24 dev mtun0
cli_rc=0; wait "$clipid" || cli_rc=$?
srv_rc=0; wait "$srvpid" || srv_rc=$?
sleep 1
kill "$tdpid" "$tdcli" "$tdtun" 2>/dev/null || true
wait "$tdpid" "$tdcli" "$tdtun" 2>/dev/null || true
trap - EXIT
ip netns exec cli iptables-save -c >"$out/client-rules.txt"
ip netns exec srv iptables-save -c >"$out/server-rules.txt"
cat "$out/client.log" "$out/server.log"
[ "$cli_rc" = 0 ] && [ "$srv_rc" = 0 ] || { echo "FAIL client=$cli_rc server=$srv_rc"; exit 1; }
python3 tests/interop/check.py "$scenario" "$out" "$want_c2s" "$want_s2c" | tee "$out/result.log"
