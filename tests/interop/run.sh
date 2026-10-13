#!/usr/bin/env bash
# Reproducible isolated Linux TCP/MPTCP acceptance. Build the release client first.
set -euo pipefail
N=67108864
if [ "${1:-}" != --inner ]; then
  cd "$(dirname "$0")/../.."
  case "${1:-}:${2:-}" in
    m0:|m1:|syn-strip:|dataack-strip:|zero-server:|zero-client:|m2-mtu:) ;;
    base-a:c2s|base-a:s2c|base-b:c2s|base-b:s2c|base-unshaped:c2s|base-unshaped:s2c) ;;
    m2-goodput:c2s|m2-goodput:s2c|m2-blackhole-a:c2s|m2-blackhole-a:s2c|m2-blackhole-b:c2s|m2-blackhole-b:s2c|m2-lossy:c2s|m2-lossy:s2c) ;;
    m2-unshaped:c2s|m2-unshaped:s2c|m2-remove:c2s|m2-remove:s2c) ;;
    csum-fail1:c2s|csum-fail1:s2c|csum-fail2:c2s|csum-fail2:s2c) ;;
    *) echo "usage: $0 m0|m1|syn-strip|dataack-strip|zero-server|zero-client|m2-mtu | $0 base-a|base-b|base-unshaped|m2-goodput|m2-lossy|m2-unshaped|m2-remove|m2-blackhole-a|m2-blackhole-b|csum-fail1|csum-fail2 c2s|s2c" >&2; exit 2;;
  esac
  docker build -t mptcp-rs-m1-test:local tests/interop
  exec docker run --rm --init --network none --privileged -e MPTCP_RS_CC -e INTEROP_CLIENT -e INTEROP_SERVER -e INTEROP_BENCH -e INTEROP_CSUM -v "$PWD":/w -w /w mptcp-rs-m1-test:local bash tests/interop/run.sh --inner "$1" "${2:-}"
fi
scenario=$2; dir=${3:-}; cc=${MPTCP_RS_CC:-cubic}
# Kernel comparison bench (see test_bench.py): INTEROP_CLIENT=kernel runs the Linux MPTCP client
# (kclient.py) instead of mptcp-rs-tun; INTEROP_BENCH=1 gives both clients the same conditions.
client=${INTEROP_CLIENT:-mptcp-rs}; bench=${INTEROP_BENCH:-}
case "$client:$scenario" in
  mptcp-rs:m2-remove) echo "INTEROP_CLIENT=$client: unsupported for $scenario" >&2; exit 2;;
  mptcp-rs:*|kernel:base-a|kernel:base-b|kernel:m2-goodput|kernel:m2-lossy|kernel:m2-unshaped|kernel:m2-remove|kernel:csum-fail1|kernel:csum-fail2) ;;
  *) echo "INTEROP_CLIENT=$client: unsupported for $scenario" >&2; exit 2;;
esac
# INTEROP_SERVER=mptcp-rs: mptcp-rs-tun --listen on a TUN in srv as 10.0.7.2, instead of server.py.
server=${INTEROP_SERVER:-kernel}
case "$server:$scenario" in
  kernel:*|mptcp-rs:base-a|mptcp-rs:m1|mptcp-rs:m2-goodput|mptcp-rs:m2-lossy|mptcp-rs:m2-remove|mptcp-rs:csum-fail1|mptcp-rs:csum-fail2) ;;
  *) echo "INTEROP_SERVER=$server: unsupported for $scenario" >&2; exit 2;;
esac
# csum-fail*: one end mptcp-rs, the other Linux, whose counters run.sh checks.
[[ "$scenario" != csum-fail* ]] || [ "$client" != "$server" ] || { echo "$scenario needs one Linux end and one mptcp-rs end" >&2; exit 2; }
# INTEROP_CSUM=<ours>:<linux>: mptcp-rs-tun's --checksums and Linux's net.mptcp.checksum_enabled.
csum=${INTEROP_CSUM:-on:off}
case "$csum" in on:on|on:off|off:on|off:off) ;; *) echo "INTEROP_CSUM=$csum: want <ours>:<linux>, each on|off" >&2; exit 2;; esac
csum_ours=${csum%:*}; csum_linux=0; [ "${csum#*:}" = off ] || csum_linux=1
[ -z "$bench" ] || [ "$server" = kernel ] || { echo "INTEROP_BENCH needs the kernel server" >&2; exit 2; }
mkdir -p "artifacts/interop/$scenario${dir:+-$dir}"
out=$(mktemp -d "artifacts/interop/$scenario${dir:+-$dir}/$(date -u +%Y%m%dT%H%M%S)-XXXXXX")
echo "artifacts: $out"
chmod 755 "$out"
sha256sum target/release/mptcp-rs-tun tests/interop/{run.sh,server.py,check.py,pattern.py,check_fin_mutation.py,check_rst_mutation.py,endpoints.py,goodput.py,retrans.py,blackhole.sh,Dockerfile,kclient.py,cpu.py,ceiling.py,bench.py} >"$out/inputs.sha256"
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
  ip netns exec "$ns" sysctl -qw net.mptcp.checksum_enabled="$csum_linux"
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
# m2-lossy: the same paths plus 1 % random loss on all four egress qdiscs.
loss=(); [ "$scenario" != m2-lossy ] || loss=(loss 1%)
case "$scenario" in base-a|base-b|m2-goodput|m2-lossy|m2-remove|m2-blackhole-*|csum-fail*)
  for x in "cli a0 10 300 1000" "srv a1 10 300 1000" "cli b0 30 80 800" "srv b1 30 80 800"; do
    set -- $x; ip netns exec "$1" tc qdisc add dev "$2" root netem delay "$3"ms rate "$4"mbit limit "$5" "${loss[@]}"
    # Bench: one segment per skb at netem for both clients. TCP builds software-GSO skbs even
    # with device GSO off (split after the qdisc), so gso_max_segs 1 is what caps them.
    [ -z "$bench" ] || { ip netns exec "$1" ethtool -K "$2" tso off gso off gro off; ip -n "$1" link set "$2" gso_max_segs 1; }
  done;;
esac
echo "$client" >"$out/client.txt"; echo "$server" >"$out/server.txt"; echo "$csum" >"$out/csum.txt"
# Two subflows: the initial one on path A and one join on path B.
m2=; [[ "$scenario" != m2-* && "$scenario" != csum-fail2 ]] || m2=1
srvip=10.0.1.2
if [ "$server" = mptcp-rs ]; then
  # 10.0.1.2 belongs to srv's kernel: the userspace server is 10.0.7.2 behind mtun0, made ahead
  # of the server so that its capture is ready. Every client subflow targets 10.0.7.2.
  srvip=10.0.7.2
  ip netns exec srv ip tuntap add dev mtun0 mode tun
  ip -n srv addr add 10.0.7.1/24 dev mtun0; ip -n srv link set mtun0 up
  ip netns exec srv sysctl -qw net.ipv4.ip_forward=1
  ip -n cli route add 10.0.7.0/24 via 10.0.1.2
  ip -n cli route add 10.0.7.2 via 10.0.2.2 dev b0 table 200
fi
# csum-fail*: the Linux selftest's corruption (mptcp_join.sh): invert payload octet 148 (from
# the IP header) of the 100th packet of 150 octets or more leaving cdev, and fix the TCP checksum.
# Packet 100 is well after the first verified mapping (Linux falls back silently before one).
cns=; cdev=
case "$scenario:$dir" in
  csum-fail1:c2s) cns=cli; cdev=a0;;
  csum-fail2:c2s) cns=cli; cdev=b0;;
  csum-fail1:s2c) cns=srv; cdev=a1;;
  csum-fail2:s2c) cns=srv; cdev=b1;;
esac
if [ -n "$cns" ]; then
  # One packet per skb: offloads off alone still leave software-GSO skbs (as the bench).
  ip netns exec $cns ethtool -K $cdev tso off gso off gro off; ip -n $cns link set $cdev gso_max_segs 1
  # Once per run: --every is larger than any run's packet count.
  ip netns exec $cns iptables -t mangle -A POSTROUTING -o $cdev -p tcp -m length --length 150:9999 -m statistic --mode nth --every 2000000000 --packet 100 -j MARK --set-mark 42
  ip netns exec $cns tc qdisc add dev $cdev clsact
  # `index 100` before `csum`, or it names the csum action.
  ip netns exec $cns tc filter add dev $cdev egress protocol ip prio 1000 handle 42 fw action pedit munge offset 148 u8 invert pipe index 100 csum tcp
fi
for x in "cli a0" "cli b0" "srv a1" "srv b1"; do
  set -- $x; echo "# $2"; ip netns exec "$1" ethtool -k "$2"; ip -n "$1" -d link show "$2"
done >"$out/ethtool.txt"
for ns in cli srv; do echo "# $ns"; ip netns exec "$ns" sysctl net.mptcp net.ipv4.tcp_congestion_control; done >"$out/sysctl.txt"
for ns in cli srv; do echo "# $ns"; ip netns exec "$ns" tc qdisc show; done >"$out/qdisc.txt"
echo "$cc" >"$out/cc.txt"
# Path B MTU 1280 with offloads off, so the B link pcap shows wire-sized packets (no GSO/GRO).
if [ "$scenario" = m2-mtu ]; then
  ip -n cli link set b0 mtu 1280; ip -n srv link set b1 mtu 1280
  ip netns exec cli ethtool -K b0 tso off gso off gro off; ip netns exec srv ethtool -K b1 tso off gso off gro off
fi
cip=10.0.9.2; sif=a1; cif=a0
[ "$scenario" != base-b ] || { cip=10.0.8.2; sif=b1; cif=b0; }
if [ "$client" = kernel ]; then
  # The kernel client sources from the veth addresses; 10.0.2.1 leaves on leg B (table 200).
  cip=10.0.1.1; [ "$scenario" != base-b ] || cip=10.0.2.1
  ip -n cli rule add from 10.0.2.1 table 200
  ip netns exec cli ip mptcp limits set subflows 2
  [ -z "$m2" ] || ip netns exec cli ip mptcp endpoint add 10.0.2.1 dev b0 subflow
fi
# M2: the initial subflow on A from 10.0.9.2, one join on B from 10.0.8.2 (captured on b1 too).
joins=()
if [ -n "$m2" ]; then
  joins=(--join 10.0.8.2); [ "$scenario" != m2-mtu ] || joins+=(--join-mtu 1280)
fi
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
# m2-unshaped (CPU-bound): no capture at all. Bench: no TUN capture either, for either client.
cap=1; [ "$scenario" != m2-unshaped ] || cap=
tdpid=; tdcli=; tdb=
if [ -n "$cap" ]; then
  ip netns exec srv tcpdump -Z root -i "$sif" -U -s 160 -w "$out/server.pcap" >"$out/capture.log" 2>&1 &
  tdpid=$!
  ip netns exec cli tcpdump -Z root -i "$cif" -U -s 160 -w "$out/client.pcap" >"$out/client-capture.log" 2>&1 &
  tdcli=$!
  if [ -n "$m2" ]; then
    ip netns exec srv tcpdump -Z root -i b1 -U -s 160 -w "$out/server-b.pcap" >"$out/capture-b.log" 2>&1 &
    tdb=$!
  fi
fi
tdtun=; tdstun=; bhpid=; cpupid=; rmpid=
if [ "$server" = mptcp-rs ]; then
  ip netns exec srv tcpdump -Z root -i mtun0 -U -s 160 -w "$out/server-tun.pcap" >"$out/server-tun-capture.log" 2>&1 &
  tdstun=$!
fi
trap 'kill ${tdpid:-} ${tdcli:-} ${tdb:-} ${tdtun:-} ${tdstun:-} ${bhpid:-} ${cpupid:-} ${rmpid:-} 2>/dev/null || true' EXIT
# Fixed cases: N bytes each way. Timed cases: 30 s in $dir, the other direction idle.
# Blackhole cases: 1 GiB in $dir, the other direction idle (outlasts the 15 s blackhole).
sargs=(--bytes "$N"); cargs=(--send "$N" --expect "$N"); want_c2s=$N; want_s2c=$N
B=1073741824
case "$scenario:$dir" in
  m2-blackhole-*:c2s) sargs=(--expect "$B" --send-bytes 0); cargs=(--send "$B" --expect 0); want_c2s=$B; want_s2c=0;;
  m2-blackhole-*:s2c) sargs=(--expect 0 --send-bytes "$B"); cargs=(--send 0 --expect "$B"); want_c2s=0; want_s2c=$B;;
  *:c2s) sargs=(--expect any --send-bytes 0); cargs=(--send-secs 30 --expect 0); want_c2s=any; want_s2c=0;;
  *:s2c) sargs=(--expect 0 --send-secs 30); cargs=(--send 0 --expect any); want_c2s=0; want_s2c=any;;
esac
verify=(); [ "$scenario" != m2-unshaped ] || verify=(--verify off)
# csum-fail1: the receiver's stream holds the rewritten octet (delivered after the fallback).
sinv=(); cinv=()
[ "$scenario" != csum-fail1 ] || if [ "$dir" = c2s ]; then sinv=(--invert 1); else cinv=(--invert 1); fi
if [ "$server" = mptcp-rs ]; then
  # server.py's counts in mptcp-rs-tun's flags (no blackhole case here).
  case "$dir" in
    c2s) targs=(--send 0 --expect any);;
    s2c) targs=(--send-secs 30 --expect 0);;
    *) targs=(--send "$N" --expect "$N");;
  esac
  ip netns exec srv timeout 910 target/release/mptcp-rs-tun --mode "$mode" --tun mtun0 --listen "$srvip:5201" "${targs[@]}" --pause-read-ms "$server_pause" --cc "$cc" --checksums "$csum_ours" "${verify[@]}" "${sinv[@]}" >"$out/server.log" 2>&1 &
  srvpid=$!
  # Listening once it holds the TUN (carrier up).
  for _ in $(seq 50); do ip -n srv link show mtun0 | grep -q LOWER_UP && break; sleep 0.1; done
else
  ip netns exec srv timeout 910 python3 tests/interop/server.py --mode "$mode" --port 5201 "${sargs[@]}" --pause-read-ms "$server_pause" "${verify[@]}" "${sinv[@]}" >"$out/server.log" 2>&1 &
  srvpid=$!
  for _ in $(seq 50); do grep -qs listening "$out/server.log" && break; sleep 0.1; done
fi
sleep 1
if [ "$client" = kernel ]; then
  ip netns exec cli timeout 910 python3 tests/interop/kclient.py --local "$cip" --remote "$srvip:5201" "${cargs[@]}" "${verify[@]}" "${cinv[@]}" >"$out/client.log" 2>&1 &
else
  ip netns exec cli timeout 910 target/release/mptcp-rs-tun --mode "$mode" --tun mtun0 --local "$cip" --remote "$srvip:5201" "${cargs[@]}" "${joins[@]}" --pause-read-ms "$client_pause" --cc "$cc" --checksums "$csum_ours" "${verify[@]}" "${cinv[@]}" >"$out/client.log" 2>&1 &
fi
clipid=$!
if [ "$scenario" = m2-remove ]; then
  # Mid-transfer, the kernel client deletes its leg-B endpoint: the transfer ends on leg A.
  ( sleep 10; id=$(ip netns exec cli ip mptcp endpoint show | awk '$1 == "10.0.2.1" {print $3}')
    echo "delete endpoint id $id at $(date +%s.%N)"; ip netns exec cli ip mptcp endpoint delete id "$id" ) >"$out/remove.log" 2>&1 &
  rmpid=$!
fi
if [ -n "$bench" ]; then
  # CPU over the steady window: the programs themselves are the children of `timeout`.
  child() { local c=; for _ in $(seq 50); do c=$(pgrep -P "$1" | head -1) && [ -n "$c" ] && break; sleep 0.1; done; echo "$c"; }
  python3 tests/interop/cpu.py "$out/cpu.json" --client "$(child "$clipid")" --server "$(child "$srvpid")" --direction "$dir" >"$out/cpu.log" 2>&1 &
  cpupid=$!
fi
case "$scenario" in
  m2-blackhole-a) bash tests/interop/blackhole.sh "$out/client.log" a0 >"$out/blackhole.log" 2>&1 & bhpid=$!;;
  m2-blackhole-b) bash tests/interop/blackhole.sh "$out/client.log" b0 >"$out/blackhole.log" 2>&1 & bhpid=$!;;
esac
if [ "$client" = mptcp-rs ]; then
  for _ in $(seq 50); do ip -n cli link show mtun0 >/dev/null 2>&1 && break; sleep 0.1; done
  ip -n cli link set mtun0 up
  if [ -n "$cap" ] && [ -z "$bench" ]; then
    ip netns exec cli tcpdump -Z root -i mtun0 -U -s 160 -w "$out/tun.pcap" >"$out/tun-capture.log" 2>&1 &
    tdtun=$!
  fi
  sleep 1
  ip -n cli addr add 10.0.9.1/24 dev mtun0; ip -n cli addr add 10.0.8.1/24 dev mtun0
fi
cli_rc=0; wait "$clipid" || cli_rc=$?
srv_rc=0; wait "$srvpid" || srv_rc=$?
bh_rc=0; [ -z "$bhpid" ] || wait "$bhpid" || bh_rc=$?
[ -z "$rmpid" ] || wait "$rmpid" || bh_rc=$?
[ -z "$cpupid" ] || wait "$cpupid" || true
sleep 1
kill $tdpid $tdcli $tdb $tdtun $tdstun 2>/dev/null || true
wait $tdpid $tdcli $tdb $tdtun $tdstun 2>/dev/null || true
trap - EXIT
ip netns exec cli iptables-save -c >"$out/client-rules.txt"
ip netns exec srv iptables-save -c >"$out/server-rules.txt"
cat "$out/client.log" "$out/server.log"
[ -z "$bhpid" ] || cat "$out/blackhole.log"
[ -z "$rmpid" ] || cat "$out/remove.log"
# Collected before the exit-code gate, so failed runs keep them.
[ -z "$cns" ] || ip netns exec $cns tc -s actions get action pedit index 100 >"$out/pedit.txt"
# Linux's MPTCP counters, in the namespace of the Linux end (both ends Linux: the server's).
lns=srv; [ "$server" = kernel ] || lns=cli
ip netns exec $lns nstat -asz | grep '^MPTcpExt' >"$out/nstat.txt" || true
[ "$cli_rc" = 0 ] && [ "$srv_rc" = 0 ] && [ "$bh_rc" = 0 ] || { echo "FAIL client=$cli_rc server=$srv_rc blackhole/remove=$bh_rc"; exit 1; }
if [ -n "$cns" ]; then
  # The corruption happened exactly once (recorded, as the Linux selftest does).
  pedit=$(awk '$1 == "Sent" {print $4; exit}' "$out/pedit.txt")
  [ "$pedit" = 1 ] || { echo "FAIL pedit rewrote ${pedit:-?} packets, want 1"; exit 1; }
fi
mib() { awk -v k="MPTcpExt$1" '$1 == k {print $2}' "$out/nstat.txt"; }
# csum-fail*: pinned from the first runs (M4b spec section 7 item 2). Which end counts the
# checksum error, and sends the reset or the infinite mapping, depends on whether Linux receives
# the corrupted direction. MPFail* count MP_FAIL packets Linux processes before its fallback.
linux_rx=0
if [ "$server:$dir" = kernel:c2s ] || [ "$client:$dir" = kernel:s2c ]; then linux_rx=1; fi
case "$scenario:$linux_rx" in
  csum-fail1:1) want="DataCsumErr=1 MPFailTx=2 MPFailRx=2 InfiniteMapTx=0 InfiniteMapRx=1 MPRstTx=0 MPRstRx=0";;
  csum-fail1:0) want="DataCsumErr=0 MPFailTx=2 MPFailRx=2 InfiniteMapTx=1 InfiniteMapRx=0 MPRstTx=0 MPRstRx=0";;
  csum-fail2:1) want="DataCsumErr=1 MPFailTx=1 MPFailRx=0 InfiniteMapTx=0 InfiniteMapRx=0 MPRstTx=1 MPRstRx=0";;
  csum-fail2:0) want="DataCsumErr=0 MPFailTx=0 MPFailRx=1 InfiniteMapTx=0 InfiniteMapRx=0 MPRstTx=0 MPRstRx=1";;
  *) want="DataCsumErr=0";;
esac
for kv in $want; do
  [ "$(mib "${kv%=*}")" = "${kv#*=}" ] || { echo "FAIL Linux MPTcpExt${kv%=*}=$(mib "${kv%=*}"), want ${kv#*=}"; exit 1; }
done
if [ "$server" = mptcp-rs ]; then
  # Joins: the mptcp-rs server reports them; the kernel client counts its MP_JOIN SYN/ACKs.
  if [ -n "$m2" ]; then
    grep -q '^event: SubflowUp' "$out/server.log" || { echo "FAIL no join (server)"; exit 1; }
    if [ "$client" = kernel ]; then
      synack_rx=$(ip netns exec cli nstat -asz MPTcpExtMPJoinSynAckRx | awk '$1 == "MPTcpExtMPJoinSynAckRx" {print $2}')
      [ "${synack_rx:-0}" -ge 1 ] || { echo "FAIL no join (client)"; exit 1; }
    fi
  fi
  python3 tests/interop/check.py "$scenario" "$out" "$want_c2s" "$want_s2c" --client "$client" --server "$server" | tee "$out/result.log"
elif [ -n "$bench" ] || [ "$client" = kernel ]; then
  # Both clients face the same checks: byte counts, and for A+B a completed MP_JOIN.
  if [ -n "$m2" ]; then
    joins_rx=$(ip netns exec srv nstat -asz MPTcpExtMPJoinAckRx | awk '$1 == "MPTcpExtMPJoinAckRx" {print $2}')
    [ "${joins_rx:-0}" -ge 1 ] || { echo "FAIL no join"; exit 1; }
  fi
  python3 tests/interop/check.py "$scenario" "$out" "$want_c2s" "$want_s2c" logs-only | tee "$out/result.log"
else
  python3 tests/interop/check.py "$scenario" "$out" "$want_c2s" "$want_s2c" | tee "$out/result.log"
fi
