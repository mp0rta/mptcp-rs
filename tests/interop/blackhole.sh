#!/usr/bin/env bash
# Blackhole one path for the M2 cases: DROP all traffic through DEV's leg (both directions) for
# exactly 15 s, starting 5 s after the client logs Connected. Each direction is dropped where it
# arrives, after the sender's egress netem queue, so data already queued there is lost too: the
# server's INPUT on the leg's server interface, the client's FORWARD from DEV.
# Usage: blackhole.sh CLIENT_LOG DEV (a0 or b0; the server side is a1 or b1). Prints
# wall-clock times; the DROP counters stay in each netns's BLACKHOLE chain for iptables-save.
set -euo pipefail
log=$1; dev=$2; sdev=${dev%0}1
cli() { ip netns exec cli iptables "$@"; }
srv() { ip netns exec srv iptables "$@"; }
for ipt in cli srv; do $ipt -N BLACKHOLE; $ipt -A BLACKHOLE -j DROP; done
for _ in $(seq 600); do grep -qs '^event: Connected' "$log" && break; sleep 0.05; done
grep -qs '^event: Connected' "$log" || { echo "no Connected line"; exit 1; }
echo "connected-seen $(date +%s.%N)"
sleep 5
srv -I INPUT -i "$sdev" -j BLACKHOLE; cli -I FORWARD -i "$dev" -j BLACKHOLE
echo "drop-on $(date +%s.%N) dev $dev"
sleep 15
srv -D INPUT -i "$sdev" -j BLACKHOLE; cli -D FORWARD -i "$dev" -j BLACKHOLE
echo "drop-off $(date +%s.%N)"
