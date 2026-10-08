#!/usr/bin/env bash
# Blackhole one path for the M2 cases: in the cli netns, DROP all traffic forwarded through
# DEV (both directions) for exactly 15 s, starting 5 s after the client logs Connected.
# Usage: blackhole.sh CLIENT_LOG DEV. Prints wall-clock times; the DROP counters stay in
# the BLACKHOLE chain for iptables-save.
set -euo pipefail
log=$1; dev=$2
ipt() { ip netns exec cli iptables "$@"; }
ipt -N BLACKHOLE
ipt -A BLACKHOLE -j DROP
for _ in $(seq 600); do grep -qs '^event: Connected' "$log" && break; sleep 0.05; done
grep -qs '^event: Connected' "$log" || { echo "no Connected line"; exit 1; }
echo "connected-seen $(date +%s.%N)"
sleep 5
ipt -I FORWARD -i "$dev" -j BLACKHOLE; ipt -I FORWARD -o "$dev" -j BLACKHOLE
echo "drop-on $(date +%s.%N) dev $dev"
sleep 15
ipt -D FORWARD -i "$dev" -j BLACKHOLE; ipt -D FORWARD -o "$dev" -j BLACKHOLE
echo "drop-off $(date +%s.%N)"
