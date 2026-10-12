#!/usr/bin/env python3
"""Theoretical goodput ceiling of a shaped bench run: each leg's netem rate times the share of
the bytes netem charges that is TCP payload, measured on that run's data segments."""
import subprocess
import sys
from pathlib import Path

RATES_MBPS = {"a": 300, "b": 80}
SRV = "10.0.1.2"


def ceiling_mbps(ratios):
    return sum(RATES_MBPS[p] * r for p, r in ratios.items())


def leg_payload(pcap, direction):
    """(sum of tcp.len, sum of frame.len) over the data direction's data segments.

    frame.len is what netem's rate charges: v7.0 sch_netem.c adds packet_time_ns(qdisc_pkt_len(skb))
    with packet_overhead 0, and a veth skb carries its 14-byte MAC header at enqueue (the
    net_dev_queue trace shows len=1514 at MTU 1500). With gso_max_segs 1 each skb is one frame."""
    flt = f"ip.{'dst' if direction == 'c2s' else 'src'} == {SRV} && tcp.len > 0"
    out = subprocess.check_output(["tshark", "-r", str(pcap), "-Y", flt, "-T", "fields", "-e", "tcp.len", "-e", "frame.len"], text=True)
    rows = [line.split("\t") for line in out.splitlines()]
    return sum(int(r[0]) for r in rows), sum(int(r[1]) for r in rows)


def payload_ratio(pcap, direction):
    payload, frames = leg_payload(pcap, direction)
    return payload / frames


def run_ceiling(run_dir, scenario, direction):
    """(ceiling Mbit/s, payload bytes per leg). An unused leg takes the other leg's ratio."""
    pcaps = {"base-a": {"a": "server.pcap"}, "base-b": {"b": "server.pcap"}}.get(scenario, {"a": "server.pcap", "b": "server-b.pcap"})
    legs = {p: leg_payload(Path(run_dir) / f, direction) for p, f in pcaps.items()}
    ratios = {p: pay / fr for p, (pay, fr) in legs.items() if fr}
    if not ratios:
        raise ValueError(f"{run_dir}: no {direction} data segments on any leg")
    fallback = next(iter(ratios.values()))
    return ceiling_mbps({p: ratios.get(p, fallback) for p in legs}), {p: pay for p, (pay, _) in legs.items()}


if __name__ == "__main__":
    print(run_ceiling(*sys.argv[1:]))
