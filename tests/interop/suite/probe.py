#!/usr/bin/env python3
"""Probe, on the wire, the Linux behaviours that the suite's stimuli rely on (amendment §5.5),
and write probe.json: one boolean per behaviour with its pcap evidence. A false entry moves its
contract to a library test. Runs inside the interop image, like run_suite.py."""
import json
from pathlib import Path
import time

import cases
import run_suite


def stimulus(name, joins, secs, sysctl=(), pm=(), timed=(), abort_after=None):
    case = cases.joins(name, joins, "s2c")
    case["server"].update(sysctl=list(sysctl), timed=list(timed), abort_after=abort_after)
    case["server"]["pm"] = ["limits set subflows 2 add_addr_accepted 0", *pm]
    case["client"]["send_secs"] = secs
    case["watchdog_s"] = 40
    return case


def server_opts(r, subtype, more=lambda g, o: True):
    """Server-sent segments (at the srv veths, their before point) with that MPTCP subtype."""
    return [g for g in r.segs if g.point == "srv" and g.direction == "s2c"
            and any(o["tcp.options.mptcp.subtype"] == subtype and more(g, o) for o in g.mptcp)]


def evidence(segs):
    return [{"t": g.t, "src": f"{g.src}:{g.sport}", "dst": f"{g.dst}:{g.dport}", "flags": hex(g.flags),
             "mptcp": [{k.removeprefix("tcp.options.mptcp."): v for k, v in o.items() if k.startswith("tcp.options.mptcp")}
                       for o in g.mptcp]} for g in segs[:4]]


def main():
    root = Path("artifacts/interop/suite") / ("probe-" + time.strftime("%Y%m%dT%H%M%S", time.gmtime()))
    probe = {}

    def entry(key, segs, **extra):
        probe[key] = {"value": bool(segs), **extra, "evidence": evidence(segs)}

    r = run_suite.run_case(stimulus("prio", 1, 6, pm=["endpoint add 10.0.1.2 dev s1 id 1"],
                                    timed=[("SubflowUp:1", 1000, "ip mptcp endpoint change id 1 backup")]), root / "prio")
    entry("mp_prio_on_endpoint_change", server_opts(r, "5"),
          stimulus="srv `endpoint add 10.0.1.2 dev s1 id 1`; 1 s after the client's join is up: `endpoint change id 1 backup`")

    r = run_suite.run_case(stimulus("signal", 0, 13, sysctl=["net.mptcp.add_addr_timeout=2"],
                                    pm=["endpoint add 10.0.2.2 dev s2 id 2 signal"],
                                    timed=[("Connected", 10500, "ip mptcp endpoint delete id 2")]), root / "signal")
    deleted = next(t for label, t in r.marks if "delete" in label)
    entry("remove_addr_on_endpoint_delete", [g for g in server_opts(r, "4") if g.t >= deleted],
          stimulus="srv `endpoint delete id 2` of a signalled 10.0.2.2, 10.5 s after Connected")
    adds = server_opts(r, "3", lambda g, o: o.get("tcp.options.mptcp.echo") == "0")
    adds = [g for g in adds if g.t <= adds[0].t + 10] if adds else []
    probe["add_addr_retransmit_without_echo"] = {
        "value": len(adds) > 1, "add_addr_in_10s": len(adds), "repeats": max(len(adds) - 1, 0),
        "stimulus": "srv `endpoint add 10.0.2.2 dev s2 id 2 signal`, add_addr_timeout=2; the client never "
                    "echoes (ADD_ADDR receive is Task 9), so no echo needed dropping; window: 10 s from the first ADD_ADDR",
        "evidence": evidence(adds)}

    r = run_suite.run_case(stimulus("refused", 1, 4, pm=["limits set subflows 0 add_addr_accepted 0"]), root / "refused")
    rsts = [g for g in r.segs if g.point == "srv" and g.direction == "s2c" and g.flags & 0x04 and g.dst == "10.0.92.2"]
    entry("refused_join_rst_reason", [g for g in rsts if any(o["tcp.options.mptcp.subtype"] == "8" for o in g.mptcp)],
          stimulus="srv `limits set subflows 0`; the client joins from 10.0.92.2",
          server_rsts_on_join=evidence(rsts))

    r = run_suite.run_case(stimulus("fastclose", 0, 5, abort_after=1000000), root / "fastclose")
    entry("fastclose_on_linger0", server_opts(r, "7"), stimulus="server.py --abort-after 1000000 (SO_LINGER 0, close)")

    r = run_suite.run_case(stimulus("c1", 0, 1, sysctl=["net.mptcp.allow_join_initial_addr_port=0"]), root / "c1")
    entry("c1_from_sysctl", server_opts(r, "0", lambda g, o: g.flags & 0x12 == 0x12
                                        and o.get("tcp.options.mptcp.nomoresubflows.flag") == "1"),
          stimulus="srv sysctl net.mptcp.allow_join_initial_addr_port=0; C flag on the MP_CAPABLE SYN/ACK")

    for n in ("cli", "srv"):
        run_suite.sh("ip", "netns", "del", n, check=False)
    (root / "probe.json").write_text(json.dumps(probe, indent=1))
    print(json.dumps({k: v["value"] for k, v in probe.items()}, indent=1))
    print(f"probe: {root}/probe.json")


if __name__ == "__main__":
    main()
