"""Interop Suite catalog (amendment §5.6). Case dict keys, as run_suite.py consumes them:

- name; group: the mptcp_join.sh family it is modelled on (for the coverage note)
- server: family v4|v6|dual, bidi, abort_after (bytes or None), pm (`ip mptcp` argument strings run
  in srv at t=0), timed [(barrier, ms, shell command in srv)], optional sysctl ["key=value"] set in
  srv before the server starts
- client: script (scenario text, Task 7), send_secs, send_rate (None: unlimited), optional args
  (extra mptcp-rs-tun flags, e.g. --join)
- links {i: {"rate", "delay"}} overriding 20mbit/10ms; fail [(link, barrier, ms, secs)]
- expect: bytes c2s|s2c|bidi, nstat {counter: int or (op, int)} on the srv delta, pcap [check(r)]
  raising AssertionError, events (ordered prefixes of client `event:` lines; the runner requires
  "Closed Normal" itself when the client closes passively, and stops an active closer in
  TIME-WAIT), kernel ("X.Y" minimum, else SKIP)
- watchdog_s; ci (part of the CI subset)

A barrier is a client event name with an optional subflow number: "Connected", "SubflowUp:1".
"""


def fin_fin_no_rst(r):
    """At mtun0: no RST, and every subflow carried a FIN from each end. Every case whose client
    may be stopped in TIME-WAIT needs this check: it is the proof of the FIN exchange."""
    tun = [g for g in r.segs if g.point == "cli"]
    assert not any(g.flags & 0x04 for g in tun), "RST present"
    for f in {g.flow for g in tun}:
        fins = {g.direction for g in tun if g.flow == f and g.flags & 0x01}
        assert fins == {"c2s", "s2c"}, f"{f}: FIN only {sorted(fins)}"


def subflows(*cips):
    """One subflow from each client address, the first MP_CAPABLE and the rest MP_JOIN, each
    carrying new data in every direction of the transfer."""
    def check(r):
        syns = [g for g in r.segs if g.point == "cli" and g.flags & 0x12 == 0x02]
        got = {g.src: {o["tcp.options.mptcp.subtype"] for o in g.mptcp} for g in syns}
        assert got == {c: {"1" if i else "0"} for i, c in enumerate(cips)}, f"SYNs {got}"
        b = r.case["expect"]["bytes"]
        for d in ["c2s", "s2c"] if b == "bidi" else [b]:
            carriers = {g.src if d == "c2s" else g.dst for g in r.segs if g.direction == d and g.new_bytes}
            assert carriers == set(cips), f"{d} new data from {sorted(carriers)}"
    return check


def joins(name, n, direction):
    """The initial subflow on link 1 and n joins, from 10.0.9i.2 on link i."""
    cips = [f"10.0.9{i}.2" for i in range(1, n + 2)]
    return {
        "name": name, "group": "subflows",
        "server": {"family": "v4", "bidi": direction == "bidi", "abort_after": None,
                   "pm": ["limits set subflows 2 add_addr_accepted 0"], "timed": []},
        "client": {"script": "", "send_secs": 5, "send_rate": None,
                   "args": [a for c in cips[1:] for a in ("--join", c)]},
        "links": {}, "fail": [],
        "expect": {"bytes": direction,
                   "nstat": {"MPTcpExtMPCapableSYNRX": 1, "MPTcpExtMPCapableFallbackACK": 0,
                             "MPTcpExtMPJoinSynRx": n, "MPTcpExtMPJoinAckRx": n},
                   "pcap": [subflows(*cips), fin_fin_no_rst],
                   "events": ["Connected mptcp=true"] + ["SubflowUp"] * n,
                   "kernel": None},
        "watchdog_s": 40, "ci": True,
    }


def refused_join():
    """`limits set subflows 0`: Linux answers the join's third ACK with a RST carrying MP_TCPRST
    0x03 T=0 (probe `refused_join_rst_reason`), which the client reports in `SubflowDown`."""
    case = joins("refused-join-mptcp-rst", 1, "s2c")
    case["server"]["pm"] = ["limits set subflows 0 add_addr_accepted 0"]
    case["client"]["send_secs"] = 4
    case["expect"].update(nstat={"MPTcpExtMPCapableSYNRX": 1, "MPTcpExtMPJoinSynRx": 1},
                          pcap=[], events=["Connected mptcp=true", "SubflowDown SubflowId(1) Reset rst=0x03/T0"])
    return case


CASES = [
    joins("no-join", 0, "c2s"),
    joins("one-join", 1, "s2c"),
    joins("two-joins", 2, "bidi"),
    refused_join(),
]
