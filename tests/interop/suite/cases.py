"""Interop Suite catalog (amendment §5.6). Case dict keys, as run_suite.py consumes them:

- name; group: the mptcp_join.sh family it is modelled on (for the coverage note)
- server: family v4|v6|dual, bidi, abort_after (bytes or None), pm (`ip mptcp` argument strings run
  in srv at t=0), timed [(barrier, ms, shell command in srv)], optional sysctl ["key=value"] set in
  srv before the server starts
- client: script (scenario text, Task 7), send_secs, send_rate (None: unlimited), optional args
  (extra mptcp-rs-tun flags, e.g. --join)
- links {i: {"rate", "delay"}} overriding 20mbit/10ms; fail [(link, barrier, ms, secs)]
- expect: bytes c2s|s2c|bidi, nstat {counter: int or (op, int)} on the srv delta, pcap [check(r)]
  raising AssertionError, events (ordered prefixes of client `event:` lines), kernel ("X.Y"
  minimum, else SKIP)
- watchdog_s; ci (part of the CI subset)

A barrier is a client event name with an optional subflow number: "Connected", "SubflowUp:1".
"""


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
                   "pcap": [subflows(*cips)],
                   "events": ["Connected mptcp=true"] + ["SubflowUp"] * n + ["Closed Normal"],
                   "kernel": None},
        "watchdog_s": 150, "ci": True,
    }


# No c2s-only case: the client would close first and its Closed event waits out TIME-WAIT
# (2 MSL = 120 s), so with bidi or s2c the server closes first.
CASES = [
    joins("no-join", 0, "s2c"),
    joins("one-join", 1, "bidi"),
    joins("two-joins", 2, "bidi"),
]
