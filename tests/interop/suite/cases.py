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
  TIME-WAIT), kernel ("X.Y" minimum, else SKIP), optional aborted ("client" | "server": the case
  ends in that side's abort, so no transfer completes and the runner expects that side's exit)
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


def fastclose_rsts(r):
    """At mtun0: every subflow carried a client RST whose only MPTCP option is MP_FASTCLOSE with
    the server's key, from its MP_CAPABLE SYN/ACK (M3 spec §3.4 note, §3.5)."""
    tun = [g for g in r.segs if g.point == "cli"]
    keys = {o.get("tcp.options.mptcp.sendkey") for g in tun if g.flags & 0x12 == 0x12 for o in g.mptcp} - {None}
    assert len(keys) == 1, f"server keys {keys}"
    for f in {g.flow for g in tun}:
        rsts = [g for g in tun if g.flow == f and g.direction == "c2s" and g.flags & 0x04]
        opts = [[(o["tcp.options.mptcp.subtype"], o.get("tcp.options.mptcp.recvkey")) for o in g.mptcp] for g in rsts]
        assert [("7", *keys)] in opts, f"{f}: client RSTs {opts}, server key {keys}"


def linux_fastclose(r):
    """At mtun0: Linux's abort RST carries MP_FASTCLOSE (probe `fastclose_on_linger0`)."""
    rsts = [g for g in r.segs if g.point == "cli" and g.direction == "s2c" and g.flags & 0x04]
    subtypes = [[o["tcp.options.mptcp.subtype"] for o in g.mptcp] for g in rsts]
    assert any("7" in s for s in subtypes), f"server RSTs {subtypes}"


def client_abort():
    """The client aborts 2 s after Connected, its join up (`--abort-after-ms`): RST and
    MP_FASTCLOSE on every subflow; Linux counts the MP_FASTCLOSE and resets the server socket."""
    case = joins("client-abort", 1, "c2s")
    case["client"]["args"] += ["--abort-after-ms", "2000"]
    e = case["expect"]
    e.update(aborted="client", pcap=[e["pcap"][0], fastclose_rsts],
             events=["Connected mptcp=true", "SubflowUp", "Closed Aborted"])
    e["nstat"]["MPTcpExtMPFastcloseRx"] = (">=", 1)
    return case


def server_abort():
    """`server.py --abort-after` (SO_LINGER 0): Linux's RST with MP_FASTCLOSE, which the client
    reports as `Closed { Reset }`."""
    case = joins("server-abort", 0, "s2c")
    case["server"]["abort_after"] = 1000000
    case["expect"].update(aborted="server", pcap=[linux_fastclose],
                          events=["Connected mptcp=true", "Closed Reset"])
    return case


CASES = [
    joins("no-join", 0, "c2s"),
    joins("one-join", 1, "s2c"),
    joins("two-joins", 2, "bidi"),
    refused_join(),
    client_abort(),
    server_abort(),
]
