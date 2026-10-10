"""Interop Suite catalog (amendment §5.6). Case dict keys, as run_suite.py consumes them:

- name; group: the mptcp_join.sh family it is modelled on (for the coverage note)
- server: family v4|v6|dual, bidi, abort_after (bytes or None), pm (`ip mptcp` argument strings run
  in srv at t=0), timed [(barrier, ms, shell command in srv)], optional sysctl ["key=value"] set in
  srv before the server starts
- client: script (scenario text for `mptcp-rs-tun --script`, crates/mptcp-rs-tun/src/script.rs),
  send_secs, send_rate (Mbit/s as a string; None: unlimited), optional args (extra mptcp-rs-tun
  flags, e.g. --join)
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


PRIMARY, BACKUP = "10.0.91.2", "10.0.92.2"
GUARD = 0.1  # as run_suite.GUARD: packets this close (s) to a phase boundary are not judged
JOIN = f"at Connected +0 join {BACKUP} 10.0.1.2:5201"


def scripted(name, group, direction, script, send_secs=5, send_rate=None, watchdog_s=40):
    """The initial subflow on link 1 and one join from 10.0.92.2 on link 2, made by `script`."""
    case = joins(name, 1, direction)
    case["group"] = group
    case["client"].update(script=script, args=[], send_secs=send_secs, send_rate=send_rate)
    case["expect"]["pcap"] = [fin_fin_no_rst]
    case["watchdog_s"] = watchdog_s
    return case


def carried(r, cip, d, segs=None):
    """New payload bytes on the subflow of client address cip in direction d (counted at d's before
    point), within segs (default: all)."""
    return sum(g.new_bytes for g in (r.segs if segs is None else segs)
               if g.direction == d and (g.src if d == "c2s" else g.dst) == cip)


def window(r, link=1):
    """The failure window of `link`, from the runner's marks."""
    marks = dict(r.marks)
    return marks[f"link {link} down"], marks[f"link {link} up"]


def mptcp_with(r, point, d, subtype):
    """Segments at `point` in direction d carrying an MPTCP option of `subtype`, with that option."""
    return [(g, o) for g in r.segs if g.point == point and g.direction == d
            for o in g.mptcp if o["tcp.options.mptcp.subtype"] == subtype]


def delivered_in_window(cip, link=1):
    """New data on cip's subflow inside the failure window, in every direction of the transfer,
    sent (before point) and delivered (the same segments at the after point)."""
    def check(r):
        t0, t1 = window(r, link)
        b = r.case["expect"]["bytes"]
        for d in ["c2s", "s2c"] if b == "bidi" else [b]:
            sent = {(g.flow, g.seq) for g in r.phase(t0, t1) if g.new_bytes
                    and g.direction == d and (g.src if d == "c2s" else g.dst) == cip}
            assert sent, f"{d}: no new data on {cip} while link {link} was down"
            after = {"c2s": "srv", "s2c": "cli"}[d]
            got = {(g.flow, g.seq) for g in r.segs if g.point == after and g.len} & sent
            assert got, f"{d}: new data on {cip} in the window never delivered"
    return check


def join_syn_backup(r):
    """At mtun0: the join SYN from 10.0.92.2 carries MP_JOIN with B=1 (M3 spec §3.6)."""
    syns = [o for g, o in mptcp_with(r, "cli", "c2s", "1") if g.src == BACKUP and g.flags & 0x12 == 0x02]
    assert [o.get("tcp.options.mptcp.backup.flag") for o in syns] == ["1"], f"join SYN options {syns}"


def no_new_on_backup(d, before_window=False):
    """No new data on the backup subflow in direction d while the primary is usable: the whole run,
    or up to the failure window."""
    def check(r):
        segs = r.phase(0, window(r)[0]) if before_window else None
        n = carried(r, BACKUP, d, segs)
        assert n == 0, f"{d}: {n} new bytes on the backup while the primary was usable"
        assert carried(r, PRIMARY, d, segs) > 0, f"{d}: no new data on the primary"
    return check


def join_backup():
    """`join … backup`: the SYN's B bit; Linux, the sender, keeps new data off it while the primary
    is usable."""
    case = scripted("join-backup", "backup", "s2c", f"{JOIN} backup")
    e = case["expect"]
    e["nstat"]["MPTcpExtMPJoinSynBackupRx"] = 1
    e["pcap"] += [join_syn_backup, no_new_on_backup("s2c")]
    return case


def prio_sent(r):
    """At mtun0: exactly one MP_PRIO, B=1, on the joined subflow and none elsewhere; from 1 s after it
    Linux sends no new data on that subflow."""
    prios = mptcp_with(r, "cli", "c2s", "5")
    assert [(g.src, o.get("tcp.options.mptcp.backup.flag")) for g, o in prios] == [(BACKUP, "1")], \
        f"MP_PRIO {[(g.src, o) for g, o in prios]}"
    later = [g for g in r.segs if g.t > prios[0][0].t + 1]
    assert carried(r, BACKUP, "s2c", later) == 0, "new data on the subflow after MP_PRIO B=1"


def set_backup_mp_prio():
    """`set-backup 1 on` 1 s after the join is up: one MP_PRIO B=1 on that subflow (M3 spec §3.2)."""
    case = scripted("set-backup-mp-prio", "backup", "s2c", f"{JOIN}\nat SubflowUp:1 +1000 set-backup 1 on",
                    send_secs=6)
    e = case["expect"]
    e["nstat"]["MPTcpExtMPPrioRx"] = (">=", 1)
    e["pcap"] += [prio_sent]
    return case


def peer_prio_obeyed(r):
    """Every subflow that received MP_PRIO B=1 (Linux sends it on the initial subflow only, see the
    Task 2 probe) carries no new client data from its arrival at mtun0 on; the other one still does."""
    prios = [(g, o) for g, o in mptcp_with(r, "cli", "s2c", "5") if o.get("tcp.options.mptcp.backup.flag") == "1"]
    assert prios, "no MP_PRIO B=1 reached the client"
    flows = {g.flow: g.t for g, _ in reversed(prios)}  # the first arrival per flow
    for flow, t in flows.items():
        later = [g for g in r.segs if g.t > t + GUARD and g.flow == flow]
        n = sum(g.new_bytes for g in later if g.direction == "c2s")
        assert n == 0, f"{flow}: {n} new bytes after MP_PRIO B=1"
    rest = [g for g in r.segs if g.t > min(flows.values()) + GUARD and g.flow not in flows]
    assert sum(g.new_bytes for g in rest if g.direction == "c2s"), "no new data on the other subflow"


def server_mp_prio():
    """`endpoint change … backup` 1 s after the join is up: Linux's MP_PRIO B=1 is reported as
    `PeerPriority`, and the client sends no new data on that subflow."""
    case = scripted("server-mp-prio", "backup", "c2s", JOIN, send_secs=6, send_rate="8")
    case["server"]["pm"] += ["endpoint add 10.0.1.2 dev s1 id 1"]
    case["server"]["timed"] = [("SubflowUp:1", 1000, "ip mptcp endpoint change id 1 backup")]
    e = case["expect"]
    e["nstat"]["MPTcpExtMPPrioTx"] = (">=", 1)
    e["pcap"] += [peer_prio_obeyed]
    e["events"] += ["PeerPriority { subflow: SubflowId(0), backup: true }"]
    return case


def failover(name, group, direction, script, cip, extra=()):
    """Link 1 (the initial subflow's) fails for 20 s from 2 s after the join is up; new data is
    delivered on cip's subflow inside the window, and the transfer completes. The transfer runs
    45 s: the failed subflow's backed-off retransmission (RTO 1, 2, 4, 8, 16 s) recovers it about
    31 s after the failure began, and it must finish its FIN exchange before the end, or the
    server resets it for retransmitting data it already has (fin_fin_no_rst)."""
    rate = None if direction == "s2c" else "8"
    case = scripted(name, group, direction, script, send_secs=45, send_rate=rate, watchdog_s=130)
    case["fail"] = [(1, "SubflowUp:1", 2000, 20)]
    case["expect"]["pcap"] += [delivered_in_window(cip), *extra]
    case["ci"] = False
    return case


CASES = [
    joins("no-join", 0, "c2s"),
    joins("one-join", 1, "s2c"),
    joins("two-joins", 2, "bidi"),
    refused_join(),
    client_abort(),
    server_abort(),
    join_backup(),
    set_backup_mp_prio(),
    server_mp_prio(),
    # The client's own sending follows its local backup policy; the server's follows the B bit.
    failover("backup-failover-c2s", "link_failure", "c2s",
             f"{JOIN} backup label=j\nafter j +0 set-local-backup 1 on", BACKUP,
             [no_new_on_backup("c2s", before_window=True)]),
    failover("backup-failover-s2c", "link_failure", "s2c", f"{JOIN} backup", BACKUP,
             [no_new_on_backup("s2c", before_window=True)]),
    failover("one-of-two-fails-c2s", "link_failure", "c2s", JOIN, BACKUP),
    failover("one-of-two-fails-s2c", "link_failure", "s2c", JOIN, BACKUP),
    failover("one-of-two-fails-bidi", "link_failure", "bidi", JOIN, BACKUP),
]
