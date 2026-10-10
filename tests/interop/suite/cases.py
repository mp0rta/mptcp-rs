"""Interop Suite catalog (amendment §5.6). Case dict keys, as run_suite.py consumes them:

- name; group: the mptcp_join.sh family it is modelled on (for the coverage note)
- server: family v4|v6|dual, bidi, abort_after (bytes or None), pm (`ip mptcp` argument strings run
  in srv at t=0), timed [(barrier, ms, shell command in srv)], optional sysctl ["key=value"] and
  setup [shell command] run in srv before the server starts
- client: script (scenario text for `mptcp-rs-tun --script`, crates/mptcp-rs-tun/src/script.rs),
  send_secs, send_rate (Mbit/s as a string; None: unlimited), optional args (extra mptcp-rs-tun
  flags, e.g. --join), optional local and remote (the initial subflow's addresses; default
  10.0.91.2 to 10.0.1.2:5201)
- links {i: {"rate", "delay"}} overriding 20mbit/10ms; fail [(link, barrier, ms, secs)]; optional
  drop_once (an iptables match): a cli FORWARD DROP rule, deleted once it has dropped one packet
- expect: bytes c2s|s2c|bidi, nstat {counter: int or (op, int)} on the srv delta, pcap [check(r)]
  raising AssertionError, events (ordered prefixes of client `event:` lines; the runner requires
  "Closed Normal" itself when the client closes passively, and stops an active closer in
  TIME-WAIT), kernel ("X.Y" minimum, else SKIP), optional aborted ("client" | "server": the case
  ends in that side's abort, so no transfer completes and the runner expects that side's exit),
  optional reset [client addresses whose subflows end in a client RST, see fin_fin_no_rst],
  optional refused [client addresses whose joins never come up; the case's own checks judge them]
- watchdog_s; ci (part of the CI subset)

A barrier is a client event name with an optional subflow number: "Connected", "SubflowUp:1".
"""


def fin_fin_no_rst(r):
    """At mtun0: no RST, and every subflow carried a FIN from each end; except that a subflow from
    a client address in expect["reset"] (`remove-address`) ends in a client RST instead: the
    address's first subflows, in SYN order, one per listing. A join from an address in
    expect["refused"] is left to the case's own checks. Every case whose client may be stopped in
    TIME-WAIT needs this check: it is the proof of the FIN exchange."""
    tun = [g for g in r.segs if g.point == "cli"]
    reset = list(r.case["expect"].get("reset", ()))
    refused = set(r.case["expect"].get("refused", ()))
    for f in sorted({g.flow for g in tun}, key=lambda f: min(g.t for g in tun if g.flow == f)):
        segs = [g for g in tun if g.flow == f]
        addrs = {a for a, _ in f}
        if addrs & refused:
            continue
        if addrs & set(reset):
            reset.remove(next(iter(addrs & set(reset))))
            assert any(g.flags & 0x04 and g.direction == "c2s" for g in segs), f"{f}: no client RST"
            continue
        assert not any(g.flags & 0x04 for g in segs), f"{f}: RST present"
        fins = {g.direction for g in segs if g.flags & 0x01}
        assert fins == {"c2s", "s2c"}, f"{f}: FIN only {sorted(fins)}"


def subflows(*cips, refused=()):
    """One subflow from each client address, the first MP_CAPABLE and the rest MP_JOIN, each
    carrying new data in every direction of the transfer; and a join from each `refused` address,
    carrying none."""
    def check(r):
        syns = [g for g in r.segs if g.point == "cli" and g.flags & 0x12 == 0x02]
        got = {g.src: {o["tcp.options.mptcp.subtype"] for o in g.mptcp} for g in syns}
        assert got == {c: {"1" if i else "0"} for i, c in enumerate(cips + tuple(refused))}, f"SYNs {got}"
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


def removed(rid, carrier, reset_from=None):
    """At mtun0: exactly one REMOVE_ADDR, for address id rid, from carrier's subflow; and the client
    RSTs on reset_from's subflow carry MP_TCPRST 0x00 T=0 (M3 spec §3.4)."""
    def check(r):
        rms = [(g.src, o.get("tcp.options.mptcp.addrid")) for g, o in mptcp_with(r, "cli", "c2s", "4")]
        assert rms == [(carrier, str(rid))], f"REMOVE_ADDR {rms}"
        if reset_from:
            rsts = [(o.get("tcp.options.mptcp.rst_reason"), o.get("tcp.options.mptcp.flag_T.flag"))
                    for g, o in mptcp_with(r, "cli", "c2s", "8") if g.src == reset_from and g.flags & 0x04]
            assert rsts and set(rsts) == {("0x00", "0")}, f"MP_TCPRST on {reset_from}: {rsts}"
    return check


def remove_address(name, gone, survivor, rid):
    """`remove-address gone` 1 s after the join is up: the subflow from gone is reset with
    MP_TCPRST 0x00/T0, REMOVE_ADDR rid goes on survivor's subflow, and the transfer completes there
    (M3 spec §4.2). Linux counts the REMOVE_ADDR (RmAddr) and the MP_TCPRST (MPRstRx), but not
    MPTcpExtRmSubflow: our RST, a few µs behind the REMOVE_ADDR, ends the subflow before Linux's
    path manager acts on the REMOVE_ADDR (observed in the Task 8 run). That contract, the
    REMOVE_ADDR next to the reset, stays with the library test
    `remove_address_sends_remove_addr_and_resets` (amendment §5.5)."""
    sub = 1 if gone == BACKUP else 0
    case = scripted(name, "remove", "c2s", f"{JOIN}\nat SubflowUp:1 +1000 remove-address {gone}",
                    send_secs=5, send_rate="8")
    e = case["expect"]
    e["reset"] = [gone]
    e["nstat"].update(MPTcpExtRmAddr=(">=", 1), MPTcpExtMPRstRx=(">=", 1))
    e["pcap"] += [removed(rid, survivor, reset_from=gone)]
    e["events"] += [f"SubflowDown SubflowId({sub}) Reset rst=none"]
    return case


def make_before_break():
    """Make-before-break (M3 spec §4.2): join the new path, `set-backup` the old one, retire it by
    FIN exchange (`close-subflow`), and once it has ended withdraw its address; the transfer
    completes on the new path with no RST anywhere."""
    script = "\n".join([JOIN, "at SubflowUp:1 +1000 set-backup 0 on label=b",
                        "after b +500 close-subflow 0", f"at SubflowDown:0 +200 remove-address {PRIMARY}"])
    case = scripted("make-before-break", "re-establishment", "c2s", script, send_secs=6, send_rate="8")
    e = case["expect"]
    e["nstat"].update(MPTcpExtMPPrioRx=(">=", 1), MPTcpExtRmAddr=(">=", 1))
    e["pcap"] += [removed(0, BACKUP)]
    e["events"] += ["SubflowDown SubflowId(0) Normal"]
    return case


SIGNALLED = "10.0.2.2"
REACT = f"on announced join {BACKUP}"


def add_addrs(r, point, d, echo):
    """ADD_ADDR options with E=echo ("0" or "1") at `point` in direction d, with their segments."""
    return [(g, o) for g, o in mptcp_with(r, point, d, "3") if o.get("tcp.options.mptcp.echo") == echo]


def echoed(rid, ip, port=None):
    """At mtun0: every echo the client sent is ADD_ADDR rid with E=1, no HMAC, and the announced
    address and port (M3 spec §3.2)."""
    def check(r):
        family = "ipv6" if ":" in ip else "ipv4"
        got = {(o.get("tcp.options.mptcp.addrid"), o.get(f"tcp.options.mptcp.{family}"), o.get("tcp.options.mptcp.port"),
                "tcp.options.mptcp.addaddrtrunchmac" in o) for _, o in add_addrs(r, "cli", "c2s", "1")}
        assert got == {(str(rid), ip, port and str(port), False)}, f"echoes {got}"
    return check


def join_syns(r):
    """The MP_JOIN SYNs at mtun0 (their retransmissions included)."""
    return [g for g, _ in mptcp_with(r, "cli", "c2s", "1") if g.flags & 0x12 == 0x02]


def hostport(ip, port):
    """ "IP:port", IPv6 in brackets: as the client prints a socket address."""
    return f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}"


def joined_only(*dsts, src=BACKUP):
    """At mtun0: the MP_JOIN SYNs went from src to dsts ("IP:port") and nowhere else."""
    def check(r):
        got = {(g.src, hostport(g.dst, g.dport)) for g in join_syns(r)}
        assert got == {(src, d) for d in dsts}, f"join SYNs {got}"
    return check


def signal(name, script=REACT, endpoint=f"{SIGNALLED} dev s2 id 2 signal", announced=f"{SIGNALLED}:5201",
           direction="s2c", joins=1, src=BACKUP):
    """The server announces `endpoint` (ADD_ADDR, as `announced`) once the connection is up; the
    client echoes it and, by `script`, joins it from src (link 2). Linux's first ADD_ADDR
    may arrive before its first DSS: the client stages it and echoes it once Confirmed (M3 spec
    §3.3 rev3)."""
    case = scripted(name, "signal", direction, script)
    case["server"]["pm"] = ["limits set subflows 1 add_addr_accepted 0", f"endpoint add {endpoint}"]
    ip, _, port = announced.rpartition(":")
    ip = ip.strip("[]")
    e = case["expect"]
    e["nstat"].update(MPTcpExtAddAddrTx=(">=", 1), MPTcpExtEchoAdd=(">=", 1),
                      MPTcpExtMPJoinSynRx=joins, MPTcpExtMPJoinAckRx=joins)
    e["pcap"] += [echoed(2, ip, None if " port " not in endpoint else port), joined_only(*[announced] * bool(joins), src=src)]
    e["events"] = ["Connected mptcp=true", f"AddressAnnounced {{ id: 2, addr: {announced} }}"] + ["SubflowUp"] * joins
    return case


def echo_before_repeat(r):
    """At mtun0: the client's echo left before any second ADD_ADDR arrived, so the first ADD_ADDR,
    sent before Linux's first DSS, was the one echoed (M3 spec §3.3 rev3)."""
    adds, echoes = add_addrs(r, "cli", "s2c", "0"), add_addrs(r, "cli", "c2s", "1")
    assert echoes, "no echo"
    assert len(adds) < 2 or echoes[0][0].t < adds[1][0].t, \
        f"echo at {echoes[0][0].t:.3f}, ADD_ADDRs at {[round(g.t, 3) for g, _ in adds]}"


def signal_join():
    """The first ADD_ADDR is used: one ADD_ADDR on the wire, echoed before Linux could repeat it."""
    case = signal("signal-join")
    case["expect"]["nstat"]["MPTcpExtAddAddrTx"] = 1
    case["expect"]["pcap"] += [echo_before_repeat]
    return case


def signal_port_join():
    """A signalled endpoint with its own port: the echo repeats the port and the join goes to it."""
    case = signal("signal-port-join", endpoint=f"{SIGNALLED} dev s2 id 2 signal port 10100",
                  announced=f"{SIGNALLED}:10100")
    case["expect"]["nstat"]["MPTcpExtMPJoinPortSynRx"] = 1
    return case


def signal_unused():
    """No join reaction: the announcement is echoed and nothing else happens."""
    return signal("signal-unused", script="", joins=0)


def one_attempt(dst):
    """At mtun0: a single join attempt to dst (SYN retransmissions keep its source port and ISN)
    before any later ADD_ADDR from the server (a refresh, M3 spec §3.3)."""
    def check(r):
        syns = [g for g in join_syns(r) if f"{g.dst}:{g.dport}" == dst]
        assert syns, f"no join SYN to {dst}"
        refresh = min([g.t for g, _ in add_addrs(r, "cli", "s2c", "0") if g.t > syns[0].t], default=float("inf"))
        attempts = {(g.sport, g.seq) for g in syns if g.t < refresh}
        assert len(attempts) == 1, f"join attempts to {dst} before a refresh: {sorted(attempts)}"
    return check


def signal_unreachable():
    """The server's own kernel refuses SYNs to the signalled address with a TCP RST, so the join
    to it fails and the address is marked failed: no new attempt until a refresh."""
    case = signal("signal-unreachable", joins=0)
    case["server"]["setup"] = [f"iptables -A INPUT -d {SIGNALLED} -p tcp --syn -j REJECT --reject-with tcp-reset"]
    e = case["expect"]
    e["pcap"] = [echoed(2, SIGNALLED), one_attempt(f"{SIGNALLED}:5201")]
    e["events"] += ["SubflowDown SubflowId(1) Reset rst=none"]
    return case


# The first ADD_ADDR echo after DSS12 (kind 30, subtype 3, E=1; any length) leaving mtun0, read
# at TCP offset 32 behind the IP header.
ECHO_AFTER_DSS12 = "-i mtun0 -p tcp -m u32 --u32 0>>22&0x3C@32&0xFF00FF00=0x1E003100"


def echo_redone(r):
    """The first echo left the client (mtun0) but never reached the server; Linux announced again
    after it, and a later echo reached the server."""
    sent, got = add_addrs(r, "cli", "c2s", "1"), add_addrs(r, "srv", "c2s", "1")
    assert len(sent) >= 2, f"{len(sent)} echoes sent"
    first = sent[0][0]
    key = lambda g: (g.flow, g.seq, g.ack)
    assert key(first) not in {key(g) for g, _ in got}, "the first echo reached the server"
    again = [g for g, _ in add_addrs(r, "srv", "s2c", "0") if g.t > first.t]
    assert again, "no ADD_ADDR after the dropped echo"
    assert any(g.t > again[0].t for g, _ in got), "no echo of the repeated ADD_ADDR reached the server"


def echo_dropped():
    """The first echo is dropped between mtun0 and the veth (`drop_once`); with add_addr_timeout=2
    Linux re-announces (probe `add_addr_retransmit_without_echo`) and a second echo follows. The
    repeated announcement is a refresh: `AddressAnnounced` again, and the driver does not join a
    second time to an address it has an open subflow to."""
    case = signal("echo-dropped")
    case["server"]["sysctl"] = ["net.mptcp.add_addr_timeout=2"]
    case["drop_once"] = ECHO_AFTER_DSS12
    e = case["expect"]
    e["pcap"] += [echo_redone]
    e["events"] = ["Connected mptcp=true"] + [f"AddressAnnounced {{ id: 2, addr: {SIGNALLED}:5201 }}"] * 2
    return case


def capable_c1(r):
    """At mtun0: the MP_CAPABLE SYN/ACK has C=1."""
    flags = [o.get("tcp.options.mptcp.nomoresubflows.flag") for g, o in mptcp_with(r, "cli", "s2c", "0")
             if g.flags & 0x12 == 0x12]
    assert flags == ["1"], f"SYN/ACK C flags {flags}"


def c1_alternate_port():
    """`allow_join_initial_addr_port=0` (C=1, probe `c1_from_sysctl`): the server signals its
    initial IP with another port; the client joins that and never the initial pair."""
    case = signal("c1-alternate-port", endpoint="10.0.1.2 dev s1 id 2 signal port 10100", announced="10.0.1.2:10100")
    case["server"]["sysctl"] = ["net.mptcp.allow_join_initial_addr_port=0"]
    e = case["expect"]
    e["nstat"]["MPTcpExtMPJoinPortSynRx"] = 1
    e["pcap"] += [capable_c1]
    return case


def removed_signal(r):
    """At mtun0: Linux's REMOVE_ADDR id 2 reached the client, and no join SYN went to the removed
    address after it."""
    rms = [g for g, o in mptcp_with(r, "cli", "s2c", "4") if o.get("tcp.options.mptcp.addrid") == "2"]
    assert rms, "no REMOVE_ADDR id 2 at mtun0"
    late = [g for g in join_syns(r) if g.dst == SIGNALLED and g.t > rms[0].t]
    assert not late, f"join SYNs to {SIGNALLED} after REMOVE_ADDR: {[(g.t, g.sport) for g in late]}"


def server_remove_signal():
    """`endpoint delete` of the signalled address 1 s after the join to it is up: observable
    assertions only (amendment §5.6). REMOVE_ADDR reaches the client, `AddressRemoved` is
    emitted, the joined subflow ends, the transfer completes on the initial subflow, and no join
    goes to the removed address afterwards."""
    case = signal("server-remove-signal")
    case["server"]["timed"] = [("SubflowUp:1", 1000, "ip mptcp endpoint delete id 2")]
    e = case["expect"]
    e["nstat"]["MPTcpExtRmAddrTx"] = (">=", 1)
    e["pcap"] = [echoed(2, SIGNALLED), joined_only(f"{SIGNALLED}:5201"), removed_signal]
    e["events"] += ["AddressRemoved { id: 2 }", "SubflowDown SubflowId(1)"]
    return case


def synack_backup(r):
    """At mtun0: the SYN/ACK of the join to the signalled address carries B=1."""
    bits = [o.get("tcp.options.mptcp.backup.flag") for g, o in mptcp_with(r, "cli", "s2c", "1")
            if g.flags & 0x12 == 0x12 and g.src == SIGNALLED]
    assert bits == ["1"], f"join SYN/ACK B bits {bits}"


def signal_backup_failover():
    """The server signals its address as a backup endpoint; the client joins it on announcement,
    and Linux's join SYN/ACK asks for backup (B=1, M3 spec §3.3). The client sends no new data on
    it while the initial path is usable, then carries the transfer on it while link 1 is down."""
    case = failover("signal-backup-failover", "link_failure", "c2s", REACT, BACKUP,
                    [no_new_on_backup("c2s", before_window=True), synack_backup, echoed(2, SIGNALLED)])
    case["server"]["pm"] = ["limits set subflows 1 add_addr_accepted 0", f"endpoint add {SIGNALLED} dev s2 id 2 signal backup"]
    e = case["expect"]
    e["nstat"].update(MPTcpExtAddAddrTx=(">=", 1), MPTcpExtEchoAdd=(">=", 1))
    e["events"] = ["Connected mptcp=true", f"AddressAnnounced {{ id: 2, addr: {SIGNALLED}:5201 }}", "SubflowUp"]
    return case


V6_SERVER = "[dead:beef:1::2]:5201"


def v6_two_paths():
    """IPv6 only (amendment §5.4): a v6 server; the initial subflow from fd00:91::2 on link 1 and a
    join from fd00:92::2 on link 2, both carrying new data in both directions."""
    cips = ["fd00:91::2", "fd00:92::2"]
    case = joins("v6-two-paths", 1, "bidi")
    case["group"] = "ipv6"
    case["server"]["family"] = "v6"
    case["client"].update(local=cips[0], remote=V6_SERVER, args=["--join", cips[1]])
    case["expect"]["pcap"] = [subflows(*cips), fin_fin_no_rst]
    return case


def v4_initial_v6_join():
    """Mixed families through the dual-stack server (amendment §5.4): the initial subflow is IPv4,
    the server announces its IPv6 address on link 2 and the client joins it from fd00:92::2; both
    subflows carry new data in both directions."""
    v6 = "fd00:92::2"
    case = signal("v4-initial-v6-join", script=f"on announced join {v6}", endpoint="dead:beef:2::2 dev s2 id 2 signal",
                  announced="[dead:beef:2::2]:5201", direction="bidi", src=v6)
    case["group"] = "ipv6"
    case["server"]["family"] = "dual"
    case["expect"]["pcap"] += [subflows(PRIMARY, v6)]
    return case


def v6_initial_v4_join():
    """The mirror (amendment §5.4): the initial subflow is IPv6 from fd00:91::2, the join IPv4 from
    10.0.92.2 to the server's IPv4 address; both carry new data in both directions."""
    case = scripted("v6-initial-v4-join", "ipv6", "bidi", JOIN)
    case["server"]["family"] = "dual"
    case["client"].update(local="fd00:91::2", remote=V6_SERVER)
    case["expect"]["pcap"] += [subflows("fd00:91::2", BACKUP)]
    return case


def join_attempts(r, cip):
    """The join attempts from cip at mtun0, in order: each one's SYNs (retransmissions keep the
    source port and ISN)."""
    syns = [g for g in join_syns(r) if g.src == cip]
    keys = list(dict.fromkeys((g.sport, g.seq) for g in syns))
    return [[g for g in syns if (g.sport, g.seq) == k] for k in keys]


def join_refused(cip, synack, reason=None):
    """At mtun0: one join attempt from cip, answered by a server RST, after a SYN/ACK if synack; the
    RST carries MP_TCPRST reason/T0 if reason, else no MPTCP option."""
    def check(r):
        tries = join_attempts(r, cip)
        assert len(tries) == 1, f"{len(tries)} join attempts from {cip}"
        flow = tries[0][0].flow
        back = [g for g in r.segs if g.point == "cli" and g.flow == flow and g.direction == "s2c"]
        assert any(g.flags & 0x12 == 0x12 for g in back) == synack, f"SYN/ACK from the server: {not synack}"
        rsts = [[(o["tcp.options.mptcp.subtype"], o.get("tcp.options.mptcp.rst_reason"), o.get("tcp.options.mptcp.flag_T.flag"))
                 for o in g.mptcp] for g in back if g.flags & 0x04]
        assert rsts == [[("8", reason, "0")] if reason else []], f"server RSTs {rsts}"
    return check


def refused_case(name, script, pm_subflows, cips, refused, events):
    """The initial subflow and joins by `script` under `limits set subflows pm_subflows`; the joins
    from `refused` never come up, and the transfer completes on cips' subflows."""
    case = scripted(name, "subflows", "c2s", script, send_rate="8")
    case["server"]["pm"] = [f"limits set subflows {pm_subflows} add_addr_accepted 0"]
    e = case["expect"]
    e["refused"] = refused
    e["nstat"]["MPTcpExtMPJoinAckRx"] = len(cips) - 1
    e["pcap"] = [subflows(*cips, refused=refused), fin_fin_no_rst]
    e["events"] = ["Connected mptcp=true", *events]
    return case


def join_refused_by_server_limit():
    """`limits set subflows 0`: Linux takes the join's SYN, answers it and refuses the third ACK
    with MP_TCPRST 0x03 (probe `refused_join_rst_reason`). The client's own sending (c2s) stays on
    the initial subflow and completes."""
    case = refused_case("join-refused-by-server-limit", JOIN, 0, (PRIMARY,), [BACKUP],
                        ["SubflowDown SubflowId(1) Reset rst=0x03/T0"])
    e = case["expect"]
    e["nstat"].update(MPTcpExtMPJoinSynRx=1, MPTcpExtMPJoinRejected=1)
    e["pcap"] += [join_refused(BACKUP, True, "0x03")]
    return case


THIRD = "10.0.93.2"


def pm_limit_one_of_two_joins():
    """`limits set subflows 1`: of two joins, the second, made once the first is up, is refused;
    the transfer completes on the initial subflow and the first join."""
    script = f"{JOIN}\nat SubflowUp:1 +500 join {THIRD} 10.0.1.2:5201"
    case = refused_case("pm-limit-one-of-two-joins", script, 1, (PRIMARY, BACKUP), [THIRD],
                        ["SubflowUp SubflowId(1)", "SubflowDown SubflowId(2) Reset rst=0x03/T0"])
    e = case["expect"]
    e["nstat"].update(MPTcpExtMPJoinSynRx=2, MPTcpExtMPJoinRejected=1)
    e["pcap"] += [join_refused(THIRD, True, "0x03")]
    return case


def join_to_closed_port():
    """A join to a server port nothing listens on: the kernel answers the SYN with a plain RST,
    which ends the join (`SubflowDown { Reset }`, no MP_TCPRST); Linux's MPTCP never sees it."""
    case = refused_case("join-to-closed-port", f"at Connected +0 join {BACKUP} 10.0.1.2:5202", 2, (PRIMARY,),
                        [BACKUP], ["SubflowDown SubflowId(1) Reset rst=none"])
    e = case["expect"]
    e["nstat"].update(MPTcpExtMPJoinSynRx=0)
    e["pcap"] += [join_refused(BACKUP, False)]
    return case


def join_unanswered(cip):
    """At mtun0: one join attempt from cip, retransmitted with backoff and never answered; it ends
    at the SYN's R2 (3 min, RFC 9293 MUST-23) with `SubflowDown { Timeout }`."""
    def check(r):
        tries = join_attempts(r, cip)
        assert len(tries) == 1, f"{len(tries)} join attempts from {cip}"
        syns = tries[0]
        gaps = [round(b.t - a.t) for a, b in zip(syns, syns[1:])]
        assert len(syns) >= 6 and gaps == sorted(gaps), f"SYN retransmission gaps {gaps}"
        assert not any(g.flow == syns[0].flow and g.direction == "s2c" for g in r.segs), "answered"
        down = [e for e in r.events if e.startswith("SubflowDown SubflowId(1) Timeout")]
        t = float(down[0].rsplit("+", 1)[1].rstrip("s")) if down else None
        assert t is not None and 180 <= t < 185, f"join timeout at {t} s after Connected"
    return check


def join_syn_dropped():
    """Link 2 drops everything from Connected for 185 s; the join from it, made 1 s later, gets no
    answer and ends at its R2 while the transfer goes on over the initial subflow (1 Mbit/s for
    190 s). Not in the CI subset: it runs through the 3-minute SYN R2."""
    case = refused_case("join-syn-dropped", f"at Connected +1000 join {BACKUP} 10.0.1.2:5201", 2, (PRIMARY,),
                        [BACKUP], ["SubflowDown SubflowId(1) Timeout rst=none"])
    case["client"].update(send_secs=190, send_rate="1")
    case["fail"] = [(2, "Connected", 0, 185)]
    case["expect"]["nstat"].update(MPTcpExtMPJoinSynRx=0)
    case["expect"]["pcap"] += [join_unanswered(BACKUP)]
    case.update(watchdog_s=260, ci=False)
    return case


def rejoined(cip, rid):
    """At mtun0: two join attempts from cip, both MP_JOIN SYNs with address id rid (the IP keeps its
    id, M3 spec §4.1), the second one carrying new data."""
    def check(r):
        tries = join_attempts(r, cip)
        assert len(tries) == 2, f"{len(tries)} join attempts from {cip}"
        ids = [{o.get("tcp.options.mptcp.addrid") for o in g.mptcp} for t in tries for g in t]
        assert all(i == {str(rid)} for i in ids), f"join SYN address ids {ids}"
        flow = tries[1][0].flow
        assert sum(g.new_bytes for g in r.segs if g.flow == flow and g.direction == "c2s"), "no new data on the rejoin"
    return check


def remove_addrs(*want):
    """At mtun0: the client's REMOVE_ADDRs, in order, as (carrier, address id)."""
    def check(r):
        rms = [(g.src, o.get("tcp.options.mptcp.addrid")) for g, o in mptcp_with(r, "cli", "c2s", "4")]
        assert rms == [(c, str(i)) for c, i in want], f"REMOVE_ADDR {rms}"
    return check


def link_down_up_rejoin():
    """Break-before-make (M3 spec §4.1, §4.3): link 2 goes away (`remove-address`), then link 1, so
    the initial subflow ends as the last one (`SubflowDown` for it, the no-subflow wait); 1 s after
    that event the policy rejoins from link 2's IP, which keeps its address id 1, and the transfer
    completes on the new subflow. REMOVE_ADDR 1 goes on the initial subflow; REMOVE_ADDR 0, with
    no subflow left to carry it, on the rejoined one."""
    script = "\n".join([JOIN, f"at SubflowUp:1 +1000 remove-address {BACKUP} label=a",
                        f"after a +1000 remove-address {PRIMARY}", f"at SubflowDown:0 +1000 join {BACKUP} 10.0.1.2:5201"])
    case = scripted("link-down-up-rejoin", "re-establishment", "c2s", script, send_secs=7, send_rate="8")
    e = case["expect"]
    e["reset"] = [BACKUP, PRIMARY]
    e["nstat"].update(MPTcpExtMPJoinSynRx=2, MPTcpExtMPJoinAckRx=2, MPTcpExtRmAddr=2, MPTcpExtMPRstRx=2)
    e["pcap"] += [rejoined(BACKUP, 1), remove_addrs((PRIMARY, 1), (BACKUP, 0))]
    e["events"] += ["SubflowDown SubflowId(1) Reset rst=none", "SubflowDown SubflowId(0) Reset rst=none",
                    "SubflowUp SubflowId(2)"]
    return case


CASES = [
    joins("no-join", 0, "c2s"),
    joins("one-join", 1, "s2c"),
    joins("two-joins", 2, "bidi"),
    refused_join(),
    join_refused_by_server_limit(),
    join_syn_dropped(),
    join_to_closed_port(),
    pm_limit_one_of_two_joins(),
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
    remove_address("client-remove-joined", BACKUP, PRIMARY, 1),
    remove_address("client-remove-id0", PRIMARY, BACKUP, 0),
    make_before_break(),
    link_down_up_rejoin(),
    signal_join(),
    signal_port_join(),
    signal_unused(),
    signal_unreachable(),
    echo_dropped(),
    c1_alternate_port(),
    server_remove_signal(),
    signal_backup_failover(),
    v6_two_paths(),
    v4_initial_v6_join(),
    v6_initial_v4_join(),
]
