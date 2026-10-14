#!/usr/bin/env python3
"""Assert wire acceptance, using raw (not Wireshark-relative) MPTCP numbers."""
import argparse
import bisect
import csv
import io
import hashlib
from pathlib import Path
import re
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from endpoints import Packet, check_inversion, csum_checks, csum_fail_checks, csum_options, csum_want, data_ack_advances, delivery_summary, endpoints, failed_mapping, infinite_mapping_checks, flag, mp_fail_bounds, mp_fail_dsn, mptcp_options, removed_flow_exempt, two_subflows  # noqa: E402

# c2s/s2c: expected byte count for that direction, or "any" (timed cases; the logs say how many).
# logs-only (the kernel comparison bench): the byte counts below, no wire checks.
# --client/--server: which end is Linux (kernel) and which is mptcp-rs (run.sh's INTEROP_*).
ap = argparse.ArgumentParser()
for name in ["scenario", "directory", "want_c2s", "want_s2c"]:
    ap.add_argument(name)
ap.add_argument("mode", nargs="?", choices=["logs-only"])
ap.add_argument("--client", choices=["kernel", "mptcp-rs"], default="mptcp-rs")
ap.add_argument("--server", choices=["kernel", "mptcp-rs"], default="kernel")
# --csum: run.sh's INTEROP_CSUM, when set: check the checksum negotiation on the wire.
ap.add_argument("--csum", choices=["on:on", "on:off", "off:on", "off:off"])
args = ap.parse_args()
scenario, want_c2s, want_s2c, mode = args.scenario, args.want_c2s, args.want_s2c, args.mode
out = Path(args.directory)
client = (out / "client.log").read_text()
server = (out / "server.log").read_text()
m = re.search(r"^ok: sent (\d+) bytes, verified (\d+) bytes, eof=true$", client, re.M)
assert m, client
c2s, s2c = int(m[1]), int(m[2])  # client sent / client verified
m = re.search(r"^server ok: received (\d+) sent (\d+) from \S+ eof=true$", server, re.M)
assert m, server
assert (int(m[1]), int(m[2])) == (c2s, s2c), f"sender/receiver byte counts differ: client sent {c2s} server got {m[1]}, server sent {m[2]} client got {s2c}"
for name, got, want in [("c2s", c2s, want_c2s), ("s2c", s2c, want_s2c)]:
    assert got > 0 if want == "any" else got == int(want), f"{name}: {got} bytes, expected {want}"
# m2-hetero still reads its pcaps in logs-only mode (the kernel-to-kernel baseline).
if mode and scenario != "m2-hetero":
    print(f"PASS {scenario} (logs only)")
    sys.exit(0)
m2 = two_subflows(scenario)
# M2: the initial subflow on path A and a join from JOIN on path B.
SRV, cips, JOIN = endpoints(scenario, args.client, args.server)
fields = ["frame.time_epoch", "ip.src", "tcp.seq_raw", "tcp.ack_raw", "tcp.len", "tcp.flags.syn", "tcp.flags.fin", "tcp.flags.reset", "tcp.window_size_value", "tcp.options.mptcp.subtype", "tcp.options.mptcp.version", "tcp.options.mptcp.datalvllen", "tcp.options.mptcp.datafin.flag", "tcp.options.mptcp.rawdataseqno", "tcp.options.mptcp.rawdataack", "tcp.options.mptcp.dataack8.flag", "tcp.options.mptcp.dseqn8.flag", "tcp.options.mptcp.sendkey", "tcp.flags.ack", "ip.dst", "tcp.srcport", "tcp.dstport", "tcp.options.mptcp.subflowseqno"]
def capture(name):
    cmd = ["tshark", "-r", str(out / name), "-Y", "tcp", "-T", "fields", "-E", "separator=\t", "-E", "occurrence=f"]
    for f in fields:
        cmd += ["-e", f]
    rows = list(csv.reader(io.StringIO(subprocess.check_output(cmd, text=True)), delimiter="\t"))
    return [[{"True": "1", "False": "0"}.get(v, v) for v in r] for r in rows]
def count(name, flt):
    return len(subprocess.check_output(["tshark", "-r", str(out / name), "-Y", flt, "-T", "fields", "-e", "frame.number"], text=True).split())
# M2: both legs, as seen by the server (a1, b1), in time order; the mptcp-rs server's own TUN
# sees every subflow.
pcaps = ["server-tun.pcap"] if args.server == "mptcp-rs" else ["server.pcap"] + (["server-b.pcap"] if m2 else [])
rows = [r for name in pcaps for r in capture(name)]
rows.sort(key=lambda r: float(r[0]))
assert rows, "empty pcap"
flow = lambda r: frozenset([(r[1], r[20]), (r[19], r[21])])
def first_dsn(side):
    """IDSN + 1 of `side`, from its MP_CAPABLE sender key."""
    keys = {int(r[17]) for r in rows if r[1] in side and r[17]}
    assert len(keys) == 1, f"ambiguous MP_CAPABLE sender key for {'/'.join(sorted(side))}"
    digest = hashlib.sha256(keys.pop().to_bytes(8, "big")).digest()
    return (int.from_bytes(digest[-8:], "big") + 1) % (1 << 64)
def data_fin_acked(side, n):
    """Time of the first DATA_ACK covering `side`'s DATA_FIN (which must end at IDSN+1+n+1)."""
    src = "/".join(sorted(side))
    fins = [r for r in rows if r[1] in side and r[12] == "1"]
    assert fins, f"missing DATA_FIN from {src}"
    # DLL already includes DATA_FIN's sequence-space byte.
    initial = first_dsn(side)
    expected_end = (initial + n + 1) % (1 << 64)
    acked = []
    for fin in fins:
        if fin[16] != "1":
            continue  # Require an unambiguous 64-bit DSN/ACK witness.
        end = (int(fin[13]) + int(fin[11])) % (1 << 64)
        assert int(fin[11]) > 0 and end == expected_end, (
            f"DATA_FIN from {src} must end at IDSN+1+{n}+1"
        )
        acked += [
            float(a[0]) for a in rows
            if a[1] not in side and a[14]
            and float(a[0]) >= float(fin[0])
            # The FIN's end is fixed by the 64-bit DSN witness above; Linux may DATA_ACK it with 32 bits.
            and int(a[14]) == expected_end % (1 << (64 if a[15] == "1" else 32))
        ]
    assert acked, f"DATA_FIN from {src} not DATA_ACKed"
    return min(acked)
def options(flt):
    """The server-side Packets matching `flt`, each MPTCP option read on its own (DSS and MP_FAIL
    share rawdataseqno)."""
    names = ["frame.time_epoch", "tcp.flags.ack", "ip.src", "tcp.srcport", "ip.dst", "tcp.dstport", "tcp.flags.reset", "tcp.options.mptcp.subtype", "tcp.options.mptcp.dseqnpresent.flag", "tcp.options.mptcp.dseqn8.flag", "tcp.options.mptcp.rawdataseqno", "tcp.options.mptcp.datalvllen", "tcp.options.mptcp.rst_reason", "tcp.seq_raw", "tcp.len", "tcp.ack_raw"]
    pkts = []
    for name in pcaps:
        cmd = ["tshark", "-r", str(out / name), "-Y", flt, "-T", "fields", "-E", "separator=\t", "-E", "occurrence=a", "-E", "aggregator=,"]
        for f in names:
            cmd += ["-e", f]
        for v in csv.reader(io.StringIO(subprocess.check_output(cmd, text=True)), delimiter="\t"):
            pkts.append(Packet(float(v[0]), v[2], frozenset([(v[2], v[3]), (v[4], v[5])]), flag(v[6]), flag(v[1]), mptcp_options(*v[7:13]), *(int(x or 0) for x in v[13:])))
    return pkts
if scenario == "m2-hetero":
    # Delivery over time: the receiver's DATA_ACK advances as the server's links see them.
    rx, tx = (cips, {SRV}) if want_c2s == "0" else ({SRV}, cips)
    adv = data_ack_advances([(float(r[0]), int(r[14]), r[15] == "1") for r in rows if r[1] in rx and r[14]], first_dsn(tx))
    gap, series = delivery_summary(adv)
    print(f"hetero: longest_dataack_gap_s={gap:.3f} mbps_per_s={series}")
    # A stall: 2 s or more with no delivered data (mptcp_net-next#635).
    assert gap < 2.0, f"delivery stalled {gap:.3f} s"
if mode:
    print(f"PASS {scenario} (logs only)")
    sys.exit(0)
rsts = [r for r in rows if r[7] == "1"]
no_rst, srv_reset, cli_reset = "no RST", set(), set()
csum_exempt = set()
if scenario.startswith("csum-fail"):
    # The data sender, and the receiver whose verifier saw the rewritten octet.
    sender, receiver = (cips, {SRV}) if want_s2c == "0" else ({SRV}, cips)
    pkts = options("tcp.flags.reset == 1 || tcp.options.mptcp.subtype == 6 || tcp.options.mptcp.datalvllen == 0")
    csum_exempt = csum_fail_checks(scenario, pkts, SRV, JOIN)
    if csum_exempt:
        # The answers: csum_fail_checks's bare RSTs after the reset.
        n = sum(p.rst and not p.opts and p.flow in csum_exempt for p in pkts)
        no_rst = f"no RST except the MP_FAIL + MP_TCPRST 6 reset on {[sorted(f) for f in csum_exempt]} and its {n} answers to segments in flight"
    rsts = [r for r in rsts if flow(r) not in csum_exempt]
    inverted = [int(x) for x in re.findall(r"^inverted at (\d+)$", client + server, re.M)]
    if scenario == "csum-fail1":
        # The receiver's MP_FAIL names the failed mapping by its first DSN.
        fail = mp_fail_dsn(pkts, receiver)
        mp_fail_bounds(pkts, {SRV} if args.server == "mptcp-rs" else cips)
        maps = options(f"tcp.options.mptcp.rawdataseqno == {fail} || tcp.options.mptcp.rawdataseqno == {fail % (1 << 32)}")
        start, dll = failed_mapping(fail, maps, sender, first_dsn(sender))
        check_inversion(inverted, start, dll)
        print(f"inverted octet at stream offset {inverted[0]}, in the failed mapping [{start}, {start + dll})")
    else:
        assert not inverted, f"inverted octets at {inverted}"
# m2-remove: the deleted kernel endpoint's subflow may end with a RST and no FIN.
removed = {flow(r) for r in rows if removed_flow_exempt(scenario, args.client, flow(r))}
if any(flow(r) in removed for r in rsts):
    no_rst = f"no RST except {sum(flow(r) in removed for r in rsts)} on the removed subflow {[sorted(f) for f in removed]}"
    rsts = [r for r in rsts if flow(r) not in removed]
if scenario.startswith("m2-blackhole-") and want_s2c == "0":
    # c2s, on the blackholed 4-tuple only, after both DATA_FINs are DATA_ACKed (RFC 8684
    # L1600-1611). The server's RST: the subflow keeps retransmitting its own stranded TCP data
    # after its ranges were reinjected and DATA_ACKed (RFC 8684 L1536-1540); if that arrives
    # after Linux closed the subflow, Linux answers RST; allowed only after the server's FIN on
    # that 4-tuple. The client's RST (ruling R18): strictly after close, only while that
    # 4-tuple still had client TCP data the server had not ACKed.
    hip = "10.0.9.2" if scenario.endswith("-a") else "10.0.8.2"
    closed = max(data_fin_acked(cips, c2s), data_fin_acked({SRV}, s2c))
    before = lambda f, t: [r for r in rows if flow(r) == f and float(r[0]) < t]
    srv_fin = lambda f, t: any(r[1] == SRV and r[6] == "1" for r in before(f, t))
    def outstanding(f, t):
        rs = before(f, t)
        isn = next((int(r[2]) for r in rs if r[1] == hip and r[5] == "1"), None)
        assert isn is not None, f"no client SYN on {sorted(f)}"
        off = lambda x: (x - isn) % (1 << 32)
        snd_max = max((off(int(r[2])) + int(r[4]) for r in rs if r[1] == hip and int(r[4] or 0) > 0), default=0)
        acked = max((off(int(r[3])) for r in rs if r[1] == SRV and r[18] == "1"), default=0)
        return snd_max > acked
    srv_ok = lambda r: r[1] == SRV and r[19] == hip and float(r[0]) >= closed and srv_fin(flow(r), float(r[0]))
    cli_ok = lambda r: r[1] == hip and r[19] == SRV and float(r[0]) > closed and outstanding(flow(r), float(r[0]))
    srv_reset = {flow(r) for r in rsts if srv_ok(r)}
    cli_reset = {flow(r) for r in rsts if cli_ok(r)}
    rsts = [r for r in rsts if not (srv_ok(r) or cli_ok(r))]
    if srv_reset or cli_reset:
        no_rst = f"no RST except after close on the blackholed subflow: server's {[sorted(f) for f in srv_reset]}, client's {[sorted(f) for f in cli_reset]}"
assert not rsts, "RST present"
for side in [cips, {SRV}]:
    assert any(r[1] in side and r[6] == "1" for r in rows), f"missing TCP FIN from {side}"
if m2:
    data = {flow(r) for r in rows if r[4] and int(r[4]) > 0}
    assert len(data) == 2 and {r[1] for r in rows if flow(r) in data} - {SRV} == cips, f"want two data-carrying subflows from {cips}: {data}"
    for f in data:
        # A subflow the client reset after close needs no FIN; one the server reset after close
        # (above) needs only the server's FIN.
        sides = [] if f in cli_reset | removed | csum_exempt else [{SRV}] if f in srv_reset else [cips, {SRV}]
        for side in sides:
            assert any(flow(r) == f and r[1] in side and r[6] == "1" for r in rows), f"subflow {sorted(f)}: no FIN from {side}"
    join = [r for r in rows if r[9] == "1"]
    assert any(r[1] == JOIN and (r[5], r[18]) == ("1", "0") for r in join), "no MP_JOIN SYN"
    assert any(r[1] == SRV and (r[5], r[18]) == ("1", "1") for r in join), "no MP_JOIN SYN/ACK"
    assert any(r[1] == JOIN and r[5] == "0" for r in join), "no MP_JOIN third ACK"
    split = {}  # client endpoint -> [c2s, s2c] payload bytes
    for r in rows:
        if flow(r) in data:
            ends = split.setdefault(next(f"{a}:{p}" for a, p in flow(r) if a != SRV), [0, 0])
            ends[r[1] == SRV] += int(r[4] or 0)
    print(f"subflow payload bytes on the wire incl. retransmissions, [c2s, s2c]: {split}")
if scenario in ["m0", "syn-strip"]:
    assert "Connected mptcp=false" in client
    assert not any(r[9] and r[5] != "1" for r in rows), "MPTCP after SYN fallback"
else:
    # The kernel client prints no events: the mptcp-rs server's Accepted shows MPTCP.
    if args.client == "kernel":
        assert "event: Accepted mptcp=true" in server, "server: no Accepted mptcp=true"
    else:
        assert "Connected mptcp=true" in client
    assert any(r[10] == "1" for r in rows), "MPTCP v1 missing"
    if args.csum:
        flt = "tcp.options.mptcp.subtype == 0 || tcp.options.mptcp.dseqnpresent.flag == 1"
        names = ["tcp.flags.syn", "tcp.flags.ack", "tcp.option_kind", "tcp.option_len", "tcp.options.mptcp.subtype", "tcp.options.mptcp.checksumreq.flags", "tcp.options.mptcp.dataackpresent.flag", "tcp.options.mptcp.dataack8.flag", "tcp.options.mptcp.dseqnpresent.flag", "tcp.options.mptcp.dseqn8.flag"]
        packets = []
        for name in pcaps:
            cmd = ["tshark", "-r", str(out / name), "-Y", flt, "-T", "fields", "-E", "separator=\t", "-E", "occurrence=a", "-E", "aggregator=,"]
            for f in names:
                cmd += ["-e", f]
            for v in csv.reader(io.StringIO(subprocess.check_output(cmd, text=True)), delimiter="\t"):
                packets.append((flag(v[0]), flag(v[1]), *csum_options(*v[2:])))
        print(csum_checks(csum_want(args.csum, args.client, args.server), packets))
    if scenario == "dataack-strip":
        assert client.count("event: FellBack") == 1, "fallback event count"
        # The client's TUN: its own sends, and the server's ACKs in the order they reached it.
        infinite_mapping_checks([(r[1] in cips, int(r[4] or 0), r[9], r[11], r[13], r[22], int(r[2]), int(r[3] or 0)) for r in capture("tun.pcap")])
        rules = (out / "server-rules.txt").read_text()
        assert re.search(r"\[[1-9][0-9]*:[0-9]+\].*TCPOPTSTRIP", rules), "strip rule unused"
    elif scenario == "csum-fail1":
        # After the fallback there are no DATA_ACKs, so no DATA_FIN check.
        assert client.count("event: FellBack") + server.count("event: FellBack") == 1, "fallback event count"
    else:
        assert "FellBack" not in client + server
        for side, n in [(cips, c2s), ({SRV}, s2c)]:
            data_fin_acked(side, n)
if scenario == "m2-remove":
    assert re.search(r"^event: SubflowDown ", server, re.M), "server: no SubflowDown after the endpoint delete"
    assert re.search(r"^event: Closed Normal$", server, re.M), "server: no Closed Normal"
if scenario.startswith("m2-blackhole-"):
    joins = dict(re.findall(r"^join: (SubflowId\(\d+\)) local (\S+)", client, re.M))
    holed = "SubflowId(0)" if scenario.endswith("-a") else next(i for i, ip in joins.items() if ip == "10.0.8.2")
    stale = set(re.findall(r"^event: SubflowStale (SubflowId\(\d+\))", client, re.M))
    # c2s: the client sends, so its RTOs must mark exactly the blackholed subflow Stale.
    # s2c: the client only ACKs; a Stale may not occur, but never on the other subflow.
    assert stale == {holed} if want_s2c == "0" else stale <= {holed}, f"Stale {stale}, blackholed {holed}"
    # Each direction is dropped where it arrives: the client's FORWARD, the server's INPUT.
    for side in ["client", "server"]:
        rules = (out / f"{side}-rules.txt").read_text()
        assert re.search(r"\[[1-9][0-9]*:[0-9]+\] -A BLACKHOLE -j DROP", rules), f"{side} blackhole dropped nothing"
if scenario == "m2-mtu":
    big = "ip.len > 1280 || ip.flags.mf == 1 || ip.frag_offset > 0"
    assert count("server-b.pcap", big) == 0, "packet over 1280 octets or fragment on the B link"
    assert count("tun.pcap", f"ip.addr == 10.0.8.2 && ({big})") == 0, "path B packet over 1280 octets at the TUN"
    for name in ["server.pcap", "server-b.pcap", "client.pcap", "tun.pcap"]:
        assert count(name, "icmp.type == 3 && icmp.code == 4") == 0, f"ICMP fragmentation needed in {name}"
if scenario == "syn-strip":
    rules = (out / "client-rules.txt").read_text()
    assert re.search(r"\[[1-9][0-9]*:[0-9]+\].*TCPOPTSTRIP", rules), "SYN strip rule unused"
if scenario.startswith("zero-"):
    receiver = "10.0.1.2" if scenario == "zero-server" else "10.0.9.2"
    # Observe the lost update before forwarding and compare with receiver-bound traffic.
    wire = rows if receiver == "10.0.1.2" else capture("tun.pcap")
    delivered = capture("tun.pcap") if receiver == "10.0.1.2" else rows
    zeros = [r for r in wire if r[1] == receiver and r[8] == "0"]
    assert zeros, "receive window never closed"
    start = float(zeros[0][0])
    reopened = [r for r in wire if r[1] == receiver and float(r[0]) > start and int(r[8]) > 0]
    assert reopened, "no DATA_ACK/window reopening"
    lost = reopened[0]
    assert lost[14], "first reopening update lacks DATA_ACK"
    drop_time = float(lost[0])
    assert drop_time - start >= 7, "window reopened before the eight-second application pause ended"
    # After losing the update, the sender must probe before it sees another open window.
    replies = [r for r in delivered if r[1] == receiver and float(r[0]) > drop_time and int(r[8]) > 0 and r[14]]
    assert replies, "no delivered DATA_ACK/window response after loss"
    reply = replies[0]
    probes = [r for r in wire if r[1] != receiver and drop_time < float(r[0]) < float(reply[0]) and int(r[4]) <= 1 and r[5] != "1"]
    probes = [p for p in probes if (
        int(p[4]) == 0 and int(p[2]) == (int(lost[3]) - 1) % (1 << 32)
    ) or (
        int(p[4]) == 1 and p[13]
        and (int(lost[14]) - int(p[13])) % (1 << (64 if p[16] == "1" else 32)) <= 1
    )]
    assert probes, "lost reopening update was not recovered by a subsequent sequence-valid probe"
    assert any(float(reply[0]) - float(p[0]) < 1 for p in probes), "window response does not follow probe"
    print(f"zero recovery: receiver={receiver} zero={start} dropped-update={drop_time} probe={probes[0][0]} probe-len={probes[0][4]} DATA_ACK/window-reply={reply[0]}")
    assert any(r[1] != receiver and float(r[0]) > float(reply[0]) and int(r[4]) > 1 for r in wire), "bulk transfer did not resume after probe response"
    rules = (out / "client-rules.txt").read_text()
    assert re.search(r"\[1:[0-9]+\] -A REOPEN -j DROP", rules), "exactly one reopening update must be dropped"
if scenario == "m2-blackhole-b" and want_s2c == "0":
    # M3 spec §2.6: the head-of-line stall while path B is blackholed. DSNs and DATA_ACKs are
    # offsets from the client's IDSN + 1; Linux's 32-bit DATA_ACKs are promoted to 64 bits.
    bh = (out / "blackhole.log").read_text()
    on = float(re.search(r"^drop-on (\S+)", bh, re.M)[1])
    off = float(re.search(r"^drop-off (\S+)", bh, re.M)[1])
    base = first_dsn(cips)
    rel = lambda v: (int(v) - base) % (1 << 64)
    # Cumulative DATA_ACK advances seen by the server: (time, offset).
    acks, cur = [], 0
    for r in rows:
        if r[1] == SRV and r[14]:
            a = rel(r[14]) if r[15] == "1" else cur + ((int(r[14]) - base - cur + (1 << 31)) % (1 << 32) - (1 << 31))
            if a > cur:
                acks.append((float(r[0]), a))
                cur = a
    # The client's mappings, from its TUN: the highest mapped end over time, and each mapping
    # start's first subflow (its original assignment).
    tun = capture("tun.pcap")
    sent, hi, first_on = [], 0, {}
    for r in tun:
        if r[1] in cips and r[13] and int(r[4] or 0) > 0:
            assert r[16] == "1", "the client maps 64-bit DSNs"
            start = rel(r[13])
            end = start + int(r[11])
            first_on.setdefault(start, (r[1], end))
            if end > hi:
                hi = end
                sent.append((float(r[0]), hi))
    sent_t = [t for t, _ in sent]
    outstanding = lambda t, a: (i := bisect.bisect_right(sent_t, t)) > 0 and sent[i - 1][1] > a
    # Primary metric: the longest interval without DATA_ACK advance while data is outstanding,
    # for intervals inside or crossing the blackhole window.
    hol_gap = max((t1 - t0 for (t0, a0), (t1, _) in zip(acks, acks[1:]) if t1 > on and t0 < off and outstanding(t0, a0)), default=0.0)
    # Witness: path A delivers, inside the window, DSNs whose original mapping was on B.
    b_orig = sorted((st, e) for st, (src, e) in first_on.items() if src == "10.0.8.2")
    starts, ends, m = [st for st, _ in b_orig], [], 0
    for _, e in b_orig:
        m = max(m, e)
        ends.append(m)
    from_b = lambda st, e: (i := bisect.bisect_left(starts, e)) > 0 and ends[i - 1] > st
    witness = any(
        on <= float(r[0]) <= off and from_b(rel(r[13]), rel(r[13]) + int(r[11]))
        for r in rows if r[1] == "10.0.9.2" and r[13] and int(r[4] or 0) > 0
    )
    a_sends = [float(r[0]) for r in tun if r[1] == "10.0.9.2" and int(r[4] or 0) > 0]
    send_gap_a = max((t1 - t0 for t0, t1 in zip(a_sends, a_sends[1:]) if t1 > on and t0 < off), default=0.0)
    st = re.search(r"^stats: opp_triggers=(\d+) opp_episodes=(\d+) penalties=(\d+) opp_bytes=(\d+) app_blocked_ms=(\d+)$", client, re.M)
    assert st, "no stats line from the client"
    print(f"hol: hol_gap_s={hol_gap:.3f} witness_ok={int(witness)} send_gap_a_s={send_gap_a:.3f} app_blocked_s={int(st[5]) / 1000:.3f} triggers={st[1]} episodes={st[2]} penalties={st[3]} dup_bytes={st[4]}")
    assert hol_gap <= 1.0, f"HOL stall {hol_gap:.3f} s > 1 s"
    assert witness, "path A carried no DSN originally mapped on B"
print(f"PASS {scenario}: {c2s} bytes c2s, {s2c} bytes s2c, EOF, FIN/FIN, {no_rst}")
