#!/usr/bin/env python3
"""Assert wire acceptance, using raw (not Wireshark-relative) MPTCP numbers."""
import csv
import io
import hashlib
from pathlib import Path
import re
import subprocess
import sys

# c2s/s2c: expected byte count for that direction, or "any" (timed cases; the logs say how many).
scenario, directory, want_c2s, want_s2c = sys.argv[1:]
out = Path(directory)
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
m2 = scenario.startswith("m2-")
# Client addresses: M2 has the initial subflow from 10.0.9.2 (path A) and a join from 10.0.8.2 (B).
cips = {"10.0.9.2", "10.0.8.2"} if m2 else {"10.0.8.2" if scenario == "base-b" else "10.0.9.2"}
SRV = "10.0.1.2"
fields = ["frame.time_epoch", "ip.src", "tcp.seq_raw", "tcp.ack_raw", "tcp.len", "tcp.flags.syn", "tcp.flags.fin", "tcp.flags.reset", "tcp.window_size_value", "tcp.options.mptcp.subtype", "tcp.options.mptcp.version", "tcp.options.mptcp.datalvllen", "tcp.options.mptcp.datafin.flag", "tcp.options.mptcp.rawdataseqno", "tcp.options.mptcp.rawdataack", "tcp.options.mptcp.dataack8.flag", "tcp.options.mptcp.dseqn8.flag", "tcp.options.mptcp.sendkey", "tcp.flags.ack", "ip.dst", "tcp.srcport", "tcp.dstport"]
def capture(name):
    cmd = ["tshark", "-r", str(out / name), "-Y", "tcp", "-T", "fields", "-E", "separator=\t", "-E", "occurrence=f"]
    for f in fields:
        cmd += ["-e", f]
    rows = list(csv.reader(io.StringIO(subprocess.check_output(cmd, text=True)), delimiter="\t"))
    return [[{"True": "1", "False": "0"}.get(v, v) for v in r] for r in rows]
def count(name, flt):
    return len(subprocess.check_output(["tshark", "-r", str(out / name), "-Y", flt, "-T", "fields", "-e", "frame.number"], text=True).split())
# M2: both legs, as seen by the server (a1, b1), in time order.
rows = capture("server.pcap") + (capture("server-b.pcap") if m2 else [])
rows.sort(key=lambda r: float(r[0]))
assert rows, "empty pcap"
flow = lambda r: frozenset([(r[1], r[20]), (r[19], r[21])])
rsts = [r for r in rows if r[7] == "1"]
no_rst = "no RST"
if scenario.startswith("m2-blackhole-"):
    # The blackholed subflow keeps retransmitting its own stranded TCP data after its ranges
    # were reinjected and DATA_ACKed (RFC 8684 L1536-1540); if that arrives after Linux closed
    # the subflow, Linux answers RST. Allowed only there, once both DATA_FINs are on the wire.
    hip = "10.0.9.2" if scenario.endswith("-a") else "10.0.8.2"
    closed = max(min((float(r[0]) for r in rows if r[1] in side and r[12] == "1"), default=float("inf")) for side in [cips, {SRV}])
    reset = {flow(r) for r in rsts}
    rsts = [r for r in rsts if hip not in {r[1], r[19]} or float(r[0]) < closed]
    if reset:
        no_rst = f"no RST except after close on the blackholed subflow {[sorted(f) for f in reset]}"
assert not rsts, "RST present"
for side in [cips, {SRV}]:
    assert any(r[1] in side and r[6] == "1" for r in rows), f"missing TCP FIN from {side}"
if m2:
    data = {flow(r) for r in rows if r[4] and int(r[4]) > 0}
    assert len(data) == 2 and {r[1] for r in rows if flow(r) in data} - {SRV} == cips, f"want two data-carrying subflows from {cips}: {data}"
    for f in data - (reset if scenario.startswith("m2-blackhole-") else set()):
        for side in [cips, {SRV}]:
            assert any(flow(r) == f and r[1] in side and r[6] == "1" for r in rows), f"subflow {sorted(f)}: no FIN from {side}"
    join = [r for r in rows if r[9] == "1"]
    assert any(r[1] == "10.0.8.2" and (r[5], r[18]) == ("1", "0") for r in join), "no MP_JOIN SYN"
    assert any(r[1] == SRV and (r[5], r[18]) == ("1", "1") for r in join), "no MP_JOIN SYN/ACK"
    assert any(r[1] == "10.0.8.2" and r[5] == "0" for r in join), "no MP_JOIN third ACK"
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
    assert "Connected mptcp=true" in client
    assert any(r[10] == "1" for r in rows), "MPTCP v1 missing"
    if scenario == "dataack-strip":
        assert client.count("event: FellBack") == 1, "fallback event count"
        assert sum(r[11] == "0" and r[9] == "2" for r in rows) == 1, "infinite mapping count"
        rules = (out / "server-rules.txt").read_text()
        assert re.search(r"\[[1-9][0-9]*:[0-9]+\].*TCPOPTSTRIP", rules), "strip rule unused"
    else:
        assert "FellBack" not in client
        for side, n in [(cips, c2s), ({SRV}, s2c)]:
            src = "/".join(sorted(side))
            fins = [r for r in rows if r[1] in side and r[12] == "1"]
            assert fins, f"missing DATA_FIN from {src}"
            # DLL already includes DATA_FIN's sequence-space byte.
            keys = {int(r[17]) for r in rows if r[1] in side and r[17]}
            assert len(keys) == 1, f"ambiguous MP_CAPABLE sender key for {src}"
            digest = hashlib.sha256(keys.pop().to_bytes(8, "big")).digest()
            initial = (int.from_bytes(digest[-8:], "big") + 1) % (1 << 64)
            expected_end = (initial + n + 1) % (1 << 64)
            covered = False
            for fin in fins:
                if fin[16] != "1":
                    continue  # Require an unambiguous 64-bit DSN/ACK witness.
                end = (int(fin[13]) + int(fin[11])) % (1 << 64)
                assert int(fin[11]) > 0 and end == expected_end, (
                    f"DATA_FIN from {src} must end at IDSN+1+{n}+1"
                )
                covered |= any(
                    a[1] not in side and a[14]
                    and float(a[0]) >= float(fin[0])
                    # The FIN's end is fixed by the 64-bit DSN witness above; Linux may DATA_ACK it with 32 bits.
                    and int(a[14]) == expected_end % (1 << (64 if a[15] == "1" else 32))
                    for a in rows
                )
            assert covered, f"DATA_FIN from {src} not DATA_ACKed"
if scenario.startswith("m2-blackhole-"):
    joins = dict(re.findall(r"^join: (SubflowId\(\d+\)) local (\S+)", client, re.M))
    holed = "SubflowId(0)" if scenario.endswith("-a") else next(i for i, ip in joins.items() if ip == "10.0.8.2")
    stale = set(re.findall(r"^event: SubflowStale (SubflowId\(\d+\))", client, re.M))
    # c2s: the client sends, so its RTOs must mark exactly the blackholed subflow Stale.
    # s2c: the client only ACKs; a Stale may not occur, but never on the other subflow.
    assert stale == {holed} if want_s2c == "0" else stale <= {holed}, f"Stale {stale}, blackholed {holed}"
    rules = (out / "client-rules.txt").read_text()
    assert re.search(r"\[[1-9][0-9]*:[0-9]+\] -A BLACKHOLE -j DROP", rules), "blackhole dropped nothing"
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
print(f"PASS {scenario}: {c2s} bytes c2s, {s2c} bytes s2c, EOF, FIN/FIN, {no_rst}")
