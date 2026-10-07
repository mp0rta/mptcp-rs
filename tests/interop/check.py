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
    assert want == "any" or got == int(want), f"{name}: {got} bytes, expected {want}"
cip = "10.0.8.2" if scenario == "base-b" else "10.0.9.2"
fields = ["frame.time_epoch", "ip.src", "tcp.seq_raw", "tcp.ack_raw", "tcp.len", "tcp.flags.syn", "tcp.flags.fin", "tcp.flags.reset", "tcp.window_size_value", "tcp.options.mptcp.subtype", "tcp.options.mptcp.version", "tcp.options.mptcp.datalvllen", "tcp.options.mptcp.datafin.flag", "tcp.options.mptcp.rawdataseqno", "tcp.options.mptcp.rawdataack", "tcp.options.mptcp.dataack8.flag", "tcp.options.mptcp.dseqn8.flag", "tcp.options.mptcp.sendkey"]
def capture(name):
    cmd = ["tshark", "-r", str(out / name), "-Y", "tcp", "-T", "fields", "-E", "separator=\t", "-E", "occurrence=f"]
    for f in fields:
        cmd += ["-e", f]
    rows = list(csv.reader(io.StringIO(subprocess.check_output(cmd, text=True)), delimiter="\t"))
    return [[{"True": "1", "False": "0"}.get(v, v) for v in r] for r in rows]
rows = capture("server.pcap")
assert rows, "empty pcap"
assert not any(r[7] == "1" for r in rows), "RST present"
for src in [cip, "10.0.1.2"]:
    assert any(r[1] == src and r[6] == "1" for r in rows), f"missing TCP FIN from {src}"
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
        for src, n in [(cip, c2s), ("10.0.1.2", s2c)]:
            fins = [r for r in rows if r[1] == src and r[12] == "1"]
            assert fins, f"missing DATA_FIN from {src}"
            # DLL already includes DATA_FIN's sequence-space byte.
            keys = {int(r[17]) for r in rows if r[1] == src and r[17]}
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
                    a[1] != src and a[14]
                    and float(a[0]) >= float(fin[0])
                    # The FIN's end is fixed by the 64-bit DSN witness above; Linux may DATA_ACK it with 32 bits.
                    and int(a[14]) == expected_end % (1 << (64 if a[15] == "1" else 32))
                    for a in rows
                )
            assert covered, f"DATA_FIN from {src} not DATA_ACKed"
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
print(f"PASS {scenario}: {c2s} bytes c2s, {s2c} bytes s2c, EOF, FIN/FIN, no RST")
