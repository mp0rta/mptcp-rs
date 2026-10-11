#!/usr/bin/env python3
"""Client-sent data segments on mtun0 (every subflow's egress) and the share tshark marks as
retransmitted. Usage: retrans.py DIR; prints {data_segments, retransmitted, rate} as JSON.
The rate means something for c2s runs only: in s2c the client sends no data."""
import json, subprocess, sys
from pathlib import Path

pcap = Path(sys.argv[1]) / "tun.pcap"
# Client-sent: to the server's port 5201, whichever subflow.
data = "tcp.dstport == 5201 && tcp.len > 0"
def count(flt):
    return len(subprocess.check_output(["tshark", "-r", str(pcap), "-Y", flt, "-T", "fields", "-e", "frame.number"], text=True).split())
segs = count(data)
rtx = count(f"{data} && (tcp.analysis.retransmission || tcp.analysis.fast_retransmission)")
print(json.dumps({"data_segments": segs, "retransmitted": rtx, "rate": rtx / segs if segs else None}))
