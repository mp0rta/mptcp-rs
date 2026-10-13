#!/usr/bin/env python3
"""Linux kernel MPTCP client for the kernel comparison bench, printing mptcp-rs-tun's lines.
c2s (--send-secs S --expect 0): send the pattern for S seconds, shut down writes, read to EOF.
s2c (--send 0 --expect any): read to the server's EOF, then close. An early SHUT_WR would take
the MPTCP socket out of ESTABLISHED, and Linux then never adds the leg-B subflow.
The kernel path manager adds subflows (run.sh configures the endpoints).
--invert N: exactly N received octets are inverted, each printed as `inverted at OFF`."""
import argparse, socket, sys, time

from pattern import BUF, verify_chunk

ap = argparse.ArgumentParser()
ap.add_argument("--local", required=True)
ap.add_argument("--remote", required=True, help="IP:PORT")
ap.add_argument("--send-secs", type=float)
ap.add_argument("--send", type=int, choices=[0])
ap.add_argument("--expect", required=True, help="0 or 'any'")
ap.add_argument("--verify", choices=["on", "off"], default="on")
ap.add_argument("--invert", type=int, default=0, metavar="N")
a = ap.parse_args()
if (a.send_secs is None) == (a.send is None):
    ap.error("give one of --send-secs or --send 0")

CHUNK = len(BUF) - 251

host, port = a.remote.rsplit(":", 1)
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 262)
s.bind((a.local, 0))
s.connect((host, int(port)))

sent = 0
if a.send_secs:
    deadline = time.monotonic() + a.send_secs
    while time.monotonic() < deadline:
        s.sendall(BUF[sent % 251 : sent % 251 + CHUNK])
        sent += CHUNK
    s.shutdown(socket.SHUT_WR)

got = 0
inverted = []
first = last = None
rbuf = bytearray(262144)
while True:
    n = s.recv_into(rbuf)
    if not n:
        break
    seen = len(inverted)
    if a.verify == "on" and not verify_chunk(got, rbuf[:n], a.invert, inverted):
        print(f"verification mismatch at byte {got}", file=sys.stderr)
        sys.exit(1)
    for off in inverted[seen:]:
        print(f"inverted at {off}", flush=True)
    got += n
    last = time.monotonic()
    first = first or last
    if a.expect != "any" and got > int(a.expect):
        print(f"received {got} bytes, expected {a.expect}", file=sys.stderr)
        sys.exit(1)
s.close()
if a.verify == "on" and len(inverted) != a.invert:
    print(f"{len(inverted)} inverted octets, expected {a.invert}", file=sys.stderr)
    sys.exit(1)
if first:  # receiver-side goodput: first to last received byte
    secs = last - first
    print(f"goodput: {got} bytes in {secs:.3f} s = {got * 8 / max(secs, 1e-9) / 1e6:.1f} Mbit/s")
print(f"ok: sent {sent} bytes, verified {got} bytes, eof=true")
