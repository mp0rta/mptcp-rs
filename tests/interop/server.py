#!/usr/bin/env python3
"""Linux TCP/MPTCP peer for the interop tests, listening on 10.0.1.2: receive the pattern
(--expect bytes, or until EOF), then send it (--send-bytes, or for --send-secs), then read
until EOF. --bytes sets both counts."""
import argparse, socket, sys, time

ap = argparse.ArgumentParser()
ap.add_argument("--mode", choices=["tcp", "mptcp"], required=True)
ap.add_argument("--port", type=int, required=True)
ap.add_argument("--bytes", type=int, help="default for --send-bytes and --expect")
ap.add_argument("--send-bytes", type=int)
ap.add_argument("--expect", help="BYTES or 'any' (verify until EOF)")
ap.add_argument("--send-secs", type=float, help="after receiving, send for S seconds, then shut down writes")
ap.add_argument("--pause-read-ms", type=int, default=0)
a = ap.parse_args()
if a.bytes is None and (a.expect is None or a.send_bytes is None and not a.send_secs):
    ap.error("give --bytes, or --expect and one of --send-bytes/--send-secs")
N = a.bytes if a.expect is None else None if a.expect == "any" else int(a.expect)  # None = any
S = a.bytes if a.send_bytes is None else a.send_bytes

# pattern byte i = (i*31+7) % 251; one repeating buffer, sliced at (offset % 251)
PAT = bytes((i * 31 + 7) % 251 for i in range(251))
BUF = PAT * (262144 // 251 + 2)

ls = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 262 if a.mode == "mptcp" else 0)
if a.pause_read_ms:
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 16384)
ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
ls.bind(("10.0.1.2", a.port))  # every case connects (and joins) to 10.0.1.2
ls.listen(1)
print("listening", flush=True)
c, peer = ls.accept()

got = 0
ok = True
first = last = None
while N is None or got < N:
    d = c.recv(262144 if N is None else min(262144, N - got))
    if not d:
        break
    if d != BUF[got % 251 : got % 251 + len(d)]:
        ok = False
        print(f"mismatch in chunk at offset {got}", file=sys.stderr)
        break
    got += len(d)
    last = time.monotonic()
    first = first or last
    if a.pause_read_ms:
        print(f"read paused at {got} bytes", flush=True)
        time.sleep(a.pause_read_ms / 1000)
        a.pause_read_ms = 0
if not ok or (N is not None and got != N):
    print(f"FAIL recv {got}/{N} ok={ok}")
    sys.exit(1)

if first:  # receiver-side goodput: first to last received byte
    secs = last - first
    print(f"goodput: {got} bytes in {secs:.3f} s = {got * 8 / max(secs, 1e-9) / 1e6:.1f} Mbit/s", flush=True)
sent = 0
deadline = time.monotonic() + a.send_secs if a.send_secs else None
while sent < S if deadline is None else time.monotonic() < deadline:
    n = len(BUF) - sent % 251 if deadline else min(len(BUF) - sent % 251, S - sent)
    c.sendall(BUF[sent % 251 : sent % 251 + n])
    sent += n
if deadline:
    c.shutdown(socket.SHUT_WR)

extra = 0
while True:  # read until EOF; any byte beyond N is a failure
    d = c.recv(65536)
    if not d:
        break
    extra += len(d)
c.close()
if extra:
    print(f"FAIL {extra} extra bytes after {got}")
    sys.exit(1)
print(f"server ok: received {got} sent {sent} from {peer[0]} eof=true")
