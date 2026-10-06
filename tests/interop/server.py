#!/usr/bin/env python3
"""Plain-TCP peer for the M0 interop test: receive N pattern bytes, send N, wait for EOF."""
import argparse, socket, sys

ap = argparse.ArgumentParser()
ap.add_argument("--mode", choices=["tcp"], required=True)
ap.add_argument("--port", type=int, required=True)
ap.add_argument("--bytes", type=int, required=True)
a = ap.parse_args()
N = a.bytes

# pattern byte i = (i*31+7) % 251; one repeating buffer, sliced at (offset % 251)
PAT = bytes((i * 31 + 7) % 251 for i in range(251))
BUF = PAT * (262144 // 251 + 2)

ls = socket.socket()
ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
ls.bind(("0.0.0.0", a.port))
ls.listen(1)
print("listening", flush=True)
c, peer = ls.accept()

got = 0
ok = True
while got < N:
    d = c.recv(min(262144, N - got))
    if not d:
        break
    if d != BUF[got % 251 : got % 251 + len(d)]:
        ok = False
        print(f"mismatch in chunk at offset {got}", file=sys.stderr)
        break
    got += len(d)
if not ok or got != N:
    print(f"FAIL recv {got}/{N} ok={ok}")
    sys.exit(1)

sent = 0
while sent < N:
    n = min(len(BUF) - sent % 251, N - sent)
    c.sendall(BUF[sent % 251 : sent % 251 + n])
    sent += n

extra = 0
while True:  # read until EOF; any byte beyond N is a failure
    d = c.recv(65536)
    if not d:
        break
    extra += len(d)
c.close()
if extra:
    print(f"FAIL {extra} extra bytes after {N}")
    sys.exit(1)
print(f"server ok: received {got} sent {sent} from {peer[0]}")
