#!/usr/bin/env python3
"""Linux TCP/MPTCP peer for the interop tests, listening on 10.0.1.2 (or the --family wildcard):
receive the pattern (--expect bytes, or until EOF), then send it (--send-bytes, or for --send-secs;
--bidi: while receiving), then read until EOF. --bytes sets both counts. --abort-after: close
with SO_LINGER 0 once that many bytes were received and sent in total, and exit 3. A connection
reset by the client exits 4. Exit 0 means every byte was verified (--invert N: exactly N octets
inverted, each printed as `inverted at OFF`)."""
import argparse, os, socket, struct, sys, threading, time

from pattern import BUF, verify_chunk

ap = argparse.ArgumentParser()
ap.add_argument("--mode", choices=["tcp", "mptcp"], required=True)
ap.add_argument("--port", type=int, required=True)
ap.add_argument("--bytes", type=int, help="default for --send-bytes and --expect")
ap.add_argument("--send-bytes", type=int)
ap.add_argument("--expect", help="BYTES or 'any' (verify until EOF)")
ap.add_argument("--send-secs", type=float, help="after receiving, send for S seconds, then shut down writes")
ap.add_argument("--pause-read-ms", type=int, default=0)
ap.add_argument("--family", choices=["v4", "v6", "dual"], help="listen on the wildcard (dual: one v6 socket, V6ONLY=0)")
ap.add_argument("--bidi", action="store_true", help="send and receive concurrently")
ap.add_argument("--abort-after", type=int, metavar="BYTES")
ap.add_argument("--verify", choices=["on", "off"], default="on", help="off: count received bytes only (CPU benchmark)")
ap.add_argument("--invert", type=int, default=0, metavar="N", help="exactly N received octets are the pattern's bitwise inverse")
a = ap.parse_args()
if a.bytes is None and (a.expect is None or a.send_bytes is None and not a.send_secs):
    ap.error("give --bytes, or --expect and one of --send-bytes/--send-secs")
N = a.bytes if a.expect is None else None if a.expect == "any" else int(a.expect)  # None = any
S = a.bytes if a.send_bytes is None else a.send_bytes

v6 = a.family in ("v6", "dual")
ls = socket.socket(socket.AF_INET6 if v6 else socket.AF_INET, socket.SOCK_STREAM, 262 if a.mode == "mptcp" else 0)
if v6:
    ls.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, int(a.family == "v6"))
if a.pause_read_ms:
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 16384)
ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
# Every run.sh case connects (and joins) to 10.0.1.2; suite cases may join any server address.
ls.bind(("::" if v6 else "0.0.0.0" if a.family else "10.0.1.2", a.port))
ls.listen(1)
print("listening", flush=True)
c, peer = ls.accept()

ABORTED, RESET = 3, 4  # exit statuses (run_suite.py)
got = sent = 0
abort_lock = threading.Lock()  # --bidi: both threads may get here
def maybe_abort():
    if a.abort_after is not None and got + sent >= a.abort_after:
        with abort_lock:
            c.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
            print(f"server aborted: received {got} sent {sent}", flush=True)
            # The exit is the close: no other thread can see the socket closed and fail first.
            os._exit(ABORTED)

def on_error(t, v, tb):
    if issubclass(t, ConnectionResetError):
        print(f"server reset: received {got} sent {sent}", flush=True)
        os._exit(RESET)
    sys.__excepthook__(t, v, tb)
    os._exit(1)
sys.excepthook = on_error

def send():
    global sent
    deadline = time.monotonic() + a.send_secs if a.send_secs else None
    while sent < S if deadline is None else time.monotonic() < deadline:
        n = len(BUF) - sent % 251 if deadline else min(len(BUF) - sent % 251, S - sent)
        c.sendall(BUF[sent % 251 : sent % 251 + n])
        sent += n
        maybe_abort()
    if deadline:
        c.shutdown(socket.SHUT_WR)

if a.bidi:
    threading.excepthook = lambda e: on_error(e.exc_type, e.exc_value, e.exc_traceback)
    sender = threading.Thread(target=send)
    sender.start()
ok = True
inverted = []
first = last = None
rbuf = bytearray(262144)
while N is None or got < N:
    if a.verify == "off":
        d = memoryview(rbuf)[: c.recv_into(rbuf, 262144 if N is None else min(262144, N - got))]
    else:
        d = c.recv(262144 if N is None else min(262144, N - got))
    if not d:
        break
    seen = len(inverted)
    if a.verify == "on" and not verify_chunk(got, d, a.invert, inverted):
        ok = False
        print(f"mismatch in chunk at offset {got}", file=sys.stderr)
        break
    for off in inverted[seen:]:
        print(f"inverted at {off}", flush=True)
    got += len(d)
    maybe_abort()
    last = time.monotonic()
    first = first or last
    if a.pause_read_ms:
        print(f"read paused at {got} bytes", flush=True)
        time.sleep(a.pause_read_ms / 1000)
        a.pause_read_ms = 0
if a.verify == "on" and len(inverted) != a.invert:
    ok = False
    print(f"{len(inverted)} inverted octets, expected {a.invert}", file=sys.stderr)
if not ok or (N is not None and got != N):
    print(f"FAIL recv {got}/{N} ok={ok}")
    sys.exit(1)

if first:  # receiver-side goodput: first to last received byte
    secs = last - first
    print(f"goodput: {got} bytes in {secs:.3f} s = {got * 8 / max(secs, 1e-9) / 1e6:.1f} Mbit/s", flush=True)
sender.join() if a.bidi else send()

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
