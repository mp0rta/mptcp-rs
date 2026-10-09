"""Acceptance checks for the blackhole RST exemption, on a passing m2-blackhole-b c2s trace
whose blackholed subflow was reset after close (by the server, the client or both). Must
fail: (1) the client RSTs moved before both DATA_FINs are DATA_ACKed; (2) every RST on it
sent by the server and the server's FIN on it removed; (3) the client RSTs while that subflow
had no client TCP data outstanding (the server ACKs everything). Must pass: (4) every RST
on it sent by the client instead, unchanged in time."""
import runpy
import subprocess
import sys

original = subprocess.check_output
directory = sys.argv[1]
SRV, HIP = "10.0.1.2", "10.0.8.2"

def run(mutate):
    def patched(cmd, **kwargs):
        rows = [line.split("\t") for line in original(cmd, **kwargs).splitlines()]
        return "\n".join("\t".join(r) for r in mutate(rows))
    subprocess.check_output = patched
    sys.argv = ["tests/interop/check.py", "m2-blackhole-b", directory, "1073741824", "0"]
    try:
        runpy.run_path(sys.argv[0], run_name="__main__")
    except AssertionError as error:
        return str(error)
    finally:
        subprocess.check_output = original
    return None

is_set = lambda v: v in ("1", "True")
tcp = lambda r: len(r) > 21
on_hip = lambda r: tcp(r) and {r[1], r[19]} == {SRV, HIP}
def swap(r):  # ip.src/ip.dst and ports: the other side sent it
    r[1], r[19], r[20], r[21] = r[19], r[1], r[21], r[20]
def client_rsts(rows):
    for r in rows:
        if on_hip(r) and is_set(r[7]) and r[1] == SRV:
            swap(r)
    return rows
def early_client_rst(rows):
    rows = client_rsts(rows)
    for r in rows:
        if on_hip(r) and is_set(r[7]):
            r[0] = str(float(r[0]) - 5.0)  # during the transfer
    return rows
def no_server_fin(rows):
    for r in rows:
        if on_hip(r) and is_set(r[7]) and r[1] == HIP:
            swap(r)  # every RST server-sent
    return [r for r in rows if not (on_hip(r) and is_set(r[6]) and r[1] == SRV)]
def nothing_outstanding(rows):
    rows = client_rsts(rows)
    isn = next((int(r[2]) for r in rows if on_hip(r) and r[1] == HIP and is_set(r[5])), None)
    if isn is None:  # called once per pcap; the B leg is in server-b.pcap
        return rows
    top = max((int(r[2]) - isn) % (1 << 32) + int(r[4] or 0) for r in rows if on_hip(r) and r[1] == HIP)
    for r in rows:
        if on_hip(r) and r[1] == SRV and is_set(r[18]):
            r[3] = str((isn + top) % (1 << 32))
    return rows

cases = [("client RST before DATA_FIN DATA_ACK", early_client_rst, "RST present"),
         ("client RST with nothing outstanding", nothing_outstanding, "RST present"),
         ("server RST without server FIN", no_server_fin, "RST present")]
for name, mutation, want in cases:
    error = run(mutation)
    assert error is not None, f"FAIL: {name}: mutated trace was accepted"
    assert want in error, f"{name}: unexpected failure: {error}"
    print(f"PASS: {name} rejected: {error}")
error = run(client_rsts)
assert error is None, f"FAIL: client RST after close rejected: {error}"
print("PASS: client RST after close with data outstanding accepted")
