"""Negative acceptance check for the blackhole RST exemption, on a passing m2-blackhole-b c2s
trace whose blackholed subflow the server reset after close: (1) the same RSTs sent by the
client instead, (2) the server's FIN on that subflow removed. Both must fail."""
import runpy
import subprocess
import sys

original = subprocess.check_output
directory = sys.argv[1]

def run(mutate_row):
    def patched(cmd, **kwargs):
        rows = [line.split("\t") for line in original(cmd, **kwargs).splitlines()]
        return "\n".join("\t".join(r) for r in rows if mutate_row(r) is not False)
    subprocess.check_output = patched
    sys.argv = ["tests/interop/check.py", "m2-blackhole-b", directory, "268435456", "0"]
    try:
        runpy.run_path(sys.argv[0], run_name="__main__")
    except AssertionError as error:
        return str(error)
    finally:
        subprocess.check_output = original
    raise SystemExit("FAIL: mutated trace was accepted")

is_set = lambda v: v in ("1", "True")
def client_rst(r):
    if len(r) > 21 and is_set(r[7]):  # swap ip.src/ip.dst and ports: the client sent it
        r[1], r[19], r[20], r[21] = r[19], r[1], r[21], r[20]
def no_server_fin(r):
    if len(r) > 21 and is_set(r[6]) and r[1] == "10.0.1.2" and "10.0.8.2" == r[19]:
        return False
for name, mutation, want in [("client-sent RST", client_rst, "RST present"), ("no server FIN", no_server_fin, "RST present")]:
    error = run(mutation)
    assert want in error, f"{name}: unexpected failure: {error}"
    print(f"PASS: {name} rejected: {error}")
