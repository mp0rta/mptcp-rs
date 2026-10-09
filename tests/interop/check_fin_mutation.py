"""Negative acceptance check: valid trace with both FIN DSNs shifted backwards."""
import runpy
import subprocess
import sys

original = subprocess.check_output

def mutate(cmd, **kwargs):
    result = original(cmd, **kwargs)
    rows = [line.split("\t") for line in result.splitlines()]
    for row in rows:
        if row[12] == "1":
            row[13] = str((int(row[13]) - 10000) % (1 << 64))
    return "\n".join("\t".join(row) for row in rows)

subprocess.check_output = mutate
directory = sys.argv[1]
sys.argv = ["tests/interop/check.py", "m1", directory, "67108864", "67108864"]
try:
    runpy.run_path(sys.argv[0], run_name="__main__")
except AssertionError as error:
    assert "must end at IDSN" in str(error), f"unexpected failure: {error}"
    print(f"PASS: shifted FIN rejected: {error}")
else:
    raise SystemExit("FAIL: corrupted DATA_FIN DSNs were accepted")
