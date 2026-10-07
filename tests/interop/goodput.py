#!/usr/bin/env python3
"""Run a timed interop case 3x; print per-run and median receiver goodput (Mbit/s) as JSON."""
import json, re, statistics, subprocess, sys

case, direction = sys.argv[1:]
runs, dirs = [], []
for _ in range(3):
    p = subprocess.run(["bash", "tests/interop/run.sh", case, direction], text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    sys.stderr.write(p.stdout)
    dirs.append(re.search(r"^artifacts: (\S+)", p.stdout, re.M)[1])
    assert p.returncode == 0 and f"PASS {case}" in p.stdout, f"{case} {direction} failed, see {dirs[-1]}"
    # Only the receiving side prints a goodput line: the idle direction receives 0 bytes.
    runs.append(float(re.search(r"^goodput: \d+ bytes in [\d.]+ s = ([\d.]+) Mbit/s$", p.stdout, re.M)[1]))
print(json.dumps({"case": case, "dir": direction, "runs_mbps": runs, "median_mbps": statistics.median(runs), "artifacts": dirs}))
