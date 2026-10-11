#!/usr/bin/env python3
"""Kernel comparison bench: run the matrix (scenario x direction x client x rep) through run.sh in
bench mode, clients alternated within each cell, and append one JSON line per run to RESULTS.
Resumable: runs already recorded without an error are skipped; a dataset from another build or
harness revision (fingerprint) is refused. Usage: bench.py RESULTS.jsonl [--reps 5] [--only S]"""
import argparse, hashlib, json, os, re, subprocess, sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))
import ceiling  # noqa: E402

SCENARIOS = ["base-a", "base-b", "m2-goodput", "m2-lossy", "m2-unshaped"]
DIRS = ["c2s", "s2c"]
CLIENTS = ["mptcp-rs", "kernel"]


def fingerprint():
    """The client binary and the harness sources (no tests, caches or outputs)."""
    files = [ROOT / "target/release/mptcp-rs-tun"] + sorted(
        p for p in HERE.rglob("*")
        if p.is_file() and (p.suffix in (".py", ".sh") or p.name == "Dockerfile") and not p.name.startswith("test_"))
    h = hashlib.sha256()
    for p in files:
        h.update(str(p.relative_to(ROOT)).encode() + b"\0" + p.read_bytes())
    return h.hexdigest()


def pending(done, reps, only):
    ok = {(r["scenario"], r["dir"], r["client"], r["rep"]) for r in done if r.get("error") is None}
    todo = []
    for rep in range(reps):
        for scen in [only] if only else SCENARIOS:
            for d in DIRS:
                for client in CLIENTS if rep % 2 == 0 else CLIENTS[::-1]:
                    if (scen, d, client, rep) not in ok:
                        todo.append((scen, d, client, rep))
    return todo


def check_run(scen, d, out, art):
    """Fill a record from run.sh's output and run dir; returns the reason it is invalid, or None."""
    rec = {"goodput_mbps": None, "goodput_secs": None, "bytes": None, "leg_payload": None, "cpu": None, "ceiling_mbps": None}
    m = re.search(r"^goodput: (\d+) bytes in ([\d.]+) s = ([\d.]+) Mbit/s$", out, re.M)
    if m:
        rec.update(bytes=int(m[1]), goodput_secs=float(m[2]), goodput_mbps=float(m[3]))
    cpu = art / "cpu.json" if art else None
    if cpu and cpu.exists():
        rec["cpu"] = json.loads(cpu.read_text())
    if not m:
        return rec, "no goodput line"
    if rec["goodput_secs"] < 25:
        return rec, f"goodput over {rec['goodput_secs']} s < 25 s"
    if not (rec["cpu"] or {}).get("valid"):
        return rec, f"cpu window: {(rec['cpu'] or {}).get('reason', 'no cpu.json')}"
    if scen != "m2-unshaped":
        eth = (art / "ethtool.txt").read_text()
        if eth.count("generic-segmentation-offload: off") != 4 or len(re.findall(r"\bgso_max_segs 1\b", eth)) != 4:
            return rec, "offloads/gso_max_segs not set on all four veths"
        try:
            rec["ceiling_mbps"], rec["leg_payload"] = ceiling.run_ceiling(art, scen, d)
        except (ValueError, subprocess.CalledProcessError) as e:
            return rec, f"ceiling: {e}"
    return rec, None


def run_one(scen, d, client, rep, fp):
    env = {**os.environ, "INTEROP_BENCH": "1", "MPTCP_RS_CC": "cubic", "INTEROP_CLIENT": client}
    p = subprocess.run(["bash", str(HERE / "run.sh"), scen, d], cwd=ROOT, env=env, text=True,
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    m = re.search(r"^artifacts: (\S+)", p.stdout, re.M)
    art = ROOT / m[1] if m else None
    rec, err = check_run(scen, d, p.stdout, art)
    if p.returncode != 0:
        err = f"rc {p.returncode}"
    return {"fingerprint": fp, "scenario": scen, "dir": d, "client": client, "rep": rep, "rc": p.returncode,
            **rec, "artifacts": str(art.relative_to(ROOT)) if art else None, "error": err}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("results")
    ap.add_argument("--reps", type=int, default=5)
    ap.add_argument("--only", choices=SCENARIOS)
    a = ap.parse_args()
    path = Path(a.results)
    done = [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []
    fp = fingerprint()
    other = {r["fingerprint"] for r in done} - {fp}
    if other:
        print(f"{path}: recorded with fingerprint {', '.join(sorted(other))}, current build is {fp}; start a new file", file=sys.stderr)
        sys.exit(2)
    todo = pending(done, a.reps, a.only)
    for i, (scen, d, client, rep) in enumerate(todo, 1):
        rec = run_one(scen, d, client, rep, fp)
        with path.open("a") as f:
            f.write(json.dumps(rec) + "\n")
        print(f"[{i}/{len(todo)}] {scen} {d} {client} rep {rep}: {rec['goodput_mbps']} Mbit/s {rec['error'] or 'ok'}", flush=True)


if __name__ == "__main__":
    main()
