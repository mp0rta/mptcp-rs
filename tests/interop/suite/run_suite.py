#!/usr/bin/env python3
"""Interop Suite runner (amendment §5), inside the privileged interop image with --network none.
Each case: fresh cli/srv namespaces, netem per link, capture readiness, nstat snapshot, server and
client, barrier-timed fail windows and server actions, watchdog, nstat snapshot, judgement (a)-(d).
Usage: run_suite.py [--case NAME]... [--runs N] [--ci]. Build the release client first."""
import argparse
import json
import operator
import platform
import re
import subprocess
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import cases
from cases import fin_fin_no_rst
import decode

LINKS = range(1, 5)
CLIENT, SERVER = "10.0.91.2", "10.0.1.2:5201"
GUARD = 0.1  # phase assertions skip packets this close (s) to a boundary; the decoder keeps them
SERVER_ABORTED, SERVER_RESET = 3, 4  # server.py exit statuses; 0: every byte verified
OPS = {"==": operator.eq, ">=": operator.ge, "<=": operator.le, ">": operator.gt, "<": operator.lt}


def sh(*cmd, check=True):
    return subprocess.run([str(c) for c in cmd], check=check, capture_output=True, text=True).stdout


def ns(n, *cmd, check=True):
    return sh("ip", "netns", "exec", n, *cmd, check=check)


def topology(case):
    """Fresh netns pair, four links (amendment §5.2), mtun0 created ahead of the client so that
    its capture is ready before the first packet."""
    for n in ("cli", "srv"):
        sh("ip", "netns", "del", n, check=False)
        sh("ip", "netns", "add", n)
        sh("ip", "-n", n, "link", "set", "lo", "up")
        ns(n, "sysctl", "-qw", "net.ipv4.conf.all.rp_filter=0", "net.mptcp.enabled=1")
    ns("cli", "sysctl", "-qw", "net.ipv4.ip_forward=1", "net.ipv6.conf.all.forwarding=1")
    ns("cli", "ip", "tuntap", "add", "dev", "mtun0", "mode", "tun")
    sh("ip", "-n", "cli", "link", "set", "mtun0", "up")
    for i in LINKS:
        sh("ip", "link", "add", f"c{i}", "netns", "cli", "type", "veth", "peer", "name", f"s{i}", "netns", "srv")
        for n, dev, h in (("cli", f"c{i}", 1), ("srv", f"s{i}", 2)):
            sh("ip", "-n", n, "addr", "add", f"10.0.{i}.{h}/24", "dev", dev)
            sh("ip", "-n", n, "addr", "add", f"dead:beef:{i}::{h}/64", "dev", dev, "nodad")
            sh("ip", "-n", n, "link", "set", dev, "up")
            link = {"rate": "20mbit", "delay": "10ms", **case["links"].get(i, {})}
            ns(n, "tc", "qdisc", "add", "dev", dev, "root", "netem", "rate", link["rate"], "delay", link["delay"])
        # Router addresses only: the client endpoints 10.0.9i.2 and fd00:9i::2 live in userspace.
        sh("ip", "-n", "cli", "addr", "add", f"10.0.9{i}.1/24", "dev", "mtun0")
        sh("ip", "-n", "cli", "addr", "add", f"fd00:9{i}::1/64", "dev", "mtun0", "nodad")
        for v, src, via, srv_net, back in (("-4", f"10.0.9{i}.2", f"10.0.{i}.2", f"10.0.9{i}.0/24", f"10.0.{i}.1"),
                                           ("-6", f"fd00:9{i}::2", f"dead:beef:{i}::2", f"fd00:9{i}::/64", f"dead:beef:{i}::1")):
            sh("ip", "-n", "cli", v, "rule", "add", "from", src, "table", 100 + i)
            sh("ip", "-n", "cli", v, "route", "add", "default", "via", via, "dev", f"c{i}", "table", 100 + i)
            sh("ip", "-n", "srv", v, "route", "add", srv_net, "via", back)


def nstat():
    return json.loads(ns("srv", "nstat", "-azs", "--json"))["kernel"]


def clocks():
    return time.time() - time.monotonic()


def drop(i, op):
    """Link i failure (op -I) or repair (-D): both directions, dropped in cli between mtun0 and the
    srv veth, which are the two observation points."""
    for ipt in ("iptables", "ip6tables"):
        ns("cli", ipt, op, "FORWARD", "-o", f"c{i}", "-j", "DROP")
        ns("cli", ipt, op, "FORWARD", "-i", f"c{i}", "-j", "DROP")


def lost(log):
    """Packets tcpdump dropped, or received but never wrote (still queued when it stopped)."""
    n = lambda what: sum(map(int, re.findall(rf"(\d+) packets? {what}", log)))
    return n("dropped by") + n("received by filter") - n("captured")


def barrier_time(log, barrier, until):
    """Realtime at which the client logged the barrier event, polled every 10 ms; None if never."""
    name, _, n = barrier.partition(":")
    while time.time() < until:
        for line in log.read_text().splitlines():
            if line.startswith(f"event: {name}") and (not n or f"({n})" in line):
                return time.time()
        time.sleep(0.01)
    return None


def run_case(case, out):
    """Run one case into out/; return what judgement needs."""
    out.mkdir(parents=True)
    r = SimpleNamespace(case=case, out=out, errors=[], marks=[])
    topology(case)
    for kv in case["server"].get("sysctl", []):
        ns("srv", "sysctl", "-qw", kv)
    for pm in case["server"]["pm"]:
        sh("ip", "-n", "srv", "mptcp", *pm.split())
    caps = {"tun": ("cli", "mtun0")} | {f"srv-s{i}": ("srv", f"s{i}") for i in LINKS}
    procs = {}
    for name, (n, dev) in caps.items():
        procs[name] = subprocess.Popen(["ip", "netns", "exec", n, "tcpdump", "-Z", "root", "-i", dev, "-U", "--immediate-mode",
                                        "-B", "16384", "-s", "160", "-w", out / f"{name}.pcap"],
                                       stdout=subprocess.DEVNULL, stderr=open(out / f"{name}.log", "w"))
    deadline = time.time() + 10
    while not all("listening on" in (out / f"{c}.log").read_text() for c in caps):
        if time.time() > deadline:
            raise RuntimeError(f"capture not ready: see {out}/*.log")
        time.sleep(0.05)
    before, drift0 = nstat(), clocks()

    s, c, d = case["server"], case["client"], case["expect"]["bytes"]
    secs = f"{c['send_secs']:g}"
    sargs = {"c2s": ["--expect", "any", "--send-bytes", "0"], "s2c": ["--expect", "0", "--send-secs", secs],
             "bidi": ["--expect", "any", "--send-secs", secs]}[d]
    sargs += ["--family", s["family"]] + ["--bidi"] * s["bidi"]
    sargs += ["--abort-after", str(s["abort_after"])] if s["abort_after"] is not None else []
    cargs = {"c2s": ["--send-secs", secs, "--expect", "0"], "s2c": ["--send", "0", "--expect", "any"],
             "bidi": ["--send-secs", secs, "--expect", "any"]}[d] + c.get("args", [])
    if c["script"]:
        (out / "script.txt").write_text(c["script"])
        cargs += ["--script", out / "script.txt"]
    cargs += ["--send-rate", c["send_rate"]] if c["send_rate"] else []
    until = time.time() + case["watchdog_s"]
    srv = subprocess.Popen(["ip", "netns", "exec", "srv", "python3", "tests/interop/server.py", "--mode", "mptcp",
                            "--port", "5201", *sargs], stdout=open(out / "server.log", "w"), stderr=subprocess.STDOUT)
    while "listening" not in (out / "server.log").read_text() and srv.poll() is None and time.time() < until:
        time.sleep(0.05)
    cli = subprocess.Popen(["ip", "netns", "exec", "cli", "target/release/mptcp-rs-tun", "--mode", "mptcp", "--tun",
                            "mtun0", "--local", CLIENT, "--remote", SERVER, *map(str, cargs)],
                           stdout=open(out / "client.log", "w"), stderr=subprocess.STDOUT)

    def at(barrier, ms, label, act):
        t = barrier_time(out / "client.log", barrier, until)
        if t is None:
            r.errors.append(f"barrier {barrier} never reached for {label}")
            return
        time.sleep(max(0, t + ms / 1000 - time.time()))
        t = time.time()
        try:
            act()
        except Exception as err:  # a stimulus that did not happen fails the case
            r.errors.append(f"{label} failed: {err}")
            return
        r.marks.append((label, t))

    def window(i, secs):
        drop(i, "-I")
        time.sleep(secs)
        r.marks.append((f"link {i} up", time.time()))
        drop(i, "-D")

    acts = [threading.Thread(target=at, args=(b, ms, f"srv: {cmd}", lambda cmd=cmd: ns("srv", "sh", "-c", cmd)))
            for b, ms, cmd in s["timed"]]
    acts += [threading.Thread(target=at, args=(b, ms, f"link {i} down", lambda i=i, t=t: window(i, t)))
             for i, b, ms, t in case["fail"]]
    for t in acts:
        t.start()
    r.watchdog = r.time_wait = False
    while cli.poll() is None or srv.poll() is None:
        if time.time() > until:
            r.watchdog = True
            for q in (cli, srv):
                q.kill()
        elif srv.poll() == 0:
            # The server verified every byte and closed; 2 s covers the subflow FIN exchange and a
            # passive closer's own exit. A client still running sits in TIME-WAIT (the core holds
            # Closed for 2 MSL); its FIN exchange is judged from the pcap (cases.fin_fin_no_rst).
            time.sleep(2)
            r.time_wait = cli.poll() is None
            cli.terminate()
        time.sleep(0.05)
    r.rc = cli.returncode, srv.returncode
    for t in acts:
        t.join()
    time.sleep(0.5)  # let the last packets reach the captures
    r.after, drift1 = nstat(), clocks()
    r.before, r.drift_ms = before, abs(drift1 - drift0) * 1000
    for p in procs.values():
        p.terminate()
        p.wait()
    r.drops = {c: lost((out / f"{c}.log").read_text()) for c in caps}
    r.client, r.server = (out / "client.log").read_text(), (out / "server.log").read_text()
    r.events = [ln.removeprefix("event: ") for ln in r.client.splitlines() if ln.startswith("event: ")]
    r.segs = decode.load({out / f"{c}.pcap": "cli" if c == "tun" else "srv" for c in caps})
    # Packets within GUARD of a phase boundary are excluded from phase assertions only.
    r.phase = lambda t0, t1: [g for g in r.segs if t0 + GUARD <= g.t <= t1 - GUARD]
    return r


def judge(r):
    """Judgement (a)-(d) of amendment §5.5: the list of failure reasons."""
    case, e, why = r.case, r.case["expect"], list(r.errors)
    # (a) transfer: byte-exact, in the case's direction(s), both ends exit cleanly. The client's
    # counts are from its `closing:` line (printed when it closes, so also before a TIME-WAIT stop).
    if r.watchdog:
        why.append(f"watchdog {case['watchdog_s']} s")
    # A case that ends in an abort by design: the exits that abort gives, and no byte counts.
    aborted = e.get("aborted")
    want_rc = {"client": (0, SERVER_RESET), "server": (1, SERVER_ABORTED)}.get(aborted, (-15 if r.time_wait else 0, 0))
    if r.rc != want_rc:
        why.append(f"exit client={r.rc[0]} server={r.rc[1]}")
    cm = re.search(r"^closing: sent (\d+) bytes, verified (\d+) bytes$", r.client, re.M)
    sm = re.search(r"^server ok: received (\d+) sent (\d+) ", r.server, re.M)
    if r.time_wait and fin_fin_no_rst not in e["pcap"]:
        e = {**e, "pcap": e["pcap"] + [fin_fin_no_rst]}  # the proof of the FIN exchange
    elif r.rc[0] == 0 and not aborted and "Closed Normal" not in r.events:
        why.append("passive close without Closed Normal")
    if aborted:
        pass
    elif cm and sm:
        c2s, s2c = int(cm[1]), int(cm[2])
        if (int(sm[1]), int(sm[2])) != (c2s, s2c):
            why.append(f"byte counts: client sent {c2s} got {s2c}, server got {sm[1]} sent {sm[2]}")
        want = {"c2s": (True, False), "s2c": (False, True), "bidi": (True, True)}[e["bytes"]]
        if (c2s > 0, s2c > 0) != want:
            why.append(f"{e['bytes']}: c2s {c2s} s2c {s2c}")
    elif not why:
        why.append("no byte count lines")
    # (b) server counters: a listed counter missing on this kernel is a FAIL, never 0
    for k, want in e["nstat"].items():
        if k not in r.after:
            why.append(f"nstat {k} missing")
            continue
        op, v = want if isinstance(want, tuple) else ("==", want)
        delta = r.after[k] - r.before.get(k, 0)
        if not OPS[op](delta, v):
            why.append(f"nstat {k} delta {delta}, want {op} {v}")
    # (c) capture hygiene, clock drift, pcap assertions
    why += [f"tcpdump {c} lost {n} packets" for c, n in r.drops.items() if n]
    if r.drift_ms > 10:
        why.append(f"realtime - monotonic drifted {r.drift_ms:.1f} ms")
    for check in e["pcap"]:
        try:
            check(r)
        except AssertionError as err:
            why.append(f"pcap: {err}")
    # (d) client events: the expected ordered subsequence (prefix match)
    it = iter(r.events)
    missing = [x for x in e["events"] if not any(ev.startswith(x) for ev in it)]
    if missing:
        why.append(f"events: {missing[0]!r} not found in order in {r.events}")
    return why


def kernel_ok(req):
    have = tuple(map(int, re.findall(r"\d+", platform.release())[:2]))
    return req is None or have >= tuple(map(int, req.split(".")))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--case", action="append", choices=[c["name"] for c in cases.CASES])
    ap.add_argument("--runs", type=int, default=1)
    ap.add_argument("--ci", action="store_true", help="only the cases marked ci")
    a = ap.parse_args()
    selected = [c for c in cases.CASES if (not a.case or c["name"] in a.case) and (not a.ci or c["ci"])]
    root = Path("artifacts/interop/suite") / time.strftime("%Y%m%dT%H%M%S", time.gmtime())
    root.mkdir(parents=True)
    versions = {"kernel": platform.release(), "iproute2": sh("ip", "-V").strip(),
                "tshark": sh("tshark", "--version").splitlines()[0]}
    summary = {"runs": a.runs, "versions": versions, "cases": {}}
    print(f"artifacts: {root}", flush=True)
    for case in selected:
        res = summary["cases"][case["name"]] = {"pass": 0, "fail": 0, "skip": 0, "reasons": []}
        if not kernel_ok(case["expect"]["kernel"]):
            res["skip"] = a.runs
            res["reasons"].append(f"kernel {versions['kernel']} < {case['expect']['kernel']}")
            print(f"SKIP {case['name']}: {res['reasons'][0]}", flush=True)
            continue
        for k in range(1, a.runs + 1):
            out = root / case["name"] / str(k)
            t0 = time.time()
            r = run_case(case, out)
            why = judge(r)
            verdict = "FAIL" if why else "PASS"
            res["fail" if why else "pass"] += 1
            res["reasons"] += why
            (out / "versions.json").write_text(json.dumps(versions, indent=1))
            (out / "nstat.json").write_text(json.dumps({"before": r.before, "after": r.after}, indent=1))
            (out / "verdict.json").write_text(json.dumps({
                "verdict": verdict, "reasons": why, "client_stopped_in_time_wait": r.time_wait,
                "drift_ms": r.drift_ms, "marks": r.marks,
                "nstat": {c: r.after.get(c, 0) - r.before.get(c, 0) for c in r.after if r.after[c] != r.before.get(c, 0)},
            }, indent=1))
            print(f"{verdict} {case['name']} run {k}/{a.runs} ({time.time() - t0:.1f} s)", flush=True)
            for w in why:
                print(f"  {w}", flush=True)
    for n in ("cli", "srv"):
        sh("ip", "netns", "del", n, check=False)
    (root / "summary.json").write_text(json.dumps(summary, indent=1))
    passed = sum(r["pass"] == a.runs for r in summary["cases"].values())
    skipped = sum(r["skip"] > 0 for r in summary["cases"].values())
    print(f"{passed} PASS, {skipped} SKIP, {len(selected) - passed - skipped} FAIL", flush=True)
    sys.exit(0 if selected and passed == len(selected) else 1)


if __name__ == "__main__":
    main()
