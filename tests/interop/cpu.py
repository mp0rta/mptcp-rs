#!/usr/bin/env python3
"""CPU over one steady window of a bench run: host busy CPUs (/proc/stat), the client and server
programs' user/sys time, and the TCP payload the server's subflows moved in the same window
(`ss -tinH` in netns srv). Run in the background right after the client starts; /proc is shared
across netns. Writes OUT.json; `valid` false with a `reason` when the window cannot be trusted."""
import argparse, json, os, re, subprocess, time

LEGS = {"10.0.9.2": "a", "10.0.1.1": "a", "10.0.8.2": "b", "10.0.2.1": "b"}  # client address -> leg
TICK = os.sysconf("SC_CLK_TCK")


def parse_ss(text):
    """`ss -tinH`: a state line (state recv-q send-q local peer) then an indented info line."""
    socks, key = {}, None
    for line in text.splitlines():
        if line and not line[0].isspace():
            f = line.split()
            key = (f[3], f[4])
            socks[key] = {"received": 0, "acked": 0}
        elif key:  # ss omits a counter that is still 0
            for name, field in (("received", "bytes_received"), ("acked", "bytes_acked")):
                m = re.search(rf"\b{field}:(\d+)", line)
                if m:
                    socks[key][name] = int(m[1])
    return socks


def window_payload(before, after):
    """Per-socket deltas summed by leg; None if a socket vanished or a counter went down."""
    if set(before) - set(after):
        return None
    legs = {leg: {"received": 0, "acked": 0} for leg in "ab"}
    for key, now in after.items():
        was = before.get(key, {"received": 0, "acked": 0})
        if any(now[c] < was[c] for c in now):
            return None
        leg = LEGS.get(key[1].rsplit(":", 1)[0])
        if leg:
            for c in now:
                legs[leg][c] += now[c] - was[c]
    return legs


def data_total(payload, direction):
    return sum(leg["received" if direction == "c2s" else "acked"] for leg in payload.values())


def host_busy():
    v = [int(x) for x in open("/proc/stat").readline().split()[1:9]]  # guest time is inside user
    return (sum(v) - v[3] - v[4]) / TICK  # minus idle and iowait


def proc_times(pid):
    f = open(f"/proc/{pid}/stat").read().rsplit(")", 1)[1].split()
    if f[0] == "Z":  # exited, not yet reaped
        raise ProcessLookupError(pid)
    return int(f[11]) / TICK, int(f[12]) / TICK  # utime, stime


def ss_snapshot():
    p = subprocess.run(["ip", "netns", "exec", "srv", "ss", "-tinH"], capture_output=True, text=True)
    socks = parse_ss(p.stdout) if p.returncode == 0 else {}
    return socks or None


def sample(pids):
    try:
        procs = {name: proc_times(pid) for name, pid in pids.items()}
    except (FileNotFoundError, ProcessLookupError):
        procs = None
    return time.monotonic(), host_busy(), procs, ss_snapshot()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("out")
    ap.add_argument("--client", type=int, required=True)
    ap.add_argument("--server", type=int, required=True)
    ap.add_argument("--direction", choices=["c2s", "s2c"], required=True)
    ap.add_argument("--start", type=float, default=5)
    ap.add_argument("--len", type=float, default=20)
    a = ap.parse_args()
    pids = {"client": a.client, "server": a.server}
    time.sleep(a.start)
    t0, h0, p0, s0 = sample(pids)
    time.sleep(a.len)
    t1, h1, p1, s1 = sample(pids)
    window = t1 - t0
    r = {"window_s": window, "host_busy_cpus": (h1 - h0) / window, "payload": None, "valid": False, "reason": None}
    for name in pids:
        r[name] = {"user_s": p1[name][0] - p0[name][0], "sys_s": p1[name][1] - p0[name][1]} if p0 and p1 else None
    r["payload"] = window_payload(s0, s1) if s0 and s1 else None
    if not (p0 and p1):
        r["reason"] = "pid gone during the window"
    elif s0 is None or s1 is None:
        r["reason"] = "ss failed or printed no sockets"
    elif r["payload"] is None:
        r["reason"] = "ss: a subflow vanished or a counter went down"
    elif data_total(r["payload"], a.direction) <= 0:
        r["reason"] = f"ss: no {a.direction} payload in the window"
    else:
        r["valid"] = True
    with open(a.out, "w") as f:
        json.dump(r, f)


if __name__ == "__main__":
    main()
