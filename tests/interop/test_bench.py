"""Tests for the kernel comparison bench scripts. Run: python3 tests/interop/test_bench.py"""
import os
import re
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def start_server(port, *args):
    """server.py on the loopback; returns once it prints `listening`."""
    p = subprocess.Popen([sys.executable, str(HERE / "server.py"), "--mode", "mptcp", "--family", "v4", "--port", str(port), *args],
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    assert p.stdout.readline().strip() == "listening"
    return p


class KernelClient(unittest.TestCase):
    def pair(self, server_args, client_args):
        port = free_port()
        srv = start_server(port, *server_args)
        cli = subprocess.run([sys.executable, str(HERE / "kclient.py"), "--local", "127.0.0.1", "--remote", f"127.0.0.1:{port}", *client_args],
                             capture_output=True, text=True, timeout=30)
        try:
            out, _ = srv.communicate(timeout=30)
        finally:
            srv.kill()
        return cli, srv.returncode, out

    def test_c2s_verified(self):
        cli, src, sout = self.pair(["--expect", "any", "--send-bytes", "0"], ["--send-secs", "1", "--expect", "0"])
        self.assertEqual(cli.returncode, 0, cli.stdout + cli.stderr)
        self.assertEqual(src, 0, sout)
        n = int(re.search(r"^ok: sent (\d+) bytes, verified 0 bytes, eof=true$", cli.stdout, re.M)[1])
        self.assertGreater(n, 0)
        self.assertRegex(sout, rf"server ok: received {n} sent 0 ")

    def test_s2c_verified(self):
        cli, src, sout = self.pair(["--expect", "0", "--send-secs", "1"], ["--send", "0", "--expect", "any"])
        self.assertEqual((cli.returncode, src), (0, 0), cli.stdout + cli.stderr + sout)
        self.assertRegex(cli.stdout, r"(?m)^goodput: \d+ bytes in [\d.]+ s = [\d.]+ Mbit/s$")
        m = int(re.search(r"^ok: sent 0 bytes, verified (\d+) bytes, eof=true$", cli.stdout, re.M)[1])
        self.assertRegex(sout, rf"server ok: received 0 sent {m} ")
        self.cli_log, self.srv_log = cli.stdout, sout

    def test_s2c_unverified(self):
        cli, src, sout = self.pair(["--expect", "0", "--send-secs", "1", "--verify", "off"], ["--send", "0", "--expect", "any", "--verify", "off"])
        self.assertEqual((cli.returncode, src), (0, 0), cli.stdout + cli.stderr + sout)
        m = int(re.search(r"^ok: sent 0 bytes, verified (\d+) bytes, eof=true$", cli.stdout, re.M)[1])
        self.assertRegex(sout, rf"server ok: received 0 sent {m} ")

    def test_c2s_mismatch_fails(self):
        port = free_port()
        srv = start_server(port, "--expect", "any", "--send-bytes", "0")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 262) as s:
            s.connect(("127.0.0.1", port))
            s.sendall(b"\x00" * 1000)
            s.shutdown(socket.SHUT_WR)
            while s.recv(65536):
                pass
        srv.communicate(timeout=10)
        self.assertEqual(srv.returncode, 1)

    def test_check_logs_only(self):
        self.test_s2c_verified()
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "client.log").write_text(self.cli_log)
            (Path(d) / "server.log").write_text(self.srv_log)
            run = lambda: subprocess.run([sys.executable, str(HERE / "check.py"), "m2-unshaped", d, "0", "any", "logs-only"], capture_output=True, text=True)
            p = run()
            self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
            self.assertIn("PASS m2-unshaped (logs only)", p.stdout)
            (Path(d) / "server.log").write_text(re.sub(r"sent (\d+)", lambda m: f"sent {int(m[1]) + 1}", self.srv_log))
            self.assertNotEqual(run().returncode, 0)


SS_SAMPLE = """ESTAB 0      0          10.0.1.2:5201     10.0.1.1:40000
\t cubic wscale:7,7 rto:204 rtt:0.05/0.02 mss:1448 bytes_sent:20 bytes_acked:10 bytes_received:1000 segs_out:5 tcp-ulp-mptcp flags:Mmec
ESTAB 0      0          10.0.1.2:5201     10.0.2.1:40001
\t cubic wscale:7,7 rto:204 rtt:0.05/0.02 mss:1448 bytes_received:500 segs_out:3 tcp-ulp-mptcp flags:Jjec
"""


class CpuSampler(unittest.TestCase):
    def test_parse_ss(self):
        import cpu
        socks = cpu.parse_ss(SS_SAMPLE)
        self.assertEqual(socks, {("10.0.1.2:5201", "10.0.1.1:40000"): {"received": 1000, "acked": 10},
                                 ("10.0.1.2:5201", "10.0.2.1:40001"): {"received": 500, "acked": 0}})
        self.assertEqual(cpu.window_payload({}, socks), {"a": {"received": 1000, "acked": 10}, "b": {"received": 500, "acked": 0}})

    def test_window_payload(self):
        import cpu
        k1, k2 = ("10.0.1.2:5201", "10.0.1.1:1"), ("10.0.1.2:5201", "10.0.2.1:2")
        c = lambda r, a: {"received": r, "acked": a}
        self.assertEqual(cpu.window_payload({k1: c(100, 5)}, {k1: c(250, 9), k2: c(40, 0)}),
                         {"a": c(150, 4), "b": c(40, 0)})
        self.assertIsNone(cpu.window_payload({k1: c(100, 5), k2: c(1, 0)}, {k1: c(250, 9)}))  # k2 vanished
        self.assertIsNone(cpu.window_payload({k1: c(100, 5)}, {k1: c(90, 9)}))  # decreased

    def test_direction_total(self):
        import cpu
        acked_only = {"a": {"received": 0, "acked": 7}, "b": {"received": 0, "acked": 3}}
        self.assertEqual(cpu.data_total(acked_only, "c2s"), 0)
        self.assertEqual(cpu.data_total(acked_only, "s2c"), 10)

    def run_cpu(self, client_cmd, start="0.5"):
        busy = subprocess.Popen(client_cmd)
        idle = subprocess.Popen(["sleep", "10"])
        try:
            with tempfile.TemporaryDirectory() as d:
                out = Path(d) / "cpu.json"
                subprocess.run([sys.executable, str(HERE / "cpu.py"), str(out), "--client", str(busy.pid), "--server", str(idle.pid),
                                "--direction", "c2s", "--start", start, "--len", "1"], check=True, timeout=30)
                import json
                return json.loads(out.read_text())
        finally:
            busy.kill(); idle.kill()

    def test_cpu_window(self):
        r = self.run_cpu([sys.executable, "-c", "while True: pass"])
        self.assertTrue(0.7 <= r["client"]["user_s"] <= 1.3, r)
        self.assertLess(r["server"]["user_s"] + r["server"]["sys_s"], 0.1)
        self.assertGreaterEqual(r["host_busy_cpus"], 0.7)
        self.assertFalse(r["valid"])
        self.assertIn("ss", r["reason"])  # the host has no srv netns

    def test_cpu_pid_gone(self):
        r = self.run_cpu(["sleep", "0.2"])
        self.assertFalse(r["valid"])
        self.assertIn("pid", r["reason"])


def eth_pcap(path, frames):
    """LINKTYPE_ETHERNET pcap of IPv4/TCP frames: (src, dst, payload_len, flags)."""
    import struct
    out = [struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)]
    for i, (src, dst, n, flags) in enumerate(frames):
        tcp = struct.pack("!HHIIBBHHH", 5201 if src == "10.0.1.2" else 40000, 40000 if src == "10.0.1.2" else 5201, 1 + i, 1, 5 << 4, flags, 65535, 0, 0)
        ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp) + n, 0, 0, 64, 6, 0, socket.inet_aton(src), socket.inet_aton(dst))
        frame = b"\x02" * 6 + b"\x04" * 6 + b"\x08\x00" + ip + tcp + b"\x00" * n
        out.append(struct.pack("<IIII", i, 0, len(frame), len(frame)) + frame)
    Path(path).write_bytes(b"".join(out))


@unittest.skipUnless(__import__("shutil").which("tshark"), "tshark not on PATH")
class Ceiling(unittest.TestCase):
    def test_ceiling_math(self):
        import ceiling
        self.assertAlmostEqual(ceiling.ceiling_mbps({"a": 1448 / 1514, "b": 1448 / 1514}), 380 * 1448 / 1514, delta=1e-9)
        self.assertAlmostEqual(ceiling.ceiling_mbps({"a": 0.95}), 285, delta=1e-9)

    def test_payload_ratio_direction(self):
        import ceiling
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "x.pcap"
            eth_pcap(p, [("10.0.1.1", "10.0.1.2", 1000, 0x18), ("10.0.1.2", "10.0.1.1", 500, 0x18), ("10.0.1.1", "10.0.1.2", 0, 0x10)])
            self.assertAlmostEqual(ceiling.payload_ratio(p, "c2s"), 1000 / (14 + 40 + 1000))
            self.assertAlmostEqual(ceiling.payload_ratio(p, "s2c"), 500 / (14 + 40 + 500))
            self.assertEqual(ceiling.leg_payload(p, "c2s"), (1000, 1054))

    def test_ceiling_unused_leg(self):
        import ceiling
        with tempfile.TemporaryDirectory() as d:
            eth_pcap(Path(d) / "server.pcap", [("10.0.1.1", "10.0.1.2", 1448, 0x18)])
            eth_pcap(Path(d) / "server-b.pcap", [("10.0.2.1", "10.0.1.2", 0, 0x10)])
            c, legs = ceiling.run_ceiling(Path(d), "m2-goodput", "c2s")
            self.assertEqual(legs, {"a": 1448, "b": 0})
            self.assertAlmostEqual(c, 380 * 1448 / 1502)
            eth_pcap(Path(d) / "server.pcap", [("10.0.1.1", "10.0.1.2", 0, 0x10)])
            with self.assertRaises(ValueError):
                ceiling.run_ceiling(Path(d), "m2-goodput", "c2s")


class Driver(unittest.TestCase):
    def test_fingerprint_ignores_cache(self):
        import bench
        fp = bench.fingerprint()
        probe = HERE / "__pycache__" / "zz_probe.pyc"
        probe.parent.mkdir(exist_ok=True)
        try:
            probe.write_bytes(b"x")
            self.assertEqual(bench.fingerprint(), fp)
        finally:
            probe.unlink()
        self.assertEqual(bench.fingerprint(), fp)

    def test_append_refuses_stale_fingerprint(self):
        import bench
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "r.jsonl"
            self.assertFalse(bench.append_record(path, {"fingerprint": "built-before-a-rebuild"}))
            self.assertFalse(path.exists())
            self.assertTrue(bench.append_record(path, {"fingerprint": bench.fingerprint()}))
            self.assertEqual(len(path.read_text().splitlines()), 1)

    def test_pending_order(self):
        import bench
        todo = bench.pending([], 2, "base-a")
        self.assertEqual(len(todo), 8)
        self.assertEqual(todo[:2], [("base-a", "c2s", "mptcp-rs", 0), ("base-a", "c2s", "kernel", 0)])
        self.assertEqual(todo[4:6], [("base-a", "c2s", "kernel", 1), ("base-a", "c2s", "mptcp-rs", 1)])
        rec = {"scenario": "base-a", "dir": "c2s", "client": "kernel", "rep": 0}
        self.assertEqual(len(bench.pending([{**rec, "error": None}], 2, "base-a")), 7)
        self.assertEqual(len(bench.pending([{**rec, "error": "rc 1"}], 2, "base-a")), 8)
        self.assertEqual(len(bench.pending([], 5, None)), 5 * 5 * 2 * 2)


def unshaped_rec(rep, server_share, client="kernel", direction="c2s", client_cpu=(2, 8)):
    cpu = {"window_s": 20, "host_busy_cpus": 3, "client": {"user_s": client_cpu[0], "sys_s": client_cpu[1]},
           "server": {"user_s": 10 * server_share, "sys_s": 10 * server_share},  # half Python
           "payload": {"a": {"received": 15e9, "acked": 0}, "b": {"received": 5e9, "acked": 0}}, "valid": True}
    return {"scenario": "m2-unshaped", "dir": direction, "client": client, "rep": rep, "goodput_mbps": 8000.0,
            "ceiling_mbps": None, "leg_payload": None, "cpu": cpu, "artifacts": f"run{rep}", "error": None}


class Summary(unittest.TestCase):
    def test_summarize(self):
        import bench_plot
        recs = [{"scenario": "base-a", "dir": "c2s", "client": "kernel", "rep": i, "goodput_mbps": g, "ceiling_mbps": 280.0,
                 "leg_payload": {"a": 100}, "cpu": None, "artifacts": "x", "error": None} for i, g in enumerate([100.0, 200.0, 300.0])]
        recs.append({**recs[0], "rep": 3, "goodput_mbps": 1.0, "error": "rc 1"})
        s = bench_plot.summarize(recs)["base-a/c2s/kernel"]
        self.assertEqual((s["n"], s["median_mbps"], s["min_mbps"], s["max_mbps"]), (3, 200.0, 100.0, 300.0))
        self.assertEqual(s["ceiling_median_mbps"], 280.0)
        self.assertFalse(s["bottleneck"])

    def test_record_cpu(self):
        import bench_plot
        rec = unshaped_rec(0, 0.95, client_cpu=(4, 16))
        rec["cpu"]["server"] = {"user_s": 2, "sys_s": 17}
        r = bench_plot.record_cpu(rec)
        self.assertAlmostEqual(r["host_cpu_s_per_gb"], 3)
        self.assertAlmostEqual(r["client_cpu_s_per_gb"], 1.0)
        self.assertAlmostEqual(r["client_core_share"], 1.0)
        self.assertAlmostEqual(r["client_user_frac"], 0.2)
        self.assertAlmostEqual(r["server_core_share"], 0.95)
        self.assertAlmostEqual(r["leg_b_share"], 0.25)
        self.assertTrue(r["bottleneck"])
        # A saturated mptcp-rs client is its own stack at work, not a harness bottleneck.
        self.assertFalse(bench_plot.record_cpu(unshaped_rec(0, 0.5, client="mptcp-rs", client_cpu=(4, 16)))["bottleneck"])

    def test_saturated_kernel_sender_not_flagged(self):
        import bench_plot
        # The smoke run: the kernel client's send path saturates one core, 97 % of it sys time.
        rec = unshaped_rec(0, 0.5, client_cpu=(0.53, 19.07))
        r = bench_plot.record_cpu(rec)
        self.assertAlmostEqual(r["client_core_share"], 0.98)
        self.assertFalse(r["bottleneck"])

    def test_bottleneck_any_run(self):
        import bench_plot
        recs = [unshaped_rec(i, sh) for i, sh in enumerate([0.6, 0.6, 0.6, 0.95, 0.95])]
        s = bench_plot.summarize(recs)["m2-unshaped/c2s/kernel"]
        self.assertTrue(s["bottleneck"])
        self.assertEqual([r["rep"] for r in s["bottleneck_runs"]], [3, 4])


if __name__ == "__main__":
    unittest.main()
