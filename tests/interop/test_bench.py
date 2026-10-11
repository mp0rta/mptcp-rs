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


if __name__ == "__main__":
    unittest.main()
