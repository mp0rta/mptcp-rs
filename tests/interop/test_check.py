"""Tests for check.py's endpoint table. Run: python3 tests/interop/test_check.py"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from endpoints import endpoints, removed_flow_exempt  # noqa: E402

SCENARIOS = ["m0", "m1", "syn-strip", "m2-mtu", "base-a", "base-b", "m2-goodput", "m2-lossy", "m2-blackhole-a", "m2-remove"]


class Endpoints(unittest.TestCase):
    def test_default_pair_unchanged(self):
        # check.py's former hard-coded SRV, cips and join source "10.0.8.2".
        for s in SCENARIOS:
            m2 = s.startswith("m2-")
            cips = {"10.0.9.2", "10.0.8.2"} if m2 else {"10.0.8.2" if s == "base-b" else "10.0.9.2"}
            self.assertEqual(endpoints(s, "mptcp-rs", "kernel"), ("10.0.1.2", cips, "10.0.8.2" if m2 else None), s)

    def test_mptcp_rs_server(self):
        self.assertEqual(endpoints("m1", "mptcp-rs", "mptcp-rs"), ("10.0.7.2", {"10.0.9.2"}, None))
        self.assertEqual(endpoints("m2-goodput", "mptcp-rs", "mptcp-rs"), ("10.0.7.2", {"10.0.9.2", "10.0.8.2"}, "10.0.8.2"))

    def test_kernel_client(self):
        for server, srv in [("kernel", "10.0.1.2"), ("mptcp-rs", "10.0.7.2")]:
            self.assertEqual(endpoints("base-a", "kernel", server), (srv, {"10.0.1.1"}, None))
            self.assertEqual(endpoints("base-b", "kernel", server), (srv, {"10.0.2.1"}, None))
            for s in ["m2-goodput", "m2-lossy", "m2-remove"]:
                self.assertEqual(endpoints(s, "kernel", server), (srv, {"10.0.1.1", "10.0.2.1"}, "10.0.2.1"), s)


class RemovedFlowExempt(unittest.TestCase):
    LEG_B = frozenset([("10.0.2.1", 40000), ("10.0.7.2", 5201)])
    LEG_A = frozenset([("10.0.1.1", 40001), ("10.0.7.2", 5201)])

    def test_only_the_removed_flow(self):
        self.assertTrue(removed_flow_exempt("m2-remove", "kernel", self.LEG_B))
        self.assertFalse(removed_flow_exempt("m2-remove", "kernel", self.LEG_A))

    def test_no_other_scenario_or_client(self):
        for s in SCENARIOS:
            for client in ["kernel", "mptcp-rs"]:
                if (s, client) == ("m2-remove", "kernel"):
                    continue
                for f in [self.LEG_A, self.LEG_B, frozenset([("10.0.8.2", 40000), ("10.0.7.2", 5201)])]:
                    self.assertFalse(removed_flow_exempt(s, client, f), (s, client, f))


if __name__ == "__main__":
    unittest.main()
