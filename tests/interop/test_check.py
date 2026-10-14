"""Tests for check.py's endpoint table. Run: python3 tests/interop/test_check.py"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from endpoints import Packet, check_inversion, csum_fail_checks, endpoints, mptcp_options, removed_flow_exempt, two_subflows  # noqa: E402
from pattern import BUF, verify_chunk  # noqa: E402

SCENARIOS = ["m0", "m1", "syn-strip", "m2-mtu", "base-a", "base-b", "m2-goodput", "m2-lossy", "m2-blackhole-a", "m2-remove", "csum-fail1", "csum-fail2"]


class Endpoints(unittest.TestCase):
    def test_default_pair_unchanged(self):
        # check.py's former hard-coded SRV, cips and join source "10.0.8.2".
        for s in SCENARIOS:
            m2 = s.startswith("m2-") or s == "csum-fail2"
            self.assertEqual(two_subflows(s), m2, s)
            cips = {"10.0.9.2", "10.0.8.2"} if m2 else {"10.0.8.2" if s == "base-b" else "10.0.9.2"}
            self.assertEqual(endpoints(s, "mptcp-rs", "kernel"), ("10.0.1.2", cips, "10.0.8.2" if m2 else None), s)

    def test_mptcp_rs_server(self):
        self.assertEqual(endpoints("m1", "mptcp-rs", "mptcp-rs"), ("10.0.7.2", {"10.0.9.2"}, None))
        self.assertEqual(endpoints("m2-goodput", "mptcp-rs", "mptcp-rs"), ("10.0.7.2", {"10.0.9.2", "10.0.8.2"}, "10.0.8.2"))

    def test_kernel_client(self):
        for server, srv in [("kernel", "10.0.1.2"), ("mptcp-rs", "10.0.7.2")]:
            self.assertEqual(endpoints("base-a", "kernel", server), (srv, {"10.0.1.1"}, None))
            self.assertEqual(endpoints("base-b", "kernel", server), (srv, {"10.0.2.1"}, None))
            self.assertEqual(endpoints("csum-fail1", "kernel", server), (srv, {"10.0.1.1"}, None))
            for s in ["m2-goodput", "m2-lossy", "m2-remove", "csum-fail2"]:
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


SRV = "10.0.1.2"
LEG_A = frozenset([("10.0.9.2", 40000), (SRV, 5201)])
LEG_B = frozenset([("10.0.8.2", 40001), (SRV, 5201)])
DSS = {"subtype": 2, "dsn8": True, "dsn": 5000, "dll": 1400}
INFINITE = {"subtype": 2, "dsn8": True, "dsn": 9000, "dll": 0}
FAIL = {"subtype": 6, "dsn": 5000}
TCPRST6 = {"subtype": 8, "reason": 6}


class MptcpOptions(unittest.TestCase):
    def test_dsn_read_in_option_order(self):
        # A DSS without a mapping, MP_FAIL, a DSS with one: rawdataseqno is MP_FAIL's, then the DSS's.
        got = mptcp_options("2,6,2", "0,1", "0,1", "111,222", "1400", "")
        self.assertEqual(got, [{"subtype": 2, "dsn8": False}, {"subtype": 6, "dsn": 111}, {"subtype": 2, "dsn8": True, "dsn": 222, "dll": 1400}])
        self.assertEqual(mptcp_options("2,6,8", "True", "True", "7,8", "0", "6"),
                         [{"subtype": 2, "dsn8": True, "dsn": 7, "dll": 0}, {"subtype": 6, "dsn": 8}, TCPRST6])


def pkt(t, src, flow, opts, rst=False, ack=True):
    return Packet(t, src, flow, rst, ack, opts)


class CsumFail(unittest.TestCase):
    """csum-fail1/2's wire rules over the captured RST, MP_FAIL and infinite-mapping packets."""
    ONE = [pkt(1, "10.0.9.2", LEG_A, [DSS]), pkt(2, SRV, LEG_A, [FAIL]), pkt(3, "10.0.9.2", LEG_A, [FAIL, INFINITE])]
    RESET = pkt(5, SRV, LEG_B, [FAIL, TCPRST6], rst=True)
    # The resetting end's answers to segments still in flight on that subflow.
    ANSWERS = [pkt(6, SRV, LEG_B, [], rst=True, ack=False), pkt(7, SRV, LEG_B, [], rst=True, ack=False)]

    def test_single_subflow_closure_accepted(self):
        self.assertEqual(csum_fail_checks("csum-fail1", self.ONE, SRV, None), set())

    def test_single_subflow_rules(self):
        for bad, why in [(self.ONE[:2], "MP_FAIL one way"), (self.ONE[1:2] + [pkt(3, "10.0.9.2", LEG_A, [FAIL])], "no infinite mapping"),
                         (self.ONE + [pkt(4, SRV, LEG_A, [], rst=True)], "RST")]:
            with self.assertRaises(AssertionError, msg=why):
                csum_fail_checks("csum-fail1", bad, SRV, None)

    def test_two_subflow_closure_accepted(self):
        for pkts in [[self.RESET], [self.RESET] + self.ANSWERS, [pkt(5, "10.0.8.2", LEG_B, [FAIL, TCPRST6], rst=True, ack=False)]]:
            self.assertEqual(csum_fail_checks("csum-fail2", [pkt(1, "10.0.9.2", LEG_B, [DSS])] + pkts, SRV, "10.0.8.2"), {LEG_B})

    def test_two_subflow_rst_without_mp_fail_and_tcprst_rejected(self):
        for opts in [[], [FAIL], [TCPRST6], [FAIL, {"subtype": 8, "reason": 1}]]:
            with self.assertRaises(AssertionError, msg=opts):
                csum_fail_checks("csum-fail2", [pkt(5, SRV, LEG_B, opts, rst=True)], SRV, "10.0.8.2")

    def test_two_subflow_rules(self):
        for bad, why in [([], "no RST"), ([self.RESET, self.RESET._replace(t=6)], "two resets"),
                         ([self.RESET._replace(flow=LEG_A)], "RST on leg A"),
                         ([self.RESET, pkt(1, "10.0.9.2", LEG_A, [INFINITE])], "infinite mapping"),
                         ([self.RESET, self.ANSWERS[0]._replace(t=4)], "bare RST before the reset"),
                         ([self.RESET, self.ANSWERS[0]._replace(src="10.0.8.2")], "bare RST from the other end"),
                         ([self.RESET, self.ANSWERS[0]._replace(flow=LEG_A)], "bare RST on the other subflow"),
                         ([self.RESET, self.ANSWERS[0]._replace(ack=True)], "RST with ACK after the reset")]:
            with self.assertRaises(AssertionError, msg=why):
                csum_fail_checks("csum-fail2", bad, SRV, "10.0.8.2")


class Inversion(unittest.TestCase):
    """csum-fail1: one inverted octet, inside the mapping the MP_FAIL names (stream offsets)."""

    def test_inside_the_mapping(self):
        check_inversion([1000], 1000, 1400)
        check_inversion([2399], 1000, 1400)

    def test_wrong_offset_rejected(self):
        for offs in [[999], [2400], [123456]]:
            with self.assertRaises(AssertionError, msg=offs):
                check_inversion(offs, 1000, 1400)

    def test_not_exactly_one(self):
        for offs in [[], [1000, 1001]]:
            with self.assertRaises(AssertionError, msg=offs):
                check_inversion(offs, 1000, 1400)


class Invert(unittest.TestCase):
    """server.py's and kclient.py's `--invert N`, as mptcp-rs-tun's."""
    DATA = bytes(BUF[1000 % 251 : 1000 % 251 + 600])  # stream offsets 1000..1600

    def check(self, data, n):
        inv = []
        ok = verify_chunk(1000, data[:300], n, inv) and verify_chunk(1300, data[300:], n, inv)
        return inv if ok and len(inv) == n else None

    def test_exact_inversions(self):
        self.assertEqual(self.check(self.DATA, 0), [])
        two = bytearray(self.DATA)
        two[10] ^= 0xFF
        two[450] ^= 0xFF
        self.assertEqual(self.check(two, 2), [1010, 1450])
        self.assertIsNone(self.check(two, 1), "more inversions than allowed")

    def test_one_inverted_with_two_expected(self):
        one = bytearray(self.DATA)
        one[10] ^= 0xFF
        self.assertIsNone(self.check(one, 2))
        self.assertEqual(self.check(one, 1), [1010])

    def test_changed_not_inverted(self):
        changed = bytearray(self.DATA)
        changed[10] ^= 1
        self.assertIsNone(self.check(changed, 1))
        changed[450] ^= 0xFF
        self.assertIsNone(self.check(changed, 2))


if __name__ == "__main__":
    unittest.main()
