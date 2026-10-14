"""Tests for check.py's endpoint table. Run: python3 tests/interop/test_check.py"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from endpoints import Packet, check_inversion, csum_checks, csum_fail_checks, csum_options, csum_want, data_ack_advances, delivery_summary, endpoints, failed_mapping, infinite_mapping_checks, mp_fail_dsn, mptcp_options, removed_flow_exempt, two_subflows  # noqa: E402
from pattern import BUF, verify_chunk  # noqa: E402

SCENARIOS = ["m0", "m1", "syn-strip", "m2-mtu", "base-a", "base-b", "m2-goodput", "m2-lossy", "m2-blackhole-a", "m2-remove", "m2-hetero", "csum-fail1", "csum-fail2"]


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
            for s in ["m2-goodput", "m2-lossy", "m2-remove", "m2-hetero", "csum-fail2"]:
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


class FailedMapping(unittest.TestCase):
    """csum-fail1: the receiver's first MP_FAIL DSN, and the sender's mapping it names as stream
    offsets from the sender's IDSN + 1."""
    CLI = {"10.0.9.2"}
    FIRST = (1 << 64) - 100  # the sender's IDSN + 1, near the wrap

    def test_first_mp_fail_from_the_receiver(self):
        pkts = [pkt(3, SRV, LEG_A, [{"subtype": 6, "dsn": 7}]), pkt(1, "10.0.9.2", LEG_A, [{"subtype": 6, "dsn": 5}]),
                pkt(2, SRV, LEG_A, [DSS, {"subtype": 6, "dsn": 6}])]
        self.assertEqual(mp_fail_dsn(pkts, {SRV}), 6)
        self.assertEqual(mp_fail_dsn(pkts, self.CLI), 5)
        with self.assertRaises(AssertionError):
            mp_fail_dsn(pkts[:1], self.CLI)

    def test_64_bit_dsn_and_offset_across_the_wrap(self):
        fail = (self.FIRST + 5000) % (1 << 64)
        maps = [pkt(1, "10.0.9.2", LEG_A, [{"subtype": 2, "dsn8": True, "dsn": fail, "dll": 1400}]),
                # Linux re-declares its last mapping with DLL + 1 (DATA_FIN): the larger one counts.
                pkt(2, "10.0.9.2", LEG_A, [{"subtype": 2, "dsn8": True, "dsn": fail, "dll": 1401}]),
                pkt(3, "10.0.9.2", LEG_A, [{"subtype": 2, "dsn8": True, "dsn": fail + 1, "dll": 9999}]),
                pkt(4, SRV, LEG_A, [{"subtype": 2, "dsn8": True, "dsn": fail, "dll": 9999}])]
        self.assertEqual(failed_mapping(fail, maps, self.CLI, self.FIRST), (5000, 1401))

    def test_32_bit_dss_matches_the_low_bits(self):
        fail = (5 << 32) + 1234
        maps = [pkt(1, "10.0.9.2", LEG_A, [{"subtype": 2, "dsn8": False, "dsn": 1234, "dll": 1400}]),
                # A 64-bit DSN must match in full.
                pkt(2, "10.0.9.2", LEG_A, [{"subtype": 2, "dsn8": True, "dsn": 1234, "dll": 9999}])]
        self.assertEqual(failed_mapping(fail, maps, self.CLI, 1000), ((5 << 32) + 234, 1400))

    def test_no_mapping_rejected(self):
        fail = (5 << 32) + 1234
        for maps in [[], [pkt(1, "10.0.9.2", LEG_A, [{"subtype": 2, "dsn8": True, "dsn": 1234, "dll": 1400}])],
                     [pkt(1, "10.0.9.2", LEG_A, [{"subtype": 2, "dsn8": False}, {"subtype": 6, "dsn": fail}])],
                     [pkt(1, SRV, LEG_A, [{"subtype": 2, "dsn8": True, "dsn": fail, "dll": 1400}])]]:
            with self.assertRaises(AssertionError, msg=maps):
                failed_mapping(fail, maps, self.CLI, 1000)


class CsumOptions(unittest.TestCase):
    """One packet's MP_CAPABLE A bits and DSS checksum octets, from tshark's per-option fields."""

    def test_dss_lengths(self):
        # NOP, NOP, timestamps, DSS: DATA_ACK 8 + DSN 8 + SSN + DLL + checksum = 28.
        self.assertEqual(csum_options("1,1,8,30", "10,28", "2", "", "1", "1", "1", "1"), ([], [2]))
        # DATA_ACK 4, DSN 4, no checksum: 18; DATA_ACK only: no mapping.
        self.assertEqual(csum_options("30", "18", "2", "", "1", "0", "1", "0"), ([], [0]))
        self.assertEqual(csum_options("30", "12", "2", "", "1", "1", "0", "0"), ([], []))
        # No DATA_ACK, DSN 8, checksum: 20; before it a bare DSS (4) and an ADD_ADDR echo (8).
        self.assertEqual(csum_options("30,30,30", "4,8,20", "2,3,2", "", "False,False", "False,False", "False,True", "False,True"), ([], [2]))

    def test_mp_capable(self):
        # SYN (A=1), third ACK (Length 20), MP_CAPABLE with data (22 or 24).
        self.assertEqual(csum_options("30,2,3,1,4,1,1", "4,4,3,2", "0", "1", "", "", "", ""), ([True], []))
        self.assertEqual(csum_options("1,1,8,30", "10,20", "0", "0", "", "", "", ""), ([False], []))
        self.assertEqual(csum_options("30", "24", "0", "True", "", "", "", ""), ([True], [2]))
        self.assertEqual(csum_options("30", "22", "0", "False", "", "", "", ""), ([False], [0]))


SYN, SYNACK, ACK = (True, False), (True, True), (False, True)


class Csum(unittest.TestCase):
    """INTEROP_CSUM runs (spec G2/G3): A bits as negotiated, a checksum on every mapping exactly
    when negotiated."""

    def wire(self, syn_a, synack_a, csum):
        o = 2 if csum else 0
        return [(*SYN, [syn_a], []), (*SYN, [syn_a], []), (*SYNACK, [synack_a], []), (*ACK, [csum], []),
                (*ACK, [csum], [o]), (*ACK, [], [o, o]), (False, True, [], [])]

    def test_want(self):
        # (SYN A, SYN/ACK A, checksums): a Linux server answers with its sysctl only; ours with
        # the decision. Both ours: the Linux sysctl plays no part.
        for csum, client, server, want in [
                ("on:off", "mptcp-rs", "kernel", (True, False, True)), ("off:on", "mptcp-rs", "kernel", (False, True, True)),
                ("off:off", "mptcp-rs", "kernel", (False, False, False)), ("on:on", "mptcp-rs", "kernel", (True, True, True)),
                ("on:off", "kernel", "mptcp-rs", (False, True, True)), ("off:on", "kernel", "mptcp-rs", (True, True, True)),
                ("off:off", "kernel", "mptcp-rs", (False, False, False)),
                ("off:on", "mptcp-rs", "mptcp-rs", (False, False, False)), ("on:off", "mptcp-rs", "mptcp-rs", (True, True, True))]:
            self.assertEqual(csum_want(csum, client, server), want, (csum, client, server))

    def test_accepted(self):
        for want in [(True, False, True), (False, True, True), (True, True, True), (False, False, False)]:
            csum_checks(want, self.wire(*want))

    def test_wrong_presence_rejected(self):
        for want in [(True, False, True), (False, False, False)]:
            o = 0 if want[2] else 2
            for extra in [(*ACK, [], [o]), (*ACK, [], [2 - o, o]), (*ACK, [want[2]], [o])]:
                with self.assertRaises(AssertionError, msg=(want, extra)):
                    csum_checks(want, self.wire(*want) + [extra])

    def test_wrong_a_bits_rejected(self):
        want = (True, False, True)
        for bad in [(*SYN, [False], []), (*SYNACK, [True], []), (*ACK, [False], [])]:
            with self.assertRaises(AssertionError, msg=bad):
                csum_checks(want, self.wire(*want) + [bad])

    def test_missing_evidence_rejected(self):
        want = (True, False, True)
        wire = self.wire(*want)
        for drop in [lambda p: p[:2] == SYN, lambda p: p[:2] == SYNACK, lambda p: p[2] and p[:2] == ACK, lambda p: p[3]]:
            with self.assertRaises(AssertionError):
                csum_checks(want, [p for p in wire if not drop(p)])


class InfiniteMapping(unittest.TestCase):
    """dataack-strip: the client's one infinite mapping, as (from the client, payload length,
    MPTCP subtype, DLL, DSN) in time order."""
    MPC = (True, 1432, "0", "1432", "")
    ACK = (False, 0, "", "", "")
    INF = lambda n: (True, n, "2", "0", "77")
    PLAIN = (True, 1460, "", "", "")

    def test_once_on_an_ack_only_segment(self):
        # Through 0.2.0: one ACK-only copy, then plain TCP.
        infinite_mapping_checks([self.MPC, self.ACK, InfiniteMapping.INF(0), self.PLAIN, self.ACK, self.PLAIN])

    def test_riding_data_until_acknowledged(self):
        # Since e0d2c5b the copy also rides the data in flight until its first new octet is
        # TCP-ACKed (the failing run 20261014T213926-RiuFja: one ACK-only copy, two on data).
        inf = InfiniteMapping.INF
        infinite_mapping_checks([self.MPC, self.ACK, inf(0), inf(1440), self.ACK, inf(1440), self.ACK, self.PLAIN])

    def test_rules(self):
        inf = InfiniteMapping.INF
        for bad, why in [([self.MPC, self.PLAIN], "no infinite mapping"),
                         ([inf(0), (True, 1440, "2", "0", "78"), self.PLAIN], "two infinite mappings"),
                         ([inf(0), (False, 0, "2", "0", "77"), self.PLAIN], "from the server"),
                         ([inf(1440), self.PLAIN], "no ACK-only copy"),
                         ([inf(0), inf(0), self.PLAIN], "two ACK-only copies"),
                         ([inf(0), inf(1440)], "never retired"),
                         ([inf(0), self.PLAIN, inf(1440), self.PLAIN], "resumed after plain data")]:
            with self.assertRaises(AssertionError, msg=why):
                infinite_mapping_checks(bad)


class Invert(unittest.TestCase):
    """server.py's and kclient.py's `--invert N`, as mptcp-rs-tun's."""
    DATA = bytes(BUF[1000 % 251 : 1000 % 251 + 600])  # stream offsets 1000..1600

    def check(self, data, n):
        inv = []
        ok = verify_chunk(1000, data[:300], n, inv) is None and verify_chunk(1300, data[300:], n, inv) is None
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

    def test_offending_octet(self):
        # The stream offset of the first octet breaking the rule, as mptcp-rs-tun's error.
        two = bytearray(self.DATA)
        two[10] ^= 0xFF
        two[450] ^= 0xFF
        self.assertEqual(verify_chunk(1000, two, 1, []), 1450, "the extra inversion")
        changed = bytearray(self.DATA)
        changed[10] ^= 1
        self.assertEqual(verify_chunk(1000, changed, 2, []), 1010, "the changed octet")
        self.assertEqual(verify_chunk(0, bytes([BUF[0] ^ 1]), 0, []), 0, "offset 0 is an error too")
        self.assertIsNone(verify_chunk(1000, self.DATA, 0, []))


class Delivery(unittest.TestCase):
    """m2-hetero: the receiver's cumulative DATA_ACK over time (offsets from the sender's IDSN + 1)."""
    BASE = (1 << 64) - 1000  # the 64-bit offsets wrap

    def test_advances_only(self):
        acks = [(0.0, self.BASE, True), (1.0, (self.BASE + 500) % (1 << 64), True), (1.5, (self.BASE + 400) % (1 << 64), True),
                (2.0, (self.BASE + 500) % (1 << 64), True), (3.0, (self.BASE + 2000) % (1 << 64), True)]
        self.assertEqual(data_ack_advances(acks, self.BASE), [(1.0, 500), (3.0, 2000)])

    def test_32_bit_acks_promoted(self):
        base = (1 << 32) - 100
        acks = [(1.0, base + 50, True), (2.0, (base + 300) % (1 << 32), False), (3.0, (base + 200) % (1 << 32), False),
                (4.0, (base + 1000000) % (1 << 32), False)]
        self.assertEqual(data_ack_advances(acks, base), [(1.0, 50), (2.0, 300), (4.0, 1000000)])

    def test_summary(self):
        # Longest gap between advances, and Mbit/s per one-second bin after the first advance.
        gap, series = delivery_summary([(10.0, 125000), (10.5, 250000), (13.0, 500000), (13.2, 625000)])
        self.assertAlmostEqual(gap, 2.5)
        self.assertEqual(series, [1.0, 0.0, 0.0, 3.0])

    def test_summary_no_advance(self):
        self.assertEqual(delivery_summary([]), (0.0, []))


if __name__ == "__main__":
    unittest.main()
