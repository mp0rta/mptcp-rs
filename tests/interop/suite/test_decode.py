"""Decoder tests on hand-built pcaps (LINKTYPE_RAW: IPv4/IPv6, no link header)."""
import os
import socket
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(__file__))
import decode  # noqa: E402

SYN, ACK = 0x02, 0x10


def tcp(src, dst, sport, dport, seq, flags=ACK, opts=b"", n=0):
    opts += b"\x01" * (-len(opts) % 4)
    seg = struct.pack("!HHIIBBHHH", sport, dport, seq % (1 << 32), 1, (5 + len(opts) // 4) << 4,
                      flags, 65535, 0, 0) + opts + b"x" * n
    if ":" in src:
        return struct.pack("!IHBB", 6 << 28, len(seg), 6, 64) + socket.inet_pton(
            socket.AF_INET6, src) + socket.inet_pton(socket.AF_INET6, dst) + seg
    return struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(seg), 0, 0, 64, 6, 0,
                       socket.inet_aton(src), socket.inet_aton(dst)) + seg


class Decode(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.dir.cleanup()

    def pcap(self, pkts, name="a.pcap"):
        path = os.path.join(self.dir.name, name)
        with open(path, "wb") as f:
            f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 101))
            for i, p in enumerate(pkts):
                f.write(struct.pack("<IIII", 1000 + i, 0, len(p), len(p)) + p)
        return path

    def flow(self, isn, *data, c="10.0.91.2", s="10.0.1.2"):
        """A SYN from c, then c-to-s segments at (relative seq, length)."""
        return [tcp(c, s, 40000, 5201, isn, SYN)] + [
            tcp(c, s, 40000, 5201, isn + off, n=n) for off, n in data]

    def test_all_mptcp_options_in_one_segment(self):
        dss = bytes([30, 8, 0x20, 0x01]) + struct.pack("!I", 12345)  # DSS, DATA_ACK only
        echo = bytes([30, 8, 0x31, 7]) + socket.inet_aton("10.0.2.2")  # ADD_ADDR, E=1, id 7
        segs = decode.load(self.pcap([tcp("10.0.91.2", "10.0.1.2", 40000, 5201, 1, opts=dss + echo)]))
        self.assertEqual(len(segs), 1)
        m = segs[0].mptcp
        self.assertEqual([o["tcp.options.mptcp.subtype"] for o in m], ["2", "3"])
        self.assertEqual(m[0]["tcp.options.mptcp.rawdataack"], "12345")
        self.assertEqual(m[1]["tcp.options.mptcp.echo"], "1")
        self.assertEqual(m[1]["tcp.options.mptcp.addrid"], "7")
        self.assertEqual(m[1]["tcp.options.mptcp.ipv4"], "10.0.2.2")
        self.assertEqual([o["tcp.option_kind"] for o in segs[0].tcp_opts], ["30", "30"])

    def test_ipv6_flows(self):
        c, s = "fd00:91::2", "dead:beef:1::2"
        segs = decode.load(self.pcap([
            tcp(c, s, 40000, 5201, 100, SYN, bytes([30, 4, 0x01, 0x81])),
            tcp(s, c, 5201, 40000, 900, SYN | ACK),
            tcp(c, s, 40000, 5201, 101, n=500),
        ]))
        self.assertEqual([(g.src, g.dst, g.sport, g.dport) for g in segs],
                         [(c, s, 40000, 5201), (s, c, 5201, 40000), (c, s, 40000, 5201)])
        self.assertEqual([g.direction for g in segs], ["c2s", "s2c", "c2s"])
        self.assertEqual(segs[0].mptcp[0]["tcp.options.mptcp.subtype"], "0")
        self.assertEqual((segs[2].seq, segs[2].len, segs[2].new_bytes), (101, 500, 500))

    def test_reordered_first_transmission_is_new(self):
        segs = decode.load(self.pcap(self.flow(5000, (2000, 1000), (1000, 1000))))
        self.assertEqual([(g.new_bytes, g.old_bytes) for g in segs[1:]], [(1000, 0), (1000, 0)])

    def test_partial_overlap_split(self):
        segs = decode.load(self.pcap(self.flow(5000, (1000, 1000), (1500, 1000), (0, 3000))))
        self.assertEqual([(g.new_bytes, g.old_bytes) for g in segs[1:]],
                         [(1000, 0), (500, 500), (1500, 1500)])

    def test_seq_wrap_unwrapped(self):
        isn = (1 << 32) - 1500
        segs = decode.load(self.pcap(self.flow(isn, (1, 1000), (1001, 1000), (2001, 1000), (1001, 1000))))
        self.assertEqual([g.seq for g in segs], [isn, isn + 1, isn + 1001, isn + 2001, isn + 1001])
        self.assertGreater(segs[3].seq, 1 << 32)
        self.assertEqual([g.new_bytes for g in segs[1:]], [1000, 1000, 1000, 0])

    def test_same_packet_two_points_counted_once(self):
        c, s = "10.0.91.2", "10.0.1.2"
        syn, synack = tcp(c, s, 40000, 5201, 10, SYN), tcp(s, c, 5201, 40000, 70, SYN | ACK)
        up, down = tcp(c, s, 40000, 5201, 11, n=1000), tcp(s, c, 5201, 40000, 71, n=700)
        # Each capture sees both directions; the client's edge sees c2s first and s2c last.
        tun = self.pcap([syn, synack, up, down], "tun.pcap")
        srv = self.pcap([syn, synack, up, down], "srv.pcap")
        segs = decode.load({tun: "cli", srv: "srv"})
        self.assertEqual(len(segs), 8)
        data = [(g.point, g.direction, g.new_bytes, g.old_bytes) for g in segs if g.len]
        self.assertCountEqual(data, [("cli", "c2s", 1000, 0), ("srv", "c2s", 0, 0),
                                     ("srv", "s2c", 700, 0), ("cli", "s2c", 0, 0)])


class Judge(unittest.TestCase):
    """run_suite.py judgement helpers."""

    def test_lost_requires_statistics(self):
        import run_suite
        stats = "10 packets captured\n10 packets received by filter\n0 packets dropped by kernel\n"
        self.assertEqual(run_suite.lost(stats), 0)
        self.assertEqual(run_suite.lost(stats.replace("10 packets captured", "9 packets captured")), 1)
        self.assertIsNone(run_suite.lost("listening on mtun0\n"))
        self.assertIsNone(run_suite.lost("10 packets captured\n"))

    def test_active_closer_is_first_fin_of_any_subflow(self):
        import run_suite
        FIN = 0x01

        # Server FINs at seq 7; a client FIN with ack 8 ACKs it.
        def seg(t, sport, direction, flags=FIN | ACK, ack=0):
            seq = 7 if direction == "s2c" else 0
            g = decode.Seg(t, "cli", "a", "b", sport, 5201, flags, seq, ack, 0, 0, [], [])
            g.direction = direction
            return g
        # A retired subflow closed by the client (TIME-WAIT), then the server closes the last one
        # first: since R31 `Closed` waits for that TIME-WAIT, so the client is an active closer.
        segs = [seg(1, 1, "c2s"), seg(1.1, 1, "s2c"), seg(5, 2, "s2c"), seg(5.1, 2, "c2s", ack=8)]
        self.assertTrue(run_suite.active_closer(segs))
        # The server closes every subflow first: passive on all of them.
        passive = [seg(1, 1, "s2c"), seg(1.1, 1, "c2s", ack=8)] + segs[2:]
        self.assertFalse(run_suite.active_closer(passive))
        # Crossing FINs on a subflow that is not the last to close; the last one closes passively.
        crossed = [seg(5, 1, "s2c"), seg(5.02, 2, "s2c"), seg(5.05, 1, "c2s"), seg(5.1, 2, "c2s", ack=8)]
        self.assertTrue(run_suite.active_closer(crossed))
        self.assertTrue(run_suite.active_closer(passive[:2] + [seg(5, 2, "c2s"), seg(5.1, 2, "s2c")]))
        # Simultaneous close: the server's FIN reached mtun0 first, the client's does not ACK it.
        self.assertTrue(run_suite.active_closer(passive[:3] + [seg(5.1, 2, "c2s")]))
        self.assertFalse(run_suite.active_closer([seg(1, 1, "c2s", ACK)]))
        self.assertFalse(run_suite.active_closer([]))


if __name__ == "__main__":
    unittest.main()
