"""The addresses run.sh gives each end, and the scenario rules, for check.py (which runs at
import)."""
from collections import namedtuple


def two_subflows(scenario):
    """The initial subflow on path A and one join on path B."""
    return scenario.startswith("m2-") or scenario == "csum-fail2"


def endpoints(scenario, client, server):
    """(server IP, client IPs, join source IP or None) of a run.sh case.
    Server: kernel (server.py) on 10.0.1.2, or mptcp-rs on its TUN as 10.0.7.2.
    Client: mptcp-rs from its TUN as 10.0.9.2 (path A, or 10.0.8.2 for base-b) and joins from
    10.0.8.2 (path B); kernel from the veth addresses 10.0.1.1 (A, or 10.0.2.1 for base-b), and
    the leg-B endpoint 10.0.2.1 for m2-* and csum-fail2."""
    srv_ip = {"kernel": "10.0.1.2", "mptcp-rs": "10.0.7.2"}[server]
    a, b = {"mptcp-rs": ("10.0.9.2", "10.0.8.2"), "kernel": ("10.0.1.1", "10.0.2.1")}[client]
    if two_subflows(scenario):
        return srv_ip, {a, b}, b
    return srv_ip, {b if scenario == "base-b" else a}, None


def removed_flow_exempt(scenario, client, flow):
    """True for the subflow m2-remove deletes (the kernel client's leg-B endpoint): Linux may
    close it with a RST and without a FIN. `flow` is a set of (IP, port) pairs."""
    return scenario == "m2-remove" and client == "kernel" and any(ip == "10.0.2.1" for ip, _ in flow)


def flag(v):
    """A tshark boolean field: "1"/"True" (its spelling varies by field)."""
    return v in ("1", "True")


def mptcp_options(subtypes, m_flags, dsn8_flags, dsns, dlls, reasons):
    """One packet's MPTCP options in option order, from tshark's comma-separated per-option
    values (occurrence=a). DSS (with a mapping) and MP_FAIL both decode to rawdataseqno, so it is
    consumed in option order. Only for packets without an MP_CAPABLE carrying data, whose
    Data-Level Length would shift `dlls`."""
    split = lambda v: [x for x in v.split(",") if x]
    m, d8, dsn, dll, why = map(iter, map(split, (m_flags, dsn8_flags, dsns, dlls, reasons)))
    out = []
    for st in map(int, split(subtypes)):
        o = {"subtype": st}
        if st == 2:
            o["dsn8"] = flag(next(d8))
            if flag(next(m)):
                o.update(dsn=int(next(dsn)), dll=int(next(dll)))
        elif st == 6:
            o["dsn"] = int(next(dsn))
        elif st == 8:
            o["reason"] = int(next(why), 0)
        out.append(o)
    return out


Packet = namedtuple("Packet", "t src flow rst ack opts seq len ackno", defaults=(0, 0, 0))
Packet.__doc__ = """A captured packet: time, source IP, flow ({(IP, port)} pair), RST and ACK flags,
mptcp_options, raw TCP seq, payload length, raw TCP ACK number."""


def csum_fail_checks(scenario, packets, srv, join):
    """csum-fail1/2's wire rules (M4b spec section 7 item 2) over `packets`, every Packet with a
    RST, an MP_FAIL or an infinite mapping. Returns the flows exempt from the FIN rule.
    csum-fail1: MP_FAIL each way, an infinite mapping, no RST. csum-fail2: no infinite mapping;
    exactly one reset with MPTCP options, on the leg-B subflow (from `join`), carrying MP_FAIL
    and MP_TCPRST reason 6. The only other RSTs allowed follow it from the same end on the same
    subflow, without ACK or MPTCP options: answers to segments still in flight to the closed
    subflow (RFC 9293 L3276-3293), as Linux and mptcp-rs both send."""
    has = lambda opts, st: any(o["subtype"] == st for o in opts)
    fails = {p.src == srv for p in packets if has(p.opts, 6)}
    infinite = [p for p in packets if any(o["subtype"] == 2 and o.get("dll") == 0 for o in p.opts)]
    rsts = [p for p in packets if p.rst]
    if scenario == "csum-fail1":
        assert fails == {True, False}, "MP_FAIL not sent in each direction"
        assert infinite, "no infinite mapping"
        assert not rsts, "RST present"
        return set()
    assert not infinite, "infinite mapping with two subflows"
    resets = [p for p in rsts if p.opts]
    assert len(resets) == 1, f"{len(resets)} RSTs with MPTCP options, want exactly one: {resets}"
    r = resets[0]
    assert any(ip == join for ip, _ in r.flow), f"RST not on the leg-B subflow: {sorted(r.flow)}"
    assert has(r.opts, 6) and any(o["subtype"] == 8 and o["reason"] == 6 for o in r.opts), f"RST without MP_FAIL and MP_TCPRST 6: {r.opts}"
    for p in rsts:
        assert p is r or (p.flow, p.src) == (r.flow, r.src) and p.t > r.t and not p.ack, f"RST other than the reset's answers to segments in flight: {p}"
    return {r.flow}


def own_capture(client, server):
    """The mptcp-rs end's own TUN capture (csum-fail1 has exactly one): the packets that reached
    it, in the order it read them."""
    return "server-tun.pcap" if server == "mptcp-rs" else "tun.pcap"


def mp_fail_bounds(packets, ours):
    """csum-fail1: the MP_FAIL traffic is bounded (M4b spec G13, G18), over `packets`, every
    packet around the MP_FAIL traffic in the capture of our end (`ours`: the mptcp-rs end's
    IPs; own_capture), so that only what reached us counts. Our MP_FAILs ride our segments
    until our state ends (the echo's round trip, or the retiring ACK's: tens of ms here), then
    come only as G13 retries on a pure ACK, the interval starting at the RTO (at least 1 s,
    rtt.rs MIN_RTO) and doubling: +1, +3, +7, +15, +31, +63 s, none later than 120 s after our
    first (mptcp.rs mp_fail_deadline). Split at gaps of 0.5 s or more, each direction has at
    most 1 + 6 episodes (Linux answers each late MP_FAIL of ours once its timer is clear: at
    most one episode per one of ours), each shorter than 0.5 s, and nothing of ours comes later
    than 120 s after our first (the spacing itself: see the comment below). An answer of ours
    after our fallback would loop with such a Linux peer and keep an episode going. G18, directly: as the echoer, our later pure-ACK MP_FAILs are retries, 1 s or more
    apart (0.5 s here, for capture jitter), and once the peer TCP-ACKs an octet sent only with
    our infinite mapping (the dataack-strip rule), retiring our echo, none of ours follows our
    first segment without MP_FAIL on that subflow (the run before it was built before we read
    that ACK: 0.4 ms seen, longer if the process pauses mid-drain); as the originator, no
    MP_FAIL of ours ACKs the peer's data sent after the first echo or infinite mapping of the
    peer that reached us (one in-order path)."""
    has = lambda p, st: any(o["subtype"] == st for o in p.opts)
    infinite = lambda p: any(o["subtype"] == 2 and o.get("dll") == 0 for o in p.opts)
    packets = sorted(packets, key=lambda p: p.t)
    fails = [p for p in packets if has(p, 6)]
    mine = [p for p in fails if p.src in ours]
    peer = [p for p in fails if p.src not in ours]
    for who, ps in [("us", mine), ("the peer", peer)]:
        episodes = [[p.t] for p in ps[:1]]
        for a, b in zip(ps, ps[1:]):
            if b.t - a.t >= 0.5:
                episodes.append([])
            episodes[-1].append(b.t)
        assert len(episodes) <= 7, f"{len(episodes)} MP_FAIL episodes from {who}, want at most 7 (G13)"
        long = [(e[0], e[-1]) for e in episodes if e[-1] - e[0] >= 0.5]
        assert not long, f"MP_FAIL from {who} lasts 0.5 s or more: {long}"
    assert mine[-1].t - mine[0].t <= 120, f"G13: MP_FAIL from us {mine[-1].t - mine[0].t:.3f} s after our first, past 120 s"
    # The retry spacing (RTO, then doubling) is not checked here: timer emissions cannot be
    # told apart on the wire. Unit tests with injected time cover it, in
    # crates/mptcp-rs/src/endpoint/mptcp_tests/mp_fail.rs: waiting_sends_mp_fail_on_acks_and_retries
    # (RTO, 2 RTO), echoer_idle_retries_bounded, waiting_times_out_at_120s and
    # after_fallback_mp_fail_triggers_nothing.
    if peer and peer[0].t < mine[0].t:
        pure = [p.t for p in mine if p.len == 0]
        early = [(a, b) for a, b in zip(pure, pure[1:]) if b - a < 0.5]
        assert not early, f"G18: our pure-ACK MP_FAIL under 0.5 s after the previous one, not a G13 retry: {early}"
        # Retirement: the octets of our infinite-mapping copies before our first plain data,
        # less those also sent without it; a peer ACK covering one retires the echo.
        t0 = min((p.t for p in packets if p.src in ours and infinite(p)), default=None)
        assert t0, "no infinite mapping from us, the echoer"
        plain = [p for p in packets if p.src in ours and p.len > 0 and p.t > t0 and not any("dll" in o for o in p.opts)]
        if not plain:
            return
        octets = lambda p: {(p.seq + k) % (1 << 32) for k in range(p.len)}
        sent = [p for p in packets if p.src in ours and p.len > 0 and p.t < plain[0].t]
        only = set().union(*(octets(p) for p in sent if infinite(p))) - set().union(*(octets(p) for p in sent if not infinite(p)))
        # A cumulative ACK covers one of them once it is past the first, in sequence order.
        first = min(only, key=lambda x: (x - sent[0].seq) % (1 << 32), default=None)
        retire = next((p for p in packets if p.src not in ours and t0 <= p.t < plain[0].t and first is not None
                       and (p.ackno - first - 1) % (1 << 32) < (1 << 31)), None)
        assert retire, "infinite mapping retired before a TCP ACK of an octet sent only with it"
        clean = next((p.t for p in packets if p.src in ours and p.flow == retire.flow and p.t > retire.t and not has(p, 6)), float("inf"))
        late = [p for p in mine if p.t > clean]
        assert not late, f"G18: MP_FAIL from us after our echo retired (TCP ACK at {retire.t}): {late[:3]}"
    else:
        trig = min((p for p in packets if p.src not in ours and p.t > mine[0].t and (has(p, 6) or infinite(p))),
                   key=lambda p: p.t, default=None)
        assert trig, "no echo or infinite mapping from the peer reached us"
        late = [p for p in mine if (p.ackno - trig.seq - 1) % (1 << 32) < (1 << 31)]
        assert not late, f"G18: MP_FAIL from us after our fallback, on an ACK past the peer's seq {trig.seq} at {trig.t}: {late[:3]}"


def check_inversion(offsets, start, dll):
    """csum-fail1: exactly one inverted octet (the receiver's `inverted at OFF`), inside the
    mapping that the receiver's MP_FAIL names: [start, start + dll) in stream offsets."""
    assert len(offsets) == 1, f"inverted octets at {offsets}, want exactly one"
    assert start <= offsets[0] < start + dll, f"inverted octet at {offsets[0]}, outside the failed mapping [{start}, {start + dll})"


def infinite_mapping_checks(segs):
    """dataack-strip: one fallback, so one infinite mapping, from the client, over every segment
    on the client's TUN in time order as (from the client, payload length, first MPTCP subtype,
    DLL, DSN, SSN, TCP seq, TCP ACK), the MPTCP fields as tshark strings. The mapping goes out
    once on an ACK-only segment and rides every data segment until an octet that only ever
    travelled with it is TCP-ACKed (M4b spec, MP_FAIL state machine; since e0d2c5b), so copies
    are counted per mapping, not per segment; a mapping is its (DSN, SSN) anchor (RFC 8684
    L1368-1370). Retired for good, and only after that ACK: plain client data follows the last
    copy, no copy follows it, and an earlier server ACK covers an octet sent only with the
    mapping. The TUN lists the ACKs as they reached the client, so a correct client always
    passes; one retiring on an ACK still unread in the TUN queue passes too."""
    inf = [i for i, s in enumerate(segs) if s[2:4] == ("2", "0")]
    assert inf, "no infinite mapping"
    assert all(segs[i][0] for i in inf), "infinite mapping from the server"
    anchors = sorted({segs[i][4:6] for i in inf})
    assert len(anchors) == 1, f"more than one infinite mapping: (DSN, SSN) {anchors}"
    assert sum(segs[i][1] == 0 for i in inf) == 1, "infinite mapping not on exactly one ACK-only segment"
    plain = [i for i, s in enumerate(segs) if s[0] and s[1] > 0 and not s[2] and i > inf[0]]
    assert plain and plain[0] > inf[-1], "infinite mapping not retired: no plain client data after its last copy"
    octets = lambda s: {(s[6] + k) % (1 << 32) for k in range(s[1])}
    only = set().union(*(octets(segs[i]) for i in inf))
    only -= set().union(*(octets(s) for s in segs[:plain[0]] if s[0] and s[2:4] != ("2", "0")))
    covers = lambda ack: any((ack - x - 1) % (1 << 32) < (1 << 31) for x in only)
    assert any(not s[0] and covers(s[7]) for s in segs[inf[0]:plain[0]]), "infinite mapping retired before a TCP ACK of an octet sent only with it"


def mp_fail_dsn(packets, receiver):
    """csum-fail1: the DSN of the first MP_FAIL from `receiver` (a set of IPs)."""
    fails = [o["dsn"] for p in sorted(packets, key=lambda p: p.t) if p.src in receiver for o in p.opts if o["subtype"] == 6]
    assert fails, f"no MP_FAIL from {receiver}"
    return fails[0]


def failed_mapping(fail, packets, sender, first):
    """csum-fail1: the mapping that an MP_FAIL names by its first DSN `fail` (RFC 8684
    L2372-2375), as (start, Data-Level Length) in stream offsets from `first`, the sender's IDSN
    + 1. A DSS from `sender` with a 32-bit DSN matches on the low 32 bits. The largest length
    wins: Linux re-declares its last mapping with the DATA_FIN added."""
    dlls = [o["dll"] for p in packets if p.src in sender for o in p.opts
            if o["subtype"] == 2 and "dsn" in o and o["dsn"] == fail % (1 << (64 if o["dsn8"] else 32))]
    assert dlls, f"no DSS from {sender} maps DSN {fail}"
    return (fail - first) % (1 << 64), max(dlls)


def csum_options(kinds, lens, subtypes, a_flags, ack_flags, ack8_flags, m_flags, dsn8_flags):
    """One packet's MP_CAPABLE A bits, and the checksum octets (0 or 2) of each DSS mapping and
    MP_CAPABLE with data, from tshark's per-option values (occurrence=a). Presence is read from
    the option length: tshark decodes the checksum field only in some cases. NOP and EOL have no
    tcp.option_len."""
    split = lambda v: [x for x in v.split(",") if x]
    sized = [k for k in split(kinds) if k not in ("0", "1")]
    lengths = [int(n) for k, n in zip(sized, split(lens)) if k == "30"]
    a, da, da8, m, d8 = map(iter, map(split, (a_flags, ack_flags, ack8_flags, m_flags, dsn8_flags)))
    bits, octets = [], []
    for length, st in zip(lengths, map(int, split(subtypes))):
        if st == 0:
            bits.append(flag(next(a)))
            if length > 20:  # with data: Length 22, or 24 with the checksum (RFC 8684 L834-843)
                octets.append(length - 22)
        elif st == 2:
            ack, ack8, mapping, dsn8 = flag(next(da)), flag(next(da8)), flag(next(m)), flag(next(d8))
            if mapping:
                # kind, length, flags (4); DATA_ACK; DSN; SSN (4); Data-Level Length (2).
                octets.append(length - (4 + (8 if ack8 else 4 if ack else 0) + (8 if dsn8 else 4) + 6))
    return bits, octets


def csum_want(csum, client, server):
    """run.sh's INTEROP_CSUM (<ours>:<linux>, each on|off) as the M4b spec's G2 decision:
    (MP_CAPABLE SYN A, SYN/ACK A, checksums used). The SYN carries the client's setting; an
    mptcp-rs server answers with the decision, a Linux server with its sysctl only; the third
    ACK carries the decision (either end's setting)."""
    ours, linux = (v == "on" for v in csum.split(":"))
    setting = {"mptcp-rs": ours, "kernel": linux}
    c, s = setting[client], setting[server]
    return c, (c or s) if server == "mptcp-rs" else s, c or s


def csum_checks(want, packets):
    """INTEROP_CSUM runs: MP_CAPABLE A bits as `want` (csum_want), and a checksum on every DSS
    mapping exactly when checksums are used (spec G2, G3). `packets`: (SYN, ACK, A bits, checksum
    octets) per packet, from csum_options. Returns a summary."""
    syn_a, synack_a, csum = want
    for what, flags, w in [("SYN", (True, False), syn_a), ("SYN/ACK", (True, True), synack_a),
                           ("third ACK / with data", (False, True), csum)]:
        got = {a for s, k, bits, _ in packets if (s, k) == flags for a in bits}
        assert got == {w}, f"MP_CAPABLE {what} A bits {sorted(got)}, want {w}"
    octets = [o for *_, os in packets for o in os]
    want_octets = 2 if csum else 0
    assert octets, "no DSS mapping"
    bad = sum(o != want_octets for o in octets)
    assert not bad, f"{bad} of {len(octets)} mappings without {want_octets} checksum octets"
    return f"checksums {'on' if csum else 'off'}: A bits SYN={int(syn_a)} SYN/ACK={int(synack_a)} third ACK={int(csum)}, {len(octets)} mappings with {want_octets} checksum octets"


def data_ack_advances(acks, base):
    """The receiver's cumulative DATA_ACK advances [(time, offset)], from its (time, raw DATA_ACK,
    64-bit) in time order. Offsets are from the sender's IDSN + 1 (`base`); a 32-bit DATA_ACK is
    promoted to the offset nearest the current one."""
    out, cur = [], 0
    for t, v, ack64 in acks:
        a = (v - base) % (1 << 64) if ack64 else cur + ((v - base - cur + (1 << 31)) % (1 << 32) - (1 << 31))
        if a > cur:
            out.append((t, a))
            cur = a
    return out


def delivery_summary(advances, start, n):
    """(longest gap in s without a DATA_ACK advance, Mbit/s per one-second bin), from `start`, the
    sender's first payload, until the advance that covers all `n` octets: a stall before the
    first advance counts, and missing evidence fails."""
    assert advances, "no DATA_ACK advance"
    done = next((i for i, (_, a) in enumerate(advances) if a >= n), None)
    assert done is not None, f"DATA_ACK stops at {advances[-1][1]}, short of {n}"
    pts = [(start, 0)] + advances[:done + 1]
    bins = [0] * (int(pts[-1][0] - start) + 1)
    for (_, a0), (t1, a1) in zip(pts, pts[1:]):
        bins[int(t1 - start)] += a1 - a0
    gap = max(t1 - t0 for (t0, _), (t1, _) in zip(pts, pts[1:]))
    return gap, [round(b * 8 / 1e6, 1) for b in bins]
