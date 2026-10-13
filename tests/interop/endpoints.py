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


def mptcp_options(subtypes, m_flags, dsn8_flags, dsns, dlls, reasons):
    """One packet's MPTCP options in option order, from tshark's comma-separated per-option
    values (occurrence=a). DSS (with a mapping) and MP_FAIL both decode to rawdataseqno, so it is
    consumed in option order. Only for packets without an MP_CAPABLE carrying data, whose
    Data-Level Length would shift `dlls`."""
    split = lambda v: [x for x in v.split(",") if x]
    flag = lambda v: v in ("1", "True")
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


Packet = namedtuple("Packet", "t src flow rst ack opts")
Packet.__doc__ = """A captured packet: time, source IP, flow ({(IP, port)} pair), RST and ACK flags,
mptcp_options."""


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


def check_inversion(offsets, start, dll):
    """csum-fail1: exactly one inverted octet (the receiver's `inverted at OFF`), inside the
    mapping that the receiver's MP_FAIL names: [start, start + dll) in stream offsets."""
    assert len(offsets) == 1, f"inverted octets at {offsets}, want exactly one"
    assert start <= offsets[0] < start + dll, f"inverted octet at {offsets[0]}, outside the failed mapping [{start}, {start + dll})"
