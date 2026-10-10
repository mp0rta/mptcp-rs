"""Suite pcap decoder (amendment §5.5 c): every TCP and MPTCP option instance of each segment, for
IPv4 and IPv6, from `tshark -T json`; 64-bit sequence numbers unwrapped from the SYN's ISN; and
new versus already-seen payload bytes per flow and direction, split only at that direction's
before point (client to server: "cli" = mtun0; server to client: "srv" = a srv veth)."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
import json
import subprocess

SYN, ACK = 0x02, 0x10
BEFORE = {"c2s": "cli", "s2c": "srv"}


@dataclass
class Seg:
    t: float  # frame.time_epoch
    point: str | None  # "cli", "srv", or None for a lone capture
    src: str
    dst: str
    sport: int
    dport: int
    flags: int
    seq: int  # unwrapped to 64 bits, continuing from the raw ISN
    ack: int  # raw
    len: int
    win: int  # raw, unscaled
    tcp_opts: list  # every TCP option instance in wire order: tshark fields, trees flattened
    mptcp: list  # the kind-30 subset of tcp_opts
    direction: str | None = None  # "c2s" if src sent the flow's SYN, else "s2c"; None without SYN
    new_bytes: int = 0  # payload bytes never seen before in this flow and direction
    old_bytes: int = 0  # retransmitted or duplicate payload bytes (both 0 off the before point)

    @property
    def flow(self):
        return tuple(sorted([(self.src, self.sport), (self.dst, self.dport)]))


def _get(obj, key):
    return next((v for k, v in obj if k == key), None)


def _flat(obj):
    out = {}
    for k, v in obj:
        out.update(_flat(v)) if isinstance(v, tuple) else out.__setitem__(k, v)
    return out


def _segs(pcap, point):
    p = subprocess.run(["tshark", "-r", str(pcap), "-Y", "tcp && !icmp && !icmpv6", "-T", "json", "-J", "frame ip ipv6 tcp",
                        "--disable-protocol", "iperf3", "-o", "tcp.analyze_sequence_numbers:FALSE",
                        "-o", "mptcp.analyze_mptcp:FALSE"], capture_output=True, text=True)
    if p.returncode:
        size = pcap.stat().st_size if pcap.exists() else None
        raise RuntimeError(f"tshark -r {pcap} ({size} bytes): exit {p.returncode}: {p.stderr.strip()}")
    out = p.stdout
    # Objects become tuples of pairs: tshark repeats a key once per option instance.
    for p in json.loads(out, object_pairs_hook=tuple):
        layers = _get(_get(p, "_source"), "layers")
        ip, tcp = _get(layers, "ip"), _get(layers, "tcp")
        v = "ip" if ip else "ipv6"
        ip = ip or _get(layers, "ipv6")
        opts = [_flat(o) for _, o in _get(tcp, "tcp.options_tree") or ()
                if isinstance(o, tuple) and _get(o, "tcp.option_kind") is not None]
        yield Seg(float(_get(_get(layers, "frame"), "frame.time_epoch")), point, _get(ip, v + ".src"),
                  _get(ip, v + ".dst"), int(_get(tcp, "tcp.srcport")), int(_get(tcp, "tcp.dstport")),
                  int(_get(tcp, "tcp.flags"), 16), int(_get(tcp, "tcp.seq_raw")), int(_get(tcp, "tcp.ack_raw")),
                  int(_get(tcp, "tcp.len")), int(_get(tcp, "tcp.window_size_value")), opts,
                  [o for o in opts if o["tcp.option_kind"] == "30"])


def _add(iv, a, b):
    """Insert [a, b) into the sorted disjoint interval list iv; return how many bytes were unseen."""
    new, lo, hi, keep = b - a, a, b, []
    for x, y in iv:
        if y < a or x > b:
            keep.append((x, y))
        else:
            new -= max(0, min(y, b) - max(x, a))
            lo, hi = min(lo, x), max(hi, y)
    iv[:] = sorted(keep + [(lo, hi)])
    return new


def load(pcap):
    """Segments of one capture (a path), or of several ({path: "cli" | "srv"}), in time order."""
    points = pcap.items() if isinstance(pcap, dict) else [(pcap, None)]
    with ThreadPoolExecutor() as ex:  # one tshark per capture, concurrently
        segs = sorted((g for gs in ex.map(lambda p: list(_segs(*p)), points) for g in gs), key=lambda g: g.t)
    init, last, seen = {}, {}, {}
    for g in segs:
        side = (g.flow, g.src, g.sport)
        if g.flags & (SYN | ACK) == SYN:
            init.setdefault(g.flow, (g.src, g.sport))
        if g.flow in init:
            g.direction = "c2s" if init[g.flow] == (g.src, g.sport) else "s2c"
        # Nearest 64-bit value with these low 32 bits, relative to the highest seen so far.
        top = last.setdefault(side, g.seq)
        g.seq = top + ((g.seq - top + (1 << 31)) % (1 << 32) - (1 << 31))
        last[side] = max(top, g.seq)
        if g.len and g.point in (None, BEFORE.get(g.direction, g.point)):
            start = g.seq + (1 if g.flags & SYN else 0)
            g.new_bytes = _add(seen.setdefault(side, []), start, start + g.len)
            g.old_bytes = g.len - g.new_bytes
    return segs
