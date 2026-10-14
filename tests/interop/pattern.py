"""The test pattern of server.py and kclient.py (as mptcp-rs-tun's): byte i = (i*31+7) % 251,
one repeating buffer, sliced at (offset % 251)."""
PAT = bytes((i * 31 + 7) % 251 for i in range(251))
BUF = memoryview(PAT * (262144 // 251 + 2))  # slices are views: no copy per send


def verify_chunk(offset, data, n, inverted):
    """`--invert n`: True when every octet of `data` (at stream `offset`, at most 256 KiB) equals
    the pattern or its bitwise inverse, and at most `n` inverted octets were seen so far. Appends
    the stream offset of each inverted octet to `inverted`; the stream passes if exactly `n` end
    up there."""
    want = BUF[offset % 251 : offset % 251 + len(data)]
    if data == want:
        return True
    for i, (b, w) in enumerate(zip(data, want)):
        if b == w ^ 0xFF:
            inverted.append(offset + i)
        elif b != w:
            return False
    return len(inverted) <= n
