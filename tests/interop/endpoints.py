"""The addresses run.sh gives each end, for check.py (which runs at import)."""


def endpoints(scenario, client, server):
    """(server IP, client IPs, join source IP or None) of a run.sh case.
    Server: kernel (server.py) on 10.0.1.2, or mptcp-rs on its TUN as 10.0.7.2.
    Client: mptcp-rs from its TUN as 10.0.9.2 (path A, or 10.0.8.2 for base-b) and joins from
    10.0.8.2 (path B); kernel from the veth addresses 10.0.1.1 (A, or 10.0.2.1 for base-b), and
    the leg-B endpoint 10.0.2.1 for m2-*."""
    srv_ip = {"kernel": "10.0.1.2", "mptcp-rs": "10.0.7.2"}[server]
    a, b = {"mptcp-rs": ("10.0.9.2", "10.0.8.2"), "kernel": ("10.0.1.1", "10.0.2.1")}[client]
    if scenario.startswith("m2-"):
        return srv_ip, {a, b}, b
    return srv_ip, {b if scenario == "base-b" else a}, None


def removed_flow_exempt(scenario, client, flow):
    """True for the subflow m2-remove deletes (the kernel client's leg-B endpoint): Linux may
    close it with a RST and without a FIN. `flow` is a set of (IP, port) pairs."""
    return scenario == "m2-remove" and client == "kernel" and any(ip == "10.0.2.1" for ip, _ in flow)
