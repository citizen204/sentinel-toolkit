"""Optional scapy-backed capture for netmon.

Turns real network traffic into the same `Flow` records the pure-function
detectors consume. scapy is an optional dependency — install it with
`pip install "sentinel-toolkit[capture]"`. Reading a pcap works cross-platform;
live capture additionally needs OS privileges (and npcap on Windows).
"""
from __future__ import annotations

from .checks.flows import Flow


def _flow_from_packet(pkt):
    from scapy.layers.inet import IP, TCP, UDP

    if IP not in pkt:
        return None
    ip = pkt[IP]
    if TCP in pkt:
        return Flow(ip.src, ip.dst, int(pkt[TCP].dport))
    if UDP in pkt:
        return Flow(ip.src, ip.dst, int(pkt[UDP].dport))
    return None


def flows_from_pcap(path) -> list[Flow]:
    """Read a pcap/pcapng file and extract (src_ip, dst_ip, dst_port) flows."""
    from scapy.utils import rdpcap

    flows: list[Flow] = []
    for pkt in rdpcap(str(path)):
        flow = _flow_from_packet(pkt)
        if flow is not None:
            flows.append(flow)
    return flows


def live_capture(interface=None, count: int = 100, timeout=None) -> list[Flow]:
    """Sniff live traffic and extract flows.

    Requires elevated privileges (and npcap on Windows). Not exercised by the
    test suite because it needs a real network interface.
    """
    from scapy.sendrecv import sniff

    flows: list[Flow] = []

    def handle(pkt):
        flow = _flow_from_packet(pkt)
        if flow is not None:
            flows.append(flow)

    sniff(iface=interface, count=count, timeout=timeout, prn=handle, store=False)
    return flows
