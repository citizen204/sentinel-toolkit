from __future__ import annotations

from pathlib import Path

from sentinel.core.finding import Finding
from sentinel.core.scanner import BaseScanner
from .checks.flows import parse_flow_file, check_port_scan, check_host_sweep


class NetmonScanner(BaseScanner):
    """Analyzes network traffic (config.capture_file) for recon patterns.

    config.capture_file may be either a text flow log ('src_ip dst_ip dst_port'
    per line) or a '.pcap'/'.pcapng' capture (parsed with scapy — see capture.py).
    scapy also provides optional live capture. The detection logic is pure and
    fully unit-tested.
    """

    name = "netmon"

    def run(self, config) -> list[Finding]:
        path = getattr(config, "capture_file", None)
        if not path or not Path(path).exists():
            return []
        if str(path).lower().endswith((".pcap", ".pcapng")):
            from .capture import flows_from_pcap
            flows = flows_from_pcap(path)
        else:
            flows = parse_flow_file(path)
        findings: list[Finding] = []
        findings.extend(check_port_scan(flows))
        findings.extend(check_host_sweep(flows))
        return findings
