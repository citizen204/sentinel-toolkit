from __future__ import annotations

from pathlib import Path

from sentinel.core.finding import Finding
from sentinel.core.scanner import BaseScanner
from .checks.flows import parse_flow_file, check_port_scan, check_host_sweep


class NetmonScanner(BaseScanner):
    """Analyzes a network flow log (config.capture_file) for recon patterns.

    Live packet capture with scapy is an optional extension: capture traffic to a
    flow log ('src_ip dst_ip dst_port' per line), then point config.capture_file
    at it. The detection logic here is pure and fully unit-tested.
    """

    name = "netmon"

    def run(self, config) -> list[Finding]:
        path = getattr(config, "capture_file", None)
        if not path or not Path(path).exists():
            return []
        flows = parse_flow_file(path)
        findings: list[Finding] = []
        findings.extend(check_port_scan(flows))
        findings.extend(check_host_sweep(flows))
        return findings
