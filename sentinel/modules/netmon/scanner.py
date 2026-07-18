from __future__ import annotations

from pathlib import Path

from sentinel.core.finding import Finding
from sentinel.core.scanner import BaseScanner, ScannerSkipped

from .checks.flows import (
    DEFAULT_HOST_SWEEP_THRESHOLD,
    DEFAULT_PORT_SCAN_THRESHOLD,
    check_host_sweep,
    check_port_scan,
    parse_flow_file,
)


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
        if not path:
            raise ScannerSkipped(
                "No capture_file is configured, so no traffic was analyzed.",
                "Set capture_file to a flow log or pcap, or exclude netmon.",
            )
        if not Path(path).exists():
            # A typo'd path used to read as "no recon detected".
            raise ScannerSkipped(
                f"capture_file '{path}' does not exist, so no traffic was analyzed.",
                "Correct the capture_file path.",
            )
        if str(path).lower().endswith((".pcap", ".pcapng")):
            from .capture import flows_from_pcap
            flows = flows_from_pcap(path)
        else:
            flows = parse_flow_file(path)
        findings: list[Finding] = []
        findings.extend(
            check_port_scan(
                flows,
                threshold=config.threshold_for(
                    "NET-PORT-SCAN", DEFAULT_PORT_SCAN_THRESHOLD
                ),
            )
        )
        findings.extend(
            check_host_sweep(
                flows,
                threshold=config.threshold_for(
                    "NET-HOST-SWEEP", DEFAULT_HOST_SWEEP_THRESHOLD
                ),
            )
        )
        return findings
