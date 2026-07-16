from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from typing import NamedTuple

from sentinel.core.asset import Asset
from sentinel.core.finding import Finding
from sentinel.core.rule import build_finding

from .. import rules  # noqa: F401 - registers netmon rules

DEFAULT_PORT_SCAN_THRESHOLD = 10
DEFAULT_HOST_SWEEP_THRESHOLD = 10


class Flow(NamedTuple):
    src_ip: str
    dst_ip: str
    dst_port: int


def parse_flow_file(path) -> list[Flow]:
    """Parse a whitespace-separated flow log: 'src_ip dst_ip dst_port' per line.

    Malformed lines are skipped. This flow log can be produced from a live
    scapy capture (documented as an optional extension) or from VPC/NetFlow logs.
    """
    flows: list[Flow] = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        parts = line.split()
        if len(parts) != 3:
            continue
        src, dst, port = parts
        try:
            flows.append(Flow(src, dst, int(port)))
        except ValueError:
            continue
    return flows


def check_port_scan(flows, threshold: int = DEFAULT_PORT_SCAN_THRESHOLD) -> list[Finding]:
    """Flag a source IP that connects to many distinct destination ports."""
    ports_by_src: dict[str, set[int]] = defaultdict(set)
    for flow in flows:
        ports_by_src[flow.src_ip].add(flow.dst_port)

    findings: list[Finding] = []
    for src, ports in ports_by_src.items():
        if len(ports) >= threshold:
            findings.append(
                build_finding(
                    "NET-PORT-SCAN",
                    description=f"{src} connected to {len(ports)} distinct ports.",
                    remediation="Investigate the source host; block it if unauthorized.",
                    asset=Asset(provider="network", type="ip", id=src),
                    evidence={"src_ip": src, "distinct_ports": len(ports)},
                    resource=src,
                )
            )
    return findings


def check_host_sweep(flows, threshold: int = DEFAULT_HOST_SWEEP_THRESHOLD) -> list[Finding]:
    """Flag a source IP that contacts many distinct destination hosts."""
    hosts_by_src: dict[str, set[str]] = defaultdict(set)
    for flow in flows:
        hosts_by_src[flow.src_ip].add(flow.dst_ip)

    findings: list[Finding] = []
    for src, hosts in hosts_by_src.items():
        if len(hosts) >= threshold:
            findings.append(
                build_finding(
                    "NET-HOST-SWEEP",
                    description=f"{src} contacted {len(hosts)} distinct hosts.",
                    remediation="Investigate the source host for reconnaissance activity.",
                    asset=Asset(provider="network", type="ip", id=src),
                    evidence={"src_ip": src, "distinct_hosts": len(hosts)},
                    resource=src,
                )
            )
    return findings
