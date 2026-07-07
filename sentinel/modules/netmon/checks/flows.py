from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from typing import NamedTuple

from sentinel.core.finding import Finding, Severity


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


def check_port_scan(flows, threshold: int = 10) -> list[Finding]:
    """Flag a source IP that connects to many distinct destination ports."""
    ports_by_src: dict[str, set[int]] = defaultdict(set)
    for flow in flows:
        ports_by_src[flow.src_ip].add(flow.dst_port)

    findings: list[Finding] = []
    for src, ports in ports_by_src.items():
        if len(ports) >= threshold:
            findings.append(
                Finding(
                    id="NET-PORT-SCAN",
                    module="netmon",
                    severity=Severity.HIGH,
                    title="Possible port scan",
                    description=f"{src} connected to {len(ports)} distinct ports.",
                    remediation="Investigate the source host; block it if unauthorized.",
                    category="Reconnaissance",
                    references=["https://attack.mitre.org/techniques/T1046/"],
                    evidence={"src_ip": src, "distinct_ports": len(ports)},
                    resource=src,
                )
            )
    return findings


def check_host_sweep(flows, threshold: int = 10) -> list[Finding]:
    """Flag a source IP that contacts many distinct destination hosts."""
    hosts_by_src: dict[str, set[str]] = defaultdict(set)
    for flow in flows:
        hosts_by_src[flow.src_ip].add(flow.dst_ip)

    findings: list[Finding] = []
    for src, hosts in hosts_by_src.items():
        if len(hosts) >= threshold:
            findings.append(
                Finding(
                    id="NET-HOST-SWEEP",
                    module="netmon",
                    severity=Severity.MEDIUM,
                    title="Possible host sweep",
                    description=f"{src} contacted {len(hosts)} distinct hosts.",
                    remediation="Investigate the source host for reconnaissance activity.",
                    category="Reconnaissance",
                    references=["https://attack.mitre.org/techniques/T1018/"],
                    evidence={"src_ip": src, "distinct_hosts": len(hosts)},
                    resource=src,
                )
            )
    return findings
