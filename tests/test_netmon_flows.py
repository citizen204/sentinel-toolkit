from sentinel.modules.netmon.checks.flows import (
    Flow, check_port_scan, check_host_sweep, parse_flow_file,
)
from sentinel.core.finding import Severity


def test_port_scan_flagged():
    flows = [Flow("10.0.0.5", "10.0.0.1", p) for p in range(1, 13)]  # 12 ports
    findings = check_port_scan(flows, threshold=10)
    assert len(findings) == 1
    assert findings[0].id == "NET-PORT-SCAN"
    assert findings[0].resource == "10.0.0.5"
    assert findings[0].severity is Severity.HIGH
    assert findings[0].evidence["distinct_ports"] == 12


def test_port_scan_below_threshold_not_flagged():
    flows = [Flow("10.0.0.5", "10.0.0.1", p) for p in range(1, 5)]
    assert check_port_scan(flows, threshold=10) == []


def test_host_sweep_flagged():
    flows = [Flow("10.0.0.5", f"10.0.0.{i}", 445) for i in range(1, 13)]
    findings = check_host_sweep(flows, threshold=10)
    assert len(findings) == 1
    assert findings[0].id == "NET-HOST-SWEEP"
    assert findings[0].severity is Severity.MEDIUM


def test_parse_flow_file_skips_malformed(tmp_path):
    f = tmp_path / "flows.txt"
    f.write_text(
        "10.0.0.5 10.0.0.1 22\n10.0.0.5 10.0.0.1 80\nbad line here\n10.0.0.5 x y\n",
        encoding="utf-8",
    )
    flows = parse_flow_file(f)
    assert len(flows) == 2
    assert flows[0] == Flow("10.0.0.5", "10.0.0.1", 22)
