import pytest

from sentinel.core.config import Config
from sentinel.core.scanner import ScannerSkipped, all_scanners


def test_netmon_registered():
    import sentinel.modules  # noqa: F401
    assert "netmon" in all_scanners()


def test_run_reads_capture_file(tmp_path):
    from sentinel.modules.netmon.scanner import NetmonScanner

    f = tmp_path / "flows.txt"
    lines = [f"10.0.0.5 10.0.0.1 {p}" for p in range(1, 13)]      # port scan by .5
    lines += [f"10.0.0.9 10.0.0.{i} 445" for i in range(1, 13)]   # host sweep by .9
    f.write_text("\n".join(lines), encoding="utf-8")

    findings = NetmonScanner().run(Config(capture_file=str(f)))

    ids = {finding.id for finding in findings}
    assert ids == {"NET-PORT-SCAN", "NET-HOST-SWEEP"}


def test_run_without_capture_is_skipped_not_clean():
    from sentinel.modules.netmon.scanner import NetmonScanner

    with pytest.raises(ScannerSkipped):
        NetmonScanner().run(Config())


def test_run_with_missing_capture_file_is_skipped(tmp_path):
    """A typo'd capture path used to read as "no reconnaissance detected"."""
    from sentinel.modules.netmon.scanner import NetmonScanner

    with pytest.raises(ScannerSkipped):
        NetmonScanner().run(Config(capture_file=str(tmp_path / "nope.txt")))


def test_run_reads_pcap_capture(tmp_path):
    from scapy.all import IP, TCP, wrpcap

    from sentinel.modules.netmon.scanner import NetmonScanner

    pkts = [IP(src="10.0.0.5", dst="10.0.0.1") / TCP(dport=p) for p in range(1, 13)]
    pcap = tmp_path / "scan.pcap"
    wrpcap(str(pcap), pkts)

    findings = NetmonScanner().run(Config(capture_file=str(pcap)))

    assert any(f.id == "NET-PORT-SCAN" for f in findings)
