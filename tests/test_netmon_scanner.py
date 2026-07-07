from sentinel.core.scanner import all_scanners
from sentinel.core.config import Config


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


def test_run_no_capture_returns_empty():
    from sentinel.modules.netmon.scanner import NetmonScanner
    assert NetmonScanner().run(Config()) == []


def test_run_reads_pcap_capture(tmp_path):
    from scapy.all import IP, TCP, wrpcap
    from sentinel.modules.netmon.scanner import NetmonScanner

    pkts = [IP(src="10.0.0.5", dst="10.0.0.1") / TCP(dport=p) for p in range(1, 13)]
    pcap = tmp_path / "scan.pcap"
    wrpcap(str(pcap), pkts)

    findings = NetmonScanner().run(Config(capture_file=str(pcap)))

    assert any(f.id == "NET-PORT-SCAN" for f in findings)
