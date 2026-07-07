from sentinel.modules.netmon.checks.flows import Flow
from sentinel.modules.netmon.capture import flows_from_pcap


def test_flows_from_pcap_extracts_tcp_and_udp(tmp_path):
    from scapy.all import IP, TCP, UDP, wrpcap

    pkts = [
        IP(src="10.0.0.5", dst="10.0.0.1") / TCP(dport=22),
        IP(src="10.0.0.5", dst="10.0.0.1") / TCP(dport=80),
        IP(src="10.0.0.5", dst="10.0.0.2") / UDP(dport=53),
    ]
    pcap = tmp_path / "capture.pcap"
    wrpcap(str(pcap), pkts)

    flows = flows_from_pcap(pcap)

    assert Flow("10.0.0.5", "10.0.0.1", 22) in flows
    assert Flow("10.0.0.5", "10.0.0.1", 80) in flows
    assert Flow("10.0.0.5", "10.0.0.2", 53) in flows
    assert len(flows) == 3


def test_flows_from_pcap_ignores_non_ip_packets(tmp_path):
    from scapy.all import Ether, ARP, wrpcap

    pcap = tmp_path / "arp.pcap"
    wrpcap(str(pcap), [Ether() / ARP()])

    assert flows_from_pcap(pcap) == []
