from scapy.all import sniff, IP, TCP, UDP, ICMP
from collections import defaultdict
import time

packet_log = []

def capture_packets(interface="eth0", count=100):
    packets = sniff(iface=interface, count=count, timeout=10)
    parsed = []

    for pkt in packets:
        if IP in pkt:
            entry = {
                "time": time.time(),
                "src": pkt[IP].src,
                "dst": pkt[IP].dst,
                "size": len(pkt),
                "protocol": "TCP" if TCP in pkt else "UDP" if UDP in pkt else "ICMP" if ICMP in pkt else "OTHER",
                "sport": pkt[TCP].sport if TCP in pkt else pkt[UDP].sport if UDP in pkt else 0,
                "dport": pkt[TCP].dport if TCP in pkt else pkt[UDP].dport if UDP in pkt else 0,
            }
            parsed.append(entry)

    packet_log.extend(parsed)
    return parsed