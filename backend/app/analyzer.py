from collections import Counter

def analyze_packets(packets: list) -> dict:
    if not packets:
        return {}

    protocols = Counter(p["protocol"] for p in packets)
    src_ips = Counter(p["src"] for p in packets)
    dst_ports = Counter(p["dport"] for p in packets)
    total_bytes = sum(p["size"] for p in packets)

    threats = detect_threats(packets, src_ips, dst_ports)

    return {
        "total_packets": len(packets),
        "total_bytes": total_bytes,
        "protocols": dict(protocols),
        "top_sources": src_ips.most_common(5),
        "top_ports": dst_ports.most_common(5),
        "threats": threats,
    }

def detect_threats(packets, src_ips, dst_ports) -> list:
    threats = []

    # Port scan detection: one IP hitting many ports
    ip_ports = {}
    for p in packets:
        ip_ports.setdefault(p["src"], set()).add(p["dport"])
    for ip, ports in ip_ports.items():
        if len(ports) > 20:
            threats.append({
                "type": "Port Scan",
                "severity": "HIGH",
                "detail": f"{ip} scanned {len(ports)} ports"
            })

    # DDoS detection: too many packets from one IP
    for ip, count in src_ips.most_common(3):
        if count > len(packets) * 0.5:
            threats.append({
                "type": "Possible DDoS",
                "severity": "CRITICAL",
                "detail": f"{ip} sent {count} packets ({round(count/len(packets)*100)}% of traffic)"
            })

    # Unusual port detection
    suspicious_ports = {22, 23, 3389, 4444, 6666, 9001}
    for port, count in dst_ports.items():
        if port in suspicious_ports and count > 5:
            threats.append({
                "type": "Suspicious Port",
                "severity": "MEDIUM",
                "detail": f"Port {port} accessed {count} times"
            })

    return threats