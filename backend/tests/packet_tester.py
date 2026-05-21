from scapy.all import IP, TCP, UDP, ICMP, send, RandIP
import time

TARGET = "127.0.0.1"  # test locally

def test_ddos():
    print("[*] Simulating DDoS attack...")
    send(IP(src="1.2.3.4", dst=TARGET)/UDP(dport=80), count=1000, verbose=0)
    print("[+] Sent 1000 UDP packets from 1.2.3.4")

def test_port_scan():
    print("[*] Simulating port scan...")
    for port in range(1, 35):
        send(IP(src="5.5.5.5", dst=TARGET)/TCP(dport=port, flags="S"), verbose=0)
    print("[+] Scanned 34 ports from 5.5.5.5")

def test_syn_flood():
    print("[*] Simulating SYN flood...")
    send(IP(src=RandIP(), dst=TARGET)/TCP(dport=443, flags="S"), count=500, verbose=0)
    print("[+] Sent 500 SYN packets with random IPs")

def test_suspicious_ports():
    print("[*] Testing suspicious ports...")
    for port in [22, 4444, 6666, 3389, 9001]:
        send(IP(src="9.9.9.9", dst=TARGET)/TCP(dport=port, flags="S"), count=10, verbose=0)
    print("[+] Hit suspicious ports 10x each")

def test_normal_traffic():
    print("[*] Sending normal traffic...")
    send(IP(src="192.168.1.1", dst=TARGET)/TCP(dport=80, flags="S"), count=20, verbose=0)
    send(IP(src="192.168.1.2", dst=TARGET)/TCP(dport=443, flags="S"), count=20, verbose=0)
    print("[+] Sent normal HTTP/HTTPS traffic")

if __name__ == "__main__":
    print("=== Network Agent Attack Simulator ===\n")
    test_normal_traffic()
    time.sleep(1)
    test_port_scan()
    time.sleep(1)
    test_ddos()
    time.sleep(1)
    test_suspicious_ports()
    time.sleep(1)
    test_syn_flood()
    print("\n[*] All tests done. Now call your /analyze endpoint!")