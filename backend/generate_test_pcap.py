import os
import sys
import time

try:
    from scapy.all import wrpcap, Ether, ARP, IP, TCP, UDP, DNS, DNSQR, DNSRR
except ImportError:
    print("[!] Scapy not installed. Run this script inside the virtual environment.")
    sys.exit(1)

def create_sample_pcap(filename="test_capture.pcap"):
    packets = []
    
    print("[*] Generating mock network traffic...")
    
    # 1. ARP Sweep/Spoofing Simulation
    # Normal ARP mapping
    packets.append(Ether(src="00:11:22:33:44:55", dst="ff:ff:ff:ff:ff:ff")/ARP(op=1, hwsrc="00:11:22:33:44:55", psrc="192.168.1.100", pdst="192.168.1.1"))
    # ARP spoofing attack: another MAC claiming to be 192.168.1.100
    packets.append(Ether(src="00:aa:bb:cc:dd:ee", dst="ff:ff:ff:ff:ff:ff")/ARP(op=2, hwsrc="00:aa:bb:cc:dd:ee", psrc="192.168.1.100", pdst="192.168.1.1"))
    
    # 2. Port Scanning Simulation (Host 192.168.1.50 scanning 192.168.1.1)
    print("[*] Simulating Port Scan (TCP SYN Sweep)...")
    for port in [21, 22, 23, 25, 53, 80, 110, 139, 443, 445, 1433, 3306, 3389, 8080, 8443, 9000, 27017, 5000, 9200, 6379, 11211]:
        # TCP SYN flag = 0x02
        packets.append(Ether(src="00:11:22:33:44:55", dst="00:aa:bb:cc:dd:ee")/IP(src="192.168.1.50", dst="192.168.1.1", ttl=64)/TCP(sport=49152, dport=port, flags="S", seq=1000))
    
    # 3. Plaintext Credentials Leak Simulation
    # TCP Handshake for HTTP (Port 80)
    print("[*] Simulating Cleartext HTTP Login Traffic...")
    src_ip = "192.168.1.10"
    dst_ip = "192.168.1.20"
    
    # SYN, SYN-ACK, ACK
    packets.append(Ether()/IP(src=src_ip, dst=dst_ip, ttl=128)/TCP(sport=51234, dport=80, flags="S", seq=100))
    packets.append(Ether()/IP(src=dst_ip, dst=src_ip, ttl=64)/TCP(sport=80, dport=51234, flags="SA", seq=5000, ack=101))
    packets.append(Ether()/IP(src=src_ip, dst=dst_ip, ttl=128)/TCP(sport=51234, dport=80, flags="A", seq=101, ack=5001))
    
    # HTTP POST Request with plaintext passwords
    http_payload = (
        "POST /login.php HTTP/1.1\r\n"
        "Host: 192.168.1.20\r\n"
        "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: 46\r\n"
        "\r\n"
        "username=administrator&password=P@ssw0rd1234!\r\n"
    )
    packets.append(Ether()/IP(src=src_ip, dst=dst_ip, ttl=128)/TCP(sport=51234, dport=80, flags="PA", seq=101, ack=5001)/http_payload.encode())
    
    # HTTP Response (200 OK)
    http_response = (
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 18\r\n"
        "\r\n"
        "<h1>Logged in</h1>"
    )
    packets.append(Ether()/IP(src=dst_ip, dst=src_ip, ttl=64)/TCP(sport=80, dport=51234, flags="PA", seq=5001, ack=http_payload.encode().__len__() + 101)/http_response.encode())
    
    # 4. DNS Tunneling & Anomalous queries
    print("[*] Simulating Anomalous DNS Queries...")
    dns_server = "8.8.8.8"
    client_ip = "192.168.1.15"
    
    # TXT Record Query (indicators of C2)
    packets.append(
        Ether()/IP(src=client_ip, dst=dns_server)/UDP(sport=53, dport=53)/
        DNS(id=1, qr=0, qd=DNSQR(qname="c2-server-checkin.badnasty.com", qtype="TXT"))
    )
    
    # Abnormally long domain queries (data exfiltration)
    long_domain = "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6.exfiltrated-sensitive-data.attacker.com"
    packets.append(
        Ether()/IP(src=client_ip, dst=dns_server)/UDP(sport=54, dport=53)/
        DNS(id=2, qr=0, qd=DNSQR(qname=long_domain, qtype="A"))
    )
    
    # Write to PCAP file
    wrpcap(filename, packets)
    print(f"[+] Sample PCAP successfully generated: {filename}")

if __name__ == "__main__":
    out_file = "test_capture.pcap"
    if len(sys.argv) > 1:
        out_file = sys.argv[1]
    create_sample_pcap(out_file)
