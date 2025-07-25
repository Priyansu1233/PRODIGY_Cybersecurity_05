"""⚠️ DISCLAIMER:
This network packet analyzer is developed strictly for educational purposes.

It is intended to demonstrate how basic packet sniffing works using Python.
Do NOT use this tool on any network you do not own or without explicit
permission from the network owner. Unauthorized monitoring is illegal and unethical.
"""

from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP

def process_packet(packet):
    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        protocol = "Other"

        if TCP in packet:
            protocol = "TCP"
        elif UDP in packet:
            protocol = "UDP"
        elif ICMP in packet:
            protocol = "ICMP"

        print(f"[+] Packet | Src: {src_ip} → Dst: {dst_ip} | Protocol: {protocol}")

def main():
    print("===  Network Packet Analyzer ===")
    print("Sniffing packets... Press Ctrl+C to stop.\n")

    try:
        sniff(prn=process_packet, store=False)
    except KeyboardInterrupt:
        print("\n Packet sniffing stopped by user.")

if __name__ == "__main__":
    main()
