import argparse
from scapy.all import sniff, get_if_list, wrpcap
from scapy.layers.inet import IP, TCP
from datetime import datetime

# Store captured packets
captured_packets = []

def packet_callback(packet):
    global packet_count
    packet_count += 1

    # Print packet summary with timestamp
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    print(f"\n[Packet {packet_count}] [{timestamp}] {packet.summary()}")

    # Print IP details
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        print(f"Source IP: {ip_src} -> Destination IP: {ip_dst}")

    # Print TCP details
    if TCP in packet:
        tcp_sport = packet[TCP].sport
        tcp_dport = packet[TCP].dport
        print(f"Source Port: {tcp_sport} -> Destination Port: {tcp_dport}")

    # Store packet if output is specified
    if args.output:
        captured_packets.append(packet)

def main():
    parser = argparse.ArgumentParser(description='Python Packet Sniffer')
    parser.add_argument('-i', '--interface', help='Network interface to sniff on', required=True)
    parser.add_argument('-f', '--filter', help='BPF filter (e.g., "tcp", "udp", "icmp")', default="")
    parser.add_argument('-o', '--output', help='Output PCAP file', default=None)
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose mode')
    
    global args
    args = parser.parse_args()
    
    global packet_count
    packet_count = 0

    print(f"Sniffing on {args.interface} with filter '{args.filter}'... Press Ctrl+C to stop.")

    try:
        # Start sniffing
        sniff(
            iface=args.interface, 
            filter=args.filter if args.filter else None, 
            prn=packet_callback if not args.verbose else lambda x: print(x.show()), 
            store=False
        )
    except KeyboardInterrupt:
        print("\nPacket sniffing stopped.")
        if args.output:
            wrpcap(args.output, captured_packets)
            print(f"\nPackets saved to '{args.output}'.")

if __name__ == "__main__":
    main()
