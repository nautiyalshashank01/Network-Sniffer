from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP

def packet_callback(packet):
    # Check if the packet has an IP layer
    if packet.haslayer(IP):
        ip_layer = packet.getlayer(IP)
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        proto = ip_layer.proto
        
        # Determine protocol name
        proto_name = "OTHER"
        if packet.haslayer(TCP):
            proto_name = "TCP"
        elif packet.haslayer(UDP):
            proto_name = "UDP"
            
        print(f"[+] Packet: {src_ip} ---> {dst_ip} | Protocol: {proto_name}")
        
        # Optional: Flag unencrypted HTTP traffic (Port 80)
        if packet.haslayer(TCP) and (packet[TCP].dport == 80 or packet[TCP].sport == 80):
            print(f"    [!] ALERT: Unencrypted HTTP traffic detected between {src_ip} and {dst_ip}")

def main():
    print("Starting packet sniffer... Press Ctrl+C to stop.")
    # Sniff packets on the default network interface
    # count=0 means it will run indefinitely until stopped
    sniff(prn=packet_callback, store=False)

if __name__ == "__main__":
    main()
