import netifaces
import scapy.all as scapy
import pandas as pd
import matplotlib.pyplot as plt

# Handle interface identification errors gracefully
def find_network_interface():
    interfaces = netifaces.interfaces()
    if "eth0" in interfaces:
        return "eth0"
    else:
        print("Could not find interface 'eth0'. Listing available interfaces:")
        for i in interfaces:
            print(i)
        return input("Enter the correct interface name (or leave blank to exit): ")

# Capture packets with error handling
def capture_packets(iface):
    try:
        packets = []
        def packet_handler(packet):
            if packet.haslayer(scapy.IP) and packet.haslayer(scapy.TCP):
                packets.append({
                    "src_ip": packet[scapy.IP].src,
                    "dst_ip": packet[scapy.IP].dst,
                    "src_port": packet[scapy.TCP].sport,
                    "dst_port": packet[scapy.TCP].dport,
                    "time": packet.time,
                    "length": len(packet)
                })
        scapy.sniff(iface=iface, filter="tcp port 80", prn=packet_handler)
        return packets
    except Exception as e:
        print(f"Error capturing packets: {e}")
        return None

# Main program logic
iface = find_network_interface()
if iface:
    packets = capture_packets(iface)
    if packets:
        # Create DataFrame and visualize data (as in previous examples)
        df = pd.DataFrame(packets)
        # ... (your data visualization code)
    else:
        print("No packets captured.")
else:
    print("Exiting due to interface issue.")