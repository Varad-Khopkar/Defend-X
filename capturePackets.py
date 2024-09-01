import netifaces
import scapy.all as scapy
import pandas as pd
import matplotlib.pyplot as plt

def find_network_interface():
    interfaces = netifaces.interfaces()
    if "eth0" in interfaces:
        return "eth0"
    else:
        print("Could not find interface 'eth0'. Listing available interfaces:")
        for i in interfaces:
            print(i)
        return input("Enter the correct interface name (or leave blank to exit): ")

def capture_packets(iface, timeout=30):
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
        scapy.sniff(iface=iface, filter="tcp port 80", prn=packet_handler, timeout=timeout)
        return packets
    except Exception as e:
        print(f"Error capturing packets: {e}")
        return None

def visualize_data(packets):
    df = pd.DataFrame(packets)

    # Convert time to datetime for easier visualization
    df['time'] = pd.to_datetime(df['time'])

    # Visualize packet count over time
    df.set_index('time').resample('1S').size().plot(title='Packets per Second')
    plt.show()

    # Visualize packet size distribution
    df['length'].hist(bins=50, title='Packet Size Distribution')
    plt.show()

    # Visualize source IP distribution
    df['src_ip'].value_counts().plot(kind='bar', title='Source IP Distribution')
    plt.show()

if __name__ == "__main__":
    iface = find_network_interface()
    if iface:
        packets = capture_packets(iface, timeout=30)
        if packets:
            visualize_data(packets)
        else:
            print("No packets captured.")
    else:
        print("Exiting due to interface issue.")