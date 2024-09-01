import netifaces
import scapy.all as scapy
import pandas as pd
import matplotlib.pyplot as plt

# Identify the network interface
interfaces = netifaces.interfaces()
if "eth0" in interfaces:
    iface = "eth0"
else:
    raise ValueError("Could not find a suitable network interface")

# Capture packets
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

packets = []
scapy.sniff(iface=iface, filter="tcp port 80", prn=packet_handler)

# Create a DataFrame
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