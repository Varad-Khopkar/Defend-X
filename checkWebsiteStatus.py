import socket
import urllib.request
import time

def is_website_up(url, ip_address, max_packets=4):
    """Checks if a website is up using both URL and IP address, sending a maximum of 4 packets.

    Args:
        url (str): The URL of the website to check.
        ip_address (str): The IP address of the website to check.
        max_packets (int): The maximum number of packets to send.

    Returns:
        tuple: A tuple containing the result (True or False), the method that was successful (URL or IP), and a list of results for each packet.
    """

    results = []
    successful_packets = 0
    lost_packets = 0
    packets_sent = 0
    while packets_sent < max_packets:
        try:
            # Try to connect to the website using the URL
            urllib.request.urlopen(url, timeout=5)
            results.append("URL: Success")
            successful_packets += 1
            packets_sent += 1
        except Exception as e:
            results.append(f"URL: Error: {e}")
            lost_packets += 1
            packets_sent += 1

        try:
            # Try to connect to the website using the IP address
            socket.create_connection((ip_address, 80), timeout=5)
            results.append("IP: Success")
            successful_packets += 1
            packets_sent += 1
        except Exception as e:
            results.append(f"IP: Error: {e}")
            lost_packets += 1
            packets_sent += 1

    return successful_packets, lost_packets, results

if __name__ == "__main__":
    url = input("Enter the URL of the website: ")
    ip_address = input("Enter the IP address of the website: ")

    successful_packets, lost_packets, packet_results = is_website_up(url, ip_address)

    print("Packet results:")
    print("Successful packets:", successful_packets)
    print("Lost packets:", lost_packets)
    for result in packet_results:
        print(result)