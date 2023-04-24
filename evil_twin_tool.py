from scapy.all import *

iface = "wlxc83a35c2e0a2"

# Set the Wi-Fi channel to scan
channel = 6
os.system("iwconfig %s channel %d" % (iface, channel))

# Define the callback function to handle packets
def handle_packet(pkt):
    if pkt.haslayer(Dot11Beacon):
        # Extract the SSID and BSSID of the network
        ssid = pkt[Dot11Elt].info.decode()
        bssid = pkt[Dot11].addr2
        # Print the SSID and BSSID of the network
        print(f"SSID: {ssid} BSSID: {bssid}")

# Start sniffing for Wi-Fi packets on the specified channel
sniff(iface=iface, prn=handle_packet)
