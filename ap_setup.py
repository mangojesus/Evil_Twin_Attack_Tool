import os
import subprocess
import time

def set_adapter_to_monitor(iface_wifi):
    os.system(f"sudo ifconfig {iface_wifi} down")
    os.system(f"sudo iwconfig {iface_wifi} mode monitor")
    os.system(f"sudo ifconfig {iface_wifi} up")

def set_default_gateway(iface_wifi, gateway_ip):
    os.system(f"sudo route add default gw {gateway_ip} {iface_wifi}")
    subprocess.run(['sysctl', '-w', 'net.ipv4.ip_forward=1'], capture_output=True, text=True)

def start_ap(iface_wifi, iface_router, gateway_ip):
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

def create_ap_config(ssid, password, iface_wifi):
    config_file = f"""interface={iface_wifi}
ssid={ssid}
wpa=2
wpa_passphrase={password}
wpa_key_mgmt=WPA-PSK
wpa_pairwise=TKIP
rsn_pairwise=CCMP
driver=nl80211
channel=6"""
    with open("/etc/hostapd/hostapd.conf", "w") as f:
        f.write(config_file)

interface = "wlxc83a35c2e0a2"
ssid = "eylon&michael"
password = "E1y2!3o4n5"
gateway_ip = "192.168.1.1"  # IP address of the router
iface_router = "wlp0s20f3"

set_adapter_to_monitor(interface)
start_ap(interface, iface_router, gateway_ip)
create_ap_config(ssid, password, interface)
# stop_ap(interface)