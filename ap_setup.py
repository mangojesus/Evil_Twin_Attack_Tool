import os
import subprocess
import time

def set_adapter_to_monitor(iface):
    os.system(f"sudo ifconfig {iface} down")
    os.system(f"sudo iwconfig {iface} mode monitor")
    os.system(f"sudo ifconfig {iface} up")


def start_ap(iface):
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
    subprocess.call(['sudo', 'ifconfig', iface, '192.168.42.1'])
    subprocess.call(['sudo', 'hostapd', '-B', '/etc/hostapd/hostapd.conf'])
    subprocess.call(['sudo', 'service', 'isc-dhcp-server', 'start'])

    # Wait for the access point to start
    time.sleep(5)

def stop_ap(iface):
    # Stop the access point
    subprocess.call(['sudo', 'service', 'isc-dhcp-server', 'stop'])
    subprocess.call(['sudo', 'hostapd', '-B', '/etc/hostapd/hostapd.conf', '-i', iface, '-K'])
    subprocess.call(['sudo', 'ifconfig', iface, 'down'])

def create_ap_config(ssid, password, iface):
    config_file = f"""interface={iface}
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
ap_name = "eylon&michael"
password = "E1y2!3o4n5"

set_adapter_to_monitor(interface)
start_ap(interface)
create_ap_config(ap_name, password, interface)

