from scapy.all import *
import os
import subprocess
import random
from network_interface import network_interface
from tabulate import tabulate
import select

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
        bssid = pkt[Dot11].addr2
        if chosen_network_interface.BSSID == bssid:
            mac_address = pkt.addr1
            users_list.add(mac_address)

iface = "wlxc83a35c2e0a2"
channels = get_adapter_chanels(iface)
set_adapter_to_monitor(iface)
network_interfaces = {}
chosen_network_interface = None

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
    name = get_input("What network would you like to attack(plz pass the bssid)? ", 1)
    if name is not None:
        if network_interfaces.get(name) is None:
            print(name)
            print("bad name choose")
        else:
            break


chosen_network_interface = network_interfaces.get(name)
users_list = set()
while True:
    # desplay the network that was choosen
    print(f"the network you choos is :\n{chosen_network_interface}")
    # change the channel to the network che
    os.system("iwconfig %s channel %d" % (iface, chosen_network_interface.CH))
    #start to sniff packets for 3 sec
    sniff(iface=iface, prn=lambda pkt: single_network_handle_packet(pkt, users_list, chosen_network_interface), timeout=3)
    print(users_list)





