from scapy.all import *
import os
import threading
import subprocess
import random
from network_interface import network_interface
from tabulate import tabulate
import select
import time



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
        if bssid is not None:
            bssid = bssid.lower()
        # Print the SSID and BSSID of the network
        # if the packet is beacon we can also check the type is 0- management and the subtype is 8-beacon
        if pkt.type == 0 and pkt.subtype == 8:
            #ssid is the name of the router
            ssid = pkt[Dot11Elt].info.decode()
            creation_time = time.time()
            if network_interfaces.get(bssid) is not None:
                network_interfaces.get(bssid).Beacons += 1
            else:
                network_interfaces[bssid] = network_interface(ssid,bssid,currchanel, creation_time)
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

        # check if we got deauth packet
        if pkt.type == 0 and pkt.subtype == 12:
            seen_ssids = set()
            # check if we got two wifi's with the same name, but different bssid
            for bssid, wifi in network_interfaces.items():
                if wifi.SSID in seen_ssids:
                    print(f"Duplicate SSID {wifi.SSID} found in keys {bssid} and {prev_bssid}")
                    # check if the creation time between the 2 wifi's is less than 2 minutes
                    if abs(wifi.CREATION_TIME - prev_wifi.CREATION_TIME) < 120:
                        print("\033[31mSomeone is performing evil twin attack on you\033[0m")
                else:
                    seen_ssids.add(wifi.SSID)
                    prev_bssid = bssid
                    prev_wifi = wifi

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


iface = "wlxc83a35c2e0b7"
channels = get_adapter_chanels(iface)
set_adapter_to_monitor(iface)
network_interfaces = {}


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
    print(tabulate(table, headers=['BSSID', 'PWR', 'RXQ', 'Beacons', 'Data', 'Data_for_sec','Data_counter', 'CH', 'MB', 'ENC','CIPHER', 'AUTH', 'SSID', 'CREATION_TIME']))