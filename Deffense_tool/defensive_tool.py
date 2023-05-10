from scapy.all import *
import os
import threading
import subprocess
import random
from network_interface import network_interface
from tabulate import tabulate
import select
import time
import re


def set_adapter_to_monitor(iface):
    os.system(f"sudo ifconfig {iface} down")
    os.system(f"sudo iwconfig {iface} mode monitor")
    os.system(f"sudo ifconfig {iface} up")


def get_current_wifi_info():
    iw_output = subprocess.check_output(['iw', 'dev', 'wlp0s20f3', 'link'])
    iw_output = iw_output.decode('utf-8')
    ssid = re.search(r'SSID: (.+)\n', iw_output).group(1)
    bssid = re.search(r'Connected to (.+) \(on', iw_output).group(1)
    freq_str = re.search(r'freq: (.+)\n', iw_output).group(1)
    freq = float(freq_str) / 1000  # Convert from MHz to GHz
    channel = None
    if freq >= 2.412 and freq <= 2.462:
        channel = int((freq - 2.412) / 0.005) + 1
    elif freq >= 5.18 and freq <= 5.32:
        channel = int((freq - 5.18) / 0.01) + 36
    elif freq >= 5.5 and freq <= 5.7:
        channel = int((freq - 5.5) / 0.005) + 52
    elif freq >= 5.745 and freq <= 5.825:
        channel = int((freq - 5.745) / 0.005) + 149
    return (ssid, bssid, channel)


flag_deauth_time = 0
my_ssid = "naamat"
my_bssid = "5c:b1:3e:ce:bd:35"
my_channel = 11


def interface_handle_packet(pkt, network_interfaces, currchanel):
    global flag_deauth_time
    global my_bssid
    global my_ssid
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
            # ssid is the name of the router
            ssid = pkt[Dot11Elt].info.decode()
            creation_time = time.time()
            if network_interfaces.get(bssid) is not None:
                network_interfaces.get(bssid).Beacons += 1
            else:
                if flag_deauth_time != 0:
                    if time.time() - flag_deauth_time > 60:
                        flag_deauth_time = 0
                    else:
                        if ssid == my_ssid and bssid != my_bssid:
                            print(f"\033[31mSomeone ssid:{ssid} bssid: {bssid} is performing evil twin attack on you\033[0m")
                        else:
                            network_interfaces[bssid] = network_interface(ssid, bssid, currchanel, creation_time)
                else:
                    network_interfaces[bssid] = network_interface(ssid, bssid, currchanel, creation_time)
        if network_interfaces.get(bssid) is not None:
            # pwr
            # RadioTap provides information about the wireless radio channel and physical
            # layer characteristics of the transmission.
            # The RadioTap header contains a set of fields that describe various aspects of the wireless transmission,
            # such as the signal strength, noise level, channel frequency, and modulation type.
            if pkt.haslayer(RadioTap):
                # extract the signal strength field from the RadioTap layer
                network_interfaces.get(bssid).PWR = pkt.dBm_AntSignal
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
            bssid = pkt[Dot11].addr2
            if bssid is not None:
                bssid = bssid.lower()
            if bssid == my_bssid:
                flag_deauth_time = time.time()
                wifi_ssid = "naamat"
                wifi_bssid = "5c:b1:3e:ce:bd:35"
                # check if we got two wifi's with the same name, but different bssid
                for bssid, wifi in network_interfaces.items():
                    if wifi_ssid == wifi.SSID and wifi_bssid != bssid:
                        # check if the creation time between the 2 wifi's is less than 2 minutes
                        if abs(wifi.CREATION_TIME - flag_deauth_time) < 60:
                            print(f"\033[31mSomeone ssid:{wifi.SSID} bssid: {bssid} is performing evil twin attack on you\033[0m")


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
set_adapter_to_monitor(iface)
network_interfaces = {}
curr_wifi_iface = input("insert your current wifi network card interface:")

try:
    my_ssid, my_bssid, channel = get_current_wifi_info(curr_wifi_iface)
except:
    pass

my_ssid = "naamat"
my_bssid = "5c:b1:3e:ce:bd:35"
channel = 11

# Start sniffing for Wi-Fi packets on all channels
while True:
    # pass the iface(adapter to that channel)
    os.system("iwconfig %s channel %d" % (iface, channel))
    # start to sniff packets for 3 sec
    sniff(iface=iface, prn=lambda pkt: interface_handle_packet(pkt, network_interfaces, channel), timeout=3)
    # calculate the data per second
    for value in network_interfaces.values():
        if channel == value.CH:
            value.Data_for_sec = int(value.Data_counter / 3)
            value.Data_counter = 0
    # Convert the dictionary to a list of lists for good print in table
    table = [list(v._dict_.values()) for k, v in network_interfaces.items()]
    # Print the table
    print(tabulate(table,
                   headers=['BSSID', 'PWR', 'RXQ', 'Beacons', 'Data', 'Data_for_sec', 'Data_counter', 'CH', 'MB', 'ENC',
                            'CIPHER', 'AUTH', 'SSID', 'CREATION_TIME']))