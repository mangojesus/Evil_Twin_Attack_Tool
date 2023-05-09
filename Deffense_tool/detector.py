from scapy.all import *


def set_adapter_to_monitor(iface):
    os.system(f"sudo ifconfig {iface} down")
    os.system(f"sudo iwconfig {iface} mode monitor")
    os.system(f"sudo ifconfig {iface} up")


#load all the good networks
def read_good_networks_from_file(filename):
    mac_dict = {}
    try:
        with open(filename, "r") as file:
            for line in file:
                line = line.strip()
                if line:
                    name, mac_address = line.split()
                    mac_dict[name] = mac_address
    except:
        with open(filename, "w") as file:
            pass

    return mac_dict


# add new good network
def add_network_to_file(filename, name, mac_address):
    with open(filename, "a") as file:
        file.write(f"{name} {mac_address}\n")

#

# get all adapter channels
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


def get_zscore(networks, field):
    # Extract the values for the given field across all networks
    values = []
    for ssid in networks:
        values += networks[ssid][field]

    # Calculate the mean and standard deviation of the values
    mean = sum(values) / len(values)
    stdev = (sum([(x - mean)**2 for x in values]) / len(values))**0.5

    # Calculate the upper and lower limits for outliers (3 standard deviations from the mean)
    upper_limit = mean + 1.5*stdev
    lower_limit = mean - 1.5*stdev
    return upper_limit, lower_limit



def scan_wifi_information_for_all_channels(iface,channel_list):
    # Set up a dictionary to store the network information for each SSID
    networks = {}

    # Loop through each channel in the  channellist
    for channel in channel_list:
        # Set the Wi-Fi channel to the current channel in the loop
        os.system(f"iwconfig {iface} channel {channel}")

        # Sniff for 2 seconds on the current channel
        packets = sniff(iface=iface, timeout=1)

        # Loop through each packet and extract information for Wi-Fi networks
        for packet in packets:
            # Check if the packet is a Beacon frame
            if packet.haslayer(Dot11Beacon):
                ssid = packet[Dot11Elt].info.decode()
                bssid = packet[Dot11].addr3
                ssid += f" {bssid}"

                # Create a new entry in the networks dictionary for this SSID
                if ssid not in networks:
                    networks[ssid] = {"signal_strength": [], "beacon_interval": [],
                                      "num_packets_per_sec": [],
                                      "network_latency": []}

                # Extract the desired information and add it to the corresponding entry
                sig_strength = packet.dBm_AntSignal
                networks[ssid]["signal_strength"].append(sig_strength)

                beacon_interval = packet[Dot11Beacon].beacon_interval
                networks[ssid]["beacon_interval"].append(beacon_interval)

                num_packets_per_sec = len([p for p in packets if p.addr2 == bssid])
                networks[ssid]["num_packets_per_sec"].append(num_packets_per_sec)

                network_latency = packet.time - packet[Dot11Beacon].timestamp
                networks[ssid]["network_latency"].append(network_latency)

    # Calculate the average value for each characteristic across all networks
    upper_avg_signal_strength , lower_avg_signal_strength = get_zscore(networks,"signal_strength")
    upper_avg_beacon_interval , lower_avg_beacon_interval = get_zscore(networks,"beacon_interval")
    upper_avg_num_packets_per_sec , lower_avg_num_packets_per_sec = get_zscore(networks,"num_packets_per_sec")
    upper_avg_network_latency , lower_avg_network_latency = get_zscore(networks,"network_latency")

    # Return the average values as a dictionary
    return {"upper_signal_strength": upper_avg_signal_strength,
            "upper_beacon_interval": upper_avg_beacon_interval,
            "upper_num_packets_per_sec": upper_avg_num_packets_per_sec,
            "upper_network_latency": upper_avg_network_latency,
            "lower_signal_strength": lower_avg_signal_strength,
            "lower_beacon_interval": lower_avg_beacon_interval,
            "lower_num_packets_per_sec": lower_avg_num_packets_per_sec,
            "lower_network_latency": lower_avg_network_latency}


# Define a function to analyze Wi-Fi packets
def get_curr_wifi_info(iface,channel_list):
    # Set up a dictionary to store the network information for each SSID
    networks = {}

    # Loop through each channel in the  channellist
    for channel in channel_list:
        # Set the Wi-Fi channel to the current channel in the loop
        os.system(f"iwconfig {iface} channel {channel}")

        # Sniff for 2 seconds on the current channel
        packets = sniff(iface=iface, timeout=1)

        # Loop through each packet and extract information for Wi-Fi networks
        for packet in packets:
            # Check if the packet is a Beacon frame
            if packet.haslayer(Dot11Beacon):
                ssid = packet[Dot11Elt].info.decode()
                bssid = packet[Dot11].addr3
                ssid += f" {bssid}"

                # Create a new entry in the networks dictionary for this SSID
                if ssid not in networks:
                    networks[ssid] = {"signal_strength": [], "beacon_interval": [],
                                      "num_packets_per_sec": [], "num_associated_clients": [],
                                      "network_latency": []}

                # Extract the desired information and add it to the corresponding entry
                sig_strength = packet.dBm_AntSignal
                networks[ssid]["signal_strength"].append(sig_strength)

                beacon_interval = packet[Dot11Beacon].beacon_interval
                networks[ssid]["beacon_interval"].append(beacon_interval)

                num_packets_per_sec = len([p for p in packets if p.addr2 == bssid])
                networks[ssid]["num_packets_per_sec"].append(num_packets_per_sec)

                network_latency = packet.time - packet[Dot11Beacon].timestamp
                networks[ssid]["network_latency"].append(network_latency)

    new_networks ={}
    for ssid in networks:
        new_networks[ssid] = {}
        new_networks[ssid]["signal_strength"] = sum(networks[ssid]["signal_strength"]) / len(networks[ssid]["signal_strength"])
        new_networks[ssid]["beacon_interval"] = sum(networks[ssid]["beacon_interval"]) / len(networks[ssid]["beacon_interval"])
        new_networks[ssid]["num_packets_per_sec"] = sum(networks[ssid]["num_packets_per_sec"]) / len(networks[ssid]["num_packets_per_sec"])
        new_networks[ssid]["network_latency"] = sum(networks[ssid]["network_latency"]) / len(networks[ssid]["network_latency"])

    return new_networks

def analyze_packet(networks,good_interfaces,get_network_upper_lower,bad_network_tool):
    for net in networks:
        if "Yona" in net:
            print(networks[net])
        if "Home2." in net:
            print(networks[net])
        tempnet = net
        net = net.strip()
        if net:
            split_net = net.split()
            if len(split_net) > 2:
                name = ' '.join(split_net[:-1])
                mac_address = split_net[-1]
            elif len(split_net) == 2:
                name= split_net[0]
                mac_address =split_net[1]
            else:
                if tempnet not in bad_network_tool:
                    bad_network_tool.add(tempnet)
                    print("\033[91mRogue AP detected! private network, MAC address: " + net + "\033[0m")

        if good_interfaces.get(name):
            if good_interfaces.get(name) != mac_address:
                if tempnet not in bad_network_tool:
                    bad_network_tool.add(tempnet)
                    print("\033[91mRogue AP detected! SSID: " + name + ", MAC address: " + mac_address + "\033[0m")
        counter = 0

        if get_network_upper_lower["upper_signal_strength"] < networks[tempnet]["signal_strength"] or get_network_upper_lower["lower_signal_strength"] > networks[tempnet]["signal_strength"]:
            counter +=1

        if get_network_upper_lower["upper_beacon_interval"] < networks[tempnet]["beacon_interval"] or get_network_upper_lower["lower_beacon_interval"] > networks[tempnet]["beacon_interval"]:
            counter +=1

        if get_network_upper_lower["upper_num_packets_per_sec"] < networks[tempnet]["num_packets_per_sec"] or get_network_upper_lower["lower_num_packets_per_sec"] > networks[tempnet]["num_packets_per_sec"]:
            counter +=1

        if get_network_upper_lower["upper_network_latency"] < networks[tempnet]["network_latency"] or get_network_upper_lower["lower_network_latency"] > networks[tempnet]["network_latency"]:
            counter +=1

        if counter > 0:
            if tempnet not in bad_network_tool:
                bad_network_tool.add(tempnet)
                print("\033[93mRogue AP detected! SSID: " + name + ", MAC address: " + mac_address + " num_of_anomali = "+str(counter)+"\033[0m")


iface = "wlxc83a35c2e0b7"
set_adapter_to_monitor(iface)
channels = get_adapter_chanels(iface)
filename = "good_networks.txt"
print("welcome to our defensive tool for evil twin attack:")
print("if you have name of file that contain list of familiar benign networks")
filename = input("plz enter it now(if there isn't you can give just name and we will make new empty one): ")
good_interfaces = read_good_networks_from_file(filename)
# print(good_interfaces)
get_network_upper_lower = scan_wifi_information_for_all_channels(iface,channels)
# print("###############################################")
print(get_network_upper_lower)
# print("###############################################")

bad_network_tool = set()
function =""
while function != 'M':
    if function == 'A':
        netname_ssid = input("insert the network ssid:")
        network_bssid = input("insert the bssid(mac address:")
        add_network_to_file(filename,netname_ssid,network_bssid)
    function = input("if you want to add new network to the list press (A) and for start monitor pres (M):")


while True:
    print("1")
    networks = analyze_packet(get_curr_wifi_info(iface,channels),good_interfaces,get_network_upper_lower,bad_network_tool)

