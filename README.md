# Evil_Twin_Attack_Tool

Group: 2</br>

Name: Eylon Naamat.</br>
ID: 315303529</br>

Name: Michael Matveev.</br>
ID: 315918557</br>

## Installations</br>
sudo apt install python3-pip </br>
sudo apt install net-tools </br>
sudo pip install scapy </br>
sudo pip install tabulate </br>
sudo apt-get install hostapd isc-dhcp-server </br>
sudo pip install flask </br>
sudo pip install flask_sslify </br>
sudo apt-get install iw </br>

## About the tools
The attack tool is called evil_twin_tool.py and can be run using the command sudo python3 evil_twin_tool.py.</br>
This tool scans the wifis and prints them to the screen with all necessary information.</br>
After the user selects which wifi he wants to attack, the tool will print the users that are connected to the chosen wifi.</br>
Then, the user needs to choose which user he want to choose as a victim.</br>
The tool then raises up a new wifi (the evil twin) which has a captive portal, and sends deauth packets to the victim.</br>
We implemented captive portal for both http an https requests.</br>
The code that sets up the access point is called ap_setup.py, and uses captive_portal_https.py as the captive portal.</br>

The defensive tool is in the folder Deffense_tool under the name defensive_tool.py.</br>
We also implemented a few other ideas which we dont use in detector.py.</br>
Enjoy!



