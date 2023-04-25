class network_interface:
    def __init__(self,ssid,bssid,currchanel):
        self.BSSID = bssid
        self.PWR = None
        self.RXQ = None
        self.Beacons = 1
        self.Data = 0
        self.Data_for_sec = 0
        self.Data_counter = 0
        self.CH = currchanel
        self.MB = None
        self.ENC = None
        self.CIPHER = None
        self.AUTH = None
        self.SSID = ssid

    def __str__(self):
        return f"BSSID: {self.BSSID}, PWR: {self.PWR}, RXQ: {self.RXQ}, Beacons: {self.Beacons}, Data: {self.Data}, Data_for_sec: {self.Data_for_sec}, CH: {self.CH}, MB: {self.MB}, ENC: {self.ENC}, CIPHER: {self.CIPHER}, AUTH: {self.AUTH}, SSID: {self.SSID}"

    def __repr__(self):
        return f"BSSID: {self.BSSID}, PWR: {self.PWR}, RXQ: {self.RXQ}, Beacons: {self.Beacons}, Data: {self.Data}, Data_for_sec: {self.Data_for_sec}, CH: {self.CH}, MB: {self.MB}, ENC: {self.ENC}, CIPHER: {self.CIPHER}, AUTH: {self.AUTH}, SSID: {self.SSID}"
