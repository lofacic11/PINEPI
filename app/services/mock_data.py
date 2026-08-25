MOCK_APS = [
    {"bssid":"00:11:22:33:44:55","ssid":"PinePi Lab","hidden":False,"channel":1,"frequency":2412,"band":"2.4 GHz","signal":-38,"signal_quality":"Excellent","privacy":"WPA3","cipher":"CCMP","authentication":"SAE","security":"WPA3","pmf":"enabled","beacons":120,"data_packets":44,"first_seen":"2026-01-01 10:00:00","last_seen":"2026-01-01 10:02:00","vendor":"Example Networks","visible":True},
    {"bssid":"10:22:33:44:55:66","ssid":"Cafe Guest <script>","hidden":False,"channel":6,"frequency":2437,"band":"2.4 GHz","signal":-61,"signal_quality":"Fair","privacy":"OPN","cipher":"","authentication":"","security":"Open","pmf":"unknown","beacons":80,"data_packets":3,"first_seen":"2026-01-01 10:00:10","last_seen":"2026-01-01 10:01:55","vendor":"Unknown","visible":True},
    {"bssid":"20:33:44:55:66:77","ssid":"","hidden":True,"channel":36,"frequency":5180,"band":"5 GHz","signal":-73,"signal_quality":"Weak","privacy":"WPA2","cipher":"CCMP","authentication":"PSK","security":"WPA2","pmf":"unknown","beacons":45,"data_packets":7,"first_seen":"2026-01-01 10:00:20","last_seen":"2026-01-01 10:01:40","vendor":"Unknown","visible":True},
    {"bssid":"30:44:55:66:77:88","ssid":"PinePi Lab","hidden":False,"channel":11,"frequency":2462,"band":"2.4 GHz","signal":-67,"signal_quality":"Fair","privacy":"OPN","cipher":"","authentication":"","security":"Open","pmf":"disabled","beacons":32,"data_packets":2,"first_seen":"2026-01-01 10:00:25","last_seen":"2026-01-01 10:01:35","vendor":"Unexpected Vendor","visible":True},
]

MOCK_CLIENTS = [
    {"station_mac":"02:AA:BB:CC:DD:EE","bssid":"00:11:22:33:44:55","relationship":"associated","probed_ssids":"","signal":-52,"packet_count":23,"first_seen":"2026-01-01 10:00:30","last_seen":"2026-01-01 10:01:50","vendor":"Randomized/local address"},
    {"station_mac":"06:11:22:33:44:55","bssid":None,"relationship":"unassociated","probed_ssids":"TrainingLab","signal":-69,"packet_count":4,"first_seen":"2026-01-01 10:00:40","last_seen":"2026-01-01 10:01:20","vendor":"Randomized/local address"},
]
