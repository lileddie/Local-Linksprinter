#!/usr/bin/env python3
import time
from scapy.all import *
load_contrib("cdp")

print('Enter the name of your Interface, this is the full description from ipconfig /all')
print('Avalailable Interface Descriptions:')

list_ifs = scapy.interfaces.get_working_ifaces()
for item in list_ifs:
    try:
        ignore_interfaces = ['WAN Miniport (IP)','Microsoft Wi-Fi Direct Virtual Adapter','Intel(R) Wi-Fi 6 AX200 160MHz','WAN Miniport (IPv6)','Bluetooth Device (Personal Area Network)','Microsoft Wi-Fi Direct Virtual Adapter #2','WAN Miniport (Network Monitor)','Hyper-V Virtual Ethernet Adapter','Software Loopback Interface 1']
        if str(item.description) not in ignore_interfaces:
            print(item.description)
    except:
        continue

capture_interface = input('Full interface description: ')
capturefilter='ether[20:2] == 0x2000'

script_end = time.time() + 60
print('Script will run for 60 seconds')
while time.time() < script_end:
    captured_packets=sniff(iface=capture_interface, count=1, filter=capturefilter, timeout=60, prn=lambda x: x.show())

print("If no CDP packets printed above, verify CDP is enabled")

bye = False
while not bye:
    user_input = input("Enter y to exit!")
    if user_input.lower() == "y":
        print('''
        ★─▄█▀▀║░▄█▀▄║▄█▀▄║██▀▄║─★
        ★─██║▀█║██║█║██║█║██║█║─★
        ★─▀███▀║▀██▀║▀██▀║███▀║─★
        ★───────────────────────★
        ★───▐█▀▄─ ▀▄─▄▀ █▀▀──█───★
        ★───▐█▀▀▄ ──█── █▀▀──▀───★
        ★───▐█▄▄▀ ──▀── ▀▀▀──▄───★
        ''')
        time.sleep(2)
        bye = True
