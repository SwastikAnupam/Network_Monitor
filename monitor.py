from scapy.all import ARP, Ether, srp

def scan_network(interface):
    ip_range = "192.168.0.1/24"  # Change this to match your network IP range
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp
    result = srp(packet, timeout=3, iface=interface, verbose=False)[0]
    clients = []

    for sent, received in result:
        clients.append({"ip": received.psrc, "mac": received.hwsrc})

    return clients

if __name__ == "__main__":
    interface = "lo0"  # Change this to match your network interface (e.g., eth0, wlan0)

    print("Scanning network...")
    connected_devices = scan_network(interface)

    if connected_devices:
        print("Devices connected to the network:")
        print("{:<15} {:<17}".format("IP Address", "MAC Address"))
        for device in connected_devices:
            print("{:<15} {:<17}".format(device["ip"], device["mac"]))
    else:
        print("No devices found on the network.")
