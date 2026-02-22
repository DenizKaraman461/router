import scapy.all as scapy
import sys

def scan(ip, interface):
    print(f"\n[*] Scanning network: {ip}")
    print(f"[*] Interface in use: {interface}")
    print("-" * 60)
    print("IP Address\t\tMAC Address")
    print("-" * 60)
    
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    
    try:
        answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False, iface=interface)[0]
        
        device_count = 0
        for element in answered_list:
            print(f"{element[1].psrc}\t\t{element[1].hwsrc}")
            device_count += 1
            
        if device_count == 0:
            print("\n[!] No devices found. Firewall might be blocking.")
            
    except Exception as e:
        print(f"\n[!] ERROR OCCURRED: {e}")

if __name__ == "__main__":
    interface = scapy.conf.iface.name
    target_range = input("[?] Enter IP range to scan (e.g., 192.168.1.1/24): ")
    if target_range:
        scan(target_range, interface)